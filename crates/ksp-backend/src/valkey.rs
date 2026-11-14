//! Valkey Blob Store with strictly verified native logical expiry.

use std::sync::Mutex;

use ksp_record::version::BlobStore as RecordBlobStore;
use redis::{Commands, Connection, ExistenceCheck, SetExpiry, SetOptions};

use crate::admission::ValkeyConfiguration;
use crate::arming::{ArmError, ArmingStore, Durability};
use crate::store::{BlobStore, StoreError, validate_path, validate_prefix};

const CAS: &str = "if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('SET', KEYS[1], ARGV[2]); return 1 else return 0 end";
const CREATE: &str = "if redis.call('EXISTS', KEYS[1]) == 0 then redis.call('SET', KEYS[1], ARGV[1]); return 1 else return 0 end";

pub struct ValkeyStore {
    connection: Mutex<Connection>,
    wait_timeout_ms: u64,
}

impl ValkeyStore {
    pub fn connect(url: &str, wait_timeout_ms: u64) -> Result<Self, StoreError> {
        let client = redis::Client::open(url)
            .map_err(|_| StoreError::Backend("invalid Valkey configuration".into()))?;
        let connection = client
            .get_connection()
            .map_err(|_| StoreError::Backend("Valkey connection failed".into()))?;
        if wait_timeout_ms == 0 {
            return Err(StoreError::Backend(
                "Valkey durability timeout must be positive".into(),
            ));
        }
        Ok(Self {
            connection: Mutex::new(connection),
            wait_timeout_ms,
        })
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        self.connection
            .lock()
            .map_err(|_| StoreError::Backend("Valkey connection unavailable".into()))
    }

    /// Verify actual server persistence configuration before native expiry admission.
    pub fn configuration(&self) -> Result<ValkeyConfiguration, StoreError> {
        let mut conn = self.connection()?;
        fn config(conn: &mut Connection, key: &str) -> Result<String, StoreError> {
            let answer: Vec<String> = redis::cmd("CONFIG")
                .arg("GET")
                .arg(key)
                .query(conn)
                .map_err(|_| {
                    StoreError::Backend("Valkey configuration inspection failed".into())
                })?;
            if answer.len() != 2 || answer[0] != key {
                return Err(StoreError::Backend("Valkey configuration unknown".into()));
            }
            Ok(answer[1].clone())
        }
        let append_only = config(&mut conn, "appendonly")? == "yes";
        let append_fsync_always = config(&mut conn, "appendfsync")? == "always";
        Ok(ValkeyConfiguration {
            logical_expiry: true,
            append_only,
            append_fsync_always,
            waitaof_supported: true,
        })
    }

    fn wait_local_fsync(conn: &mut Connection, timeout_ms: u64) -> Result<(), ArmError> {
        let counts: Vec<i64> = redis::cmd("WAITAOF")
            .arg(1)
            .arg(0)
            .arg(timeout_ms)
            .query(conn)
            .map_err(|_| ArmError::Uncertain)?;
        if counts.len() != 2 || counts[0] < 1 {
            return Err(ArmError::Uncertain);
        }
        Ok(())
    }
}

impl ksp_record::version::BlobStore for ValkeyStore {
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, StoreError> {
        validate_path(path)?;
        self.connection()?
            .get(path)
            .map_err(|_| StoreError::Backend("Valkey read failed".into()))
    }

    fn put_if_absent(&self, path: &str, bytes: &[u8]) -> Result<bool, StoreError> {
        validate_path(path)?;
        let mut conn = self.connection()?;
        let changed: i64 = redis::cmd("EVAL")
            .arg(CREATE)
            .arg(1)
            .arg(path)
            .arg(bytes)
            .query(&mut *conn)
            .map_err(|_| StoreError::Backend("Valkey create failed".into()))?;
        Ok(changed == 1)
    }

    fn compare_and_set(
        &self,
        path: &str,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<bool, StoreError> {
        validate_path(path)?;
        if expected.is_none() {
            return self.put_if_absent(path, replacement);
        }
        let mut conn = self.connection()?;
        let changed: i64 = redis::cmd("EVAL")
            .arg(CAS)
            .arg(1)
            .arg(path)
            .arg(expected.unwrap_or_default())
            .arg(replacement)
            .query(&mut *conn)
            .map_err(|_| StoreError::Backend("Valkey conditional replace failed".into()))?;
        Ok(changed == 1)
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        validate_prefix(prefix)?;
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        let mut conn = self.connection()?;
        let mut cursor = 0u64;
        let mut keys = Vec::new();
        loop {
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{prefix}*"))
                .arg("COUNT")
                .arg(100)
                .query(&mut *conn)
                .map_err(|_| StoreError::Backend("Valkey list failed".into()))?;
            keys.extend(batch.into_iter().filter(|key| key.starts_with(prefix)));
            if next == 0 {
                break;
            }
            cursor = next;
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }
}

impl BlobStore for ValkeyStore {
    fn delete(&self, path: &str) -> Result<(), StoreError> {
        validate_path(path)?;
        let mut conn = self.connection()?;
        let _: i64 = redis::cmd("DEL")
            .arg(path)
            .query(&mut *conn)
            .map_err(|_| StoreError::Backend("Valkey delete failed".into()))?;
        Ok(())
    }
}

impl ArmingStore for ValkeyStore {
    fn arm_once(
        &self,
        identity: &str,
        bytes: &[u8],
        deadline: i64,
    ) -> Result<Durability, ArmError> {
        if identity.is_empty() || identity.contains('/') || identity.contains("..") {
            return Err(ArmError::InvalidIdentity);
        }
        let millis = deadline
            .checked_sub(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| ArmError::Uncertain)?
                    .as_secs() as i64,
            )
            .and_then(|s| u64::try_from(s).ok())
            .and_then(|s| s.checked_mul(1000))
            .filter(|n| *n > 0)
            .ok_or(ArmError::Uncertain)?;
        let key = format!("intents/{identity}");
        let mut conn = self.connection().map_err(|_| ArmError::Uncertain)?;
        let append_only: Vec<String> = redis::cmd("CONFIG")
            .arg("GET")
            .arg("appendonly")
            .query(&mut *conn)
            .map_err(|_| ArmError::Uncertain)?;
        let append_fsync: Vec<String> = redis::cmd("CONFIG")
            .arg("GET")
            .arg("appendfsync")
            .query(&mut *conn)
            .map_err(|_| ArmError::Uncertain)?;
        if append_only.as_slice() != ["appendonly", "yes"]
            || append_fsync.as_slice() != ["appendfsync", "always"]
        {
            return Err(ArmError::Unsupported);
        }
        let options = SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .with_expiration(SetExpiry::PX(millis));
        let accepted: Option<String> = conn
            .set_options(&key, bytes, options)
            .map_err(|_| ArmError::Uncertain)?;
        if accepted.is_none() {
            let existing: Option<Vec<u8>> = conn.get(&key).map_err(|_| ArmError::Uncertain)?;
            if existing.as_deref() != Some(bytes) {
                return Err(ArmError::IdentityConflict);
            }
        }
        Self::wait_local_fsync(&mut conn, self.wait_timeout_ms)?;
        Ok(Durability::LocalAofFsync)
    }

    fn read_arm(&self, identity: &str) -> Result<Option<Vec<u8>>, ArmError> {
        if identity.is_empty() || identity.contains('/') || identity.contains("..") {
            return Err(ArmError::InvalidIdentity);
        }
        self.get(&format!("intents/{identity}"))
            .map_err(|_| ArmError::Uncertain)
    }

    fn list_arms(&self) -> Result<Vec<(String, Vec<u8>)>, ArmError> {
        let paths = self.list("intents/").map_err(|_| ArmError::Uncertain)?;
        let mut records = Vec::with_capacity(paths.len());
        for path in paths {
            let Some(identity) = path.strip_prefix("intents/") else {
                continue;
            };
            if identity.is_empty() || identity.contains('/') {
                continue;
            }
            // A path can vanish between the listing and the read; a record that
            // is already gone has nothing to sweep.
            if let Some(bytes) = self.get(&path).map_err(|_| ArmError::Uncertain)? {
                records.push((identity.to_string(), bytes));
            }
        }
        records.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(records)
    }
}
