#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! A `NativeExpiry` acknowledgement is tied to the configured durability mode.
//!
//! The Valkey backend admits native expiry only when the server is observed to
//! persist with `appendonly yes` and `appendfsync always`, and only
//! acknowledges durable arming after a local AOF fsync is confirmed on the
//! writing connection. These tests start real servers so the durability
//! evidence is observed, not asserted by a stub.

use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use ksp_backend::admission::{AdmissionError, Classification, classify_valkey};
use ksp_backend::arming::{ArmError, ArmRecord, Durability, arm_intent};
use ksp_backend::status::StatusDisclosure;
use ksp_backend::valkey::ValkeyStore;
use ksp_types::{ActorId, DeletionIntent, LeaseCapability, Level, OpaqueSecretId, VaultId};
use redis::Connection;

const DEADLINE_SLACK_SECONDS: i64 = 3;

/// A Valkey server started for one test, killed when the guard drops.
struct Server {
    child: Child,
    port: u16,
}

impl Server {
    /// Start a server with the given persistence configuration.
    fn start(append_only: bool) -> Self {
        let port = free_port();
        let dir = std::env::temp_dir().join(format!("ksp-valkey-{port}"));
        // A port is reused across runs, and `appendonly yes` replays whatever AOF
        // is left in that directory. Starting from a stale AOF would make the
        // first append answer `IdentityConflict` for a write this run never made.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("valkey.conf");
        let mut file = std::fs::File::create(&config).unwrap();
        writeln!(file, "port {port}").unwrap();
        writeln!(file, "bind 127.0.0.1").unwrap();
        writeln!(
            file,
            "appendonly {}",
            if append_only { "yes" } else { "no" }
        )
        .unwrap();
        if append_only {
            writeln!(file, "appendfsync always").unwrap();
        } else {
            writeln!(file, "appendfsync everysec").unwrap();
        }
        // No RDB snapshots: the test is about the AOF, and a snapshot write
        // would make the run slow and the directory grow.
        writeln!(file, "save \"\"").unwrap();
        writeln!(file, "dir {}", dir.display()).unwrap();
        writeln!(file, "daemonize no").unwrap();
        writeln!(file, "logfile {}", dir.join("valkey.log").display()).unwrap();
        file.flush().unwrap();

        let child = Command::new("/usr/bin/valkey-server")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let server = Self { child, port };
        server.wait_ready();
        server
    }

    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}/", self.port)
    }

    /// Poll until the server answers, so the test never races the startup.
    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(mut conn) =
                redis::Client::open(self.url()).and_then(|client| client.get_connection())
            {
                let pong: String = redis::cmd("PING").query(&mut conn).unwrap();
                if pong == "PONG" {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("valkey server on port {} did not become ready", self.port);
    }

    fn connection(&self) -> Connection {
        redis::Client::open(self.url())
            .and_then(|client| client.get_connection())
            .unwrap()
    }

    /// The remaining time to live in milliseconds, or `None` when the key has
    /// no expiry.
    fn pttl(&self, key: &str) -> Option<i64> {
        let mut conn = self.connection();
        let value: i64 = redis::cmd("PTTL").arg(key).query(&mut conn).unwrap();
        match value {
            -2 | -1 => None,
            other => Some(other),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn intent() -> DeletionIntent {
    DeletionIntent {
        intent_id: "intent-1".into(),
        vault_id: VaultId::new("vault-1"),
        user_id: ksp_types::PrincipalId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        level: Level::Agent(
            ksp_types::AgentId::parse("00000000-0000-4000-8000-0000000000a1").unwrap(),
        ),
        secret_id: OpaqueSecretId::new("opaque-1"),
        version: 3,
        deadline: 1_800_000_000,
        authorized_deleters: vec![ActorId::User(
            ksp_types::PrincipalId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        )],
    }
}

fn record(identity: &str) -> ArmRecord {
    let signer = SigningKey::from_bytes(&[7; 32]);
    ArmRecord::sign(
        identity.to_owned(),
        intent(),
        "signer-1".into(),
        None,
        &signer,
    )
    .unwrap()
}

#[test]
fn native_expiry_is_admitted_only_under_the_strict_durability_mode() {
    let strict = Server::start(true);
    let store = ValkeyStore::connect(&strict.url(), 5_000).unwrap();
    let config = store.configuration().unwrap();
    assert!(config.logical_expiry);
    assert!(config.append_only, "appendonly must be observed as yes");
    assert!(
        config.append_fsync_always,
        "appendfsync must be observed as always"
    );
    let classified = classify_valkey(config).unwrap();
    assert_eq!(classified.capability, LeaseCapability::NativeExpiry);

    let lax = Server::start(false);
    let lax_store = ValkeyStore::connect(&lax.url(), 5_000).unwrap();
    let lax_config = lax_store.configuration().unwrap();
    assert!(
        !lax_config.append_only || !lax_config.append_fsync_always,
        "the lax server must not satisfy the strict durability gate"
    );
    assert!(matches!(
        classify_valkey(lax_config),
        Err(AdmissionError::ConfigurationMismatch(_))
    ));
}

#[test]
fn a_native_expiry_acknowledgement_proves_the_local_fsync() {
    let server = Server::start(true);
    let store = ValkeyStore::connect(&server.url(), 5_000).unwrap();
    let arm = record("operation-1");
    let ack = arm_intent(&store, &arm).unwrap();
    assert_eq!(ack.durability, Durability::LocalAofFsync);
    assert_eq!(ack.operation_identity, "operation-1");
    assert_eq!(ack.version, 3);

    // The arming write must actually carry a deadline.
    let ttl = server
        .pttl("intents/operation-1")
        .expect("the arm must have a TTL");
    assert!(ttl > 0, "the arming key must expire, got {ttl}ms");
}

#[test]
fn a_lax_server_refuses_to_arm_rather_than_acknowledging_weakly() {
    let server = Server::start(false);
    let store = ValkeyStore::connect(&server.url(), 5_000).unwrap();
    let arm = record("operation-1");
    assert!(matches!(
        arm_intent(&store, &arm),
        Err(ArmError::Unsupported)
    ));
    // Nothing may be published on an uncertain or unsupported arming, so the
    // key must not exist at all.
    assert!(server.pttl("intents/operation-1").is_none());
}

#[test]
fn a_retry_under_the_same_identity_does_not_extend_the_deadline() {
    let server = Server::start(true);
    let store = ValkeyStore::connect(&server.url(), 5_000).unwrap();
    let arm = record("operation-1");
    let first = arm_intent(&store, &arm).unwrap();
    assert_eq!(first.durability, Durability::LocalAofFsync);
    let ttl_after_first = server.pttl("intents/operation-1").unwrap();

    // A lost acknowledgement is reconciled under the same identity with the
    // same bytes. The retry must not push the deadline further out, so the
    // remaining TTL may only shrink by the elapsed wall clock.
    let second = arm_intent(&store, &arm).unwrap();
    assert_eq!(second.durability, Durability::LocalAofFsync);
    let ttl_after_second = server.pttl("intents/operation-1").unwrap();
    let tolerance = DEADLINE_SLACK_SECONDS * 1_000;
    assert!(
        ttl_after_second <= ttl_after_first + tolerance,
        "the retry extended the deadline: {ttl_after_first}ms -> {ttl_after_second}ms"
    );
    // The record is reconciled, not duplicated.
    let keys: usize = redis::cmd("DBSIZE")
        .query(&mut server.connection())
        .unwrap();
    assert_eq!(keys, 1);
}

#[test]
fn a_different_intent_under_the_same_identity_is_a_conflict() {
    let server = Server::start(true);
    let store = ValkeyStore::connect(&server.url(), 5_000).unwrap();
    let arm = record("operation-1");
    arm_intent(&store, &arm).unwrap();

    let signer = SigningKey::from_bytes(&[7; 32]);
    let other = ArmRecord::sign(
        "operation-1".into(),
        DeletionIntent {
            deadline: 1_900_000_000,
            ..intent()
        },
        "signer-1".into(),
        None,
        &signer,
    )
    .unwrap();
    assert!(matches!(
        arm_intent(&store, &other),
        Err(ArmError::IdentityConflict)
    ));
}

#[test]
fn the_status_surface_discloses_what_is_known_and_marks_the_rest_unknown() {
    let server = Server::start(true);
    let store = ValkeyStore::connect(&server.url(), 5_000).unwrap();
    let classified = classify_valkey(store.configuration().unwrap()).unwrap();
    let status = StatusDisclosure::from(&classified);
    assert_eq!(status.capability, LeaseCapability::NativeExpiry);
    // Native expiry has no declared cadence, so there is no admission minimum.
    assert_eq!(status.declared_cadence_secs, None);
    assert_eq!(status.admission_minimum_secs, None);
    // Cleanup lag and retention are unknown, never a number.
    assert_eq!(status.cleanup_lag, ksp_backend::status::CleanupLag::Unknown);
    assert!(matches!(
        status.retention,
        ksp_backend::status::Retention::Unknown { .. }
    ));

    // A scheduled capability discloses the cadence and the floor it implies.
    let scheduled = Classification {
        capability: LeaseCapability::Scheduled {
            interval: Duration::from_secs(86_400),
        },
        mechanism: "test",
        declared_cadence: Some(Duration::from_secs(86_400)),
        proven_cadence: Some(Duration::from_secs(86_400)),
        proof_age: Some(0),
        cleanup_lag: None,
        retention: None,
        state: None,
    };
    let scheduled_status = StatusDisclosure::from(&scheduled);
    assert_eq!(scheduled_status.declared_cadence_secs, Some(86_400));
    assert_eq!(scheduled_status.admission_minimum_secs, Some(172_800));
    // A declared cadence is a configuration statement; the lag is still unknown,
    // and the two are separate fields.
    assert_eq!(
        scheduled_status.cleanup_lag,
        ksp_backend::status::CleanupLag::Unknown
    );
    assert!(matches!(
        scheduled_status.retention,
        ksp_backend::status::Retention::Unknown { .. }
    ));
}
