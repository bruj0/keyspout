//! S3 Blob Store and bucket configuration evidence.

use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ExpirationStatus, LifecycleRule};
use ksp_record::version::BlobStore as RecordBlobStore;

use crate::admission::{S3Configuration, S3Evidence};
use crate::arming::{ArmError, ArmingStore, Durability};
use crate::store::{BlobStore, StoreError, validate_path, validate_prefix};

/// Explicitly configured bucket and record prefix (never credentials).
pub struct S3Store {
    client: Client,
    bucket: String,
    prefix: String,
    runtime: tokio::runtime::Runtime,
}

impl S3Store {
    pub fn new(client: Client, bucket: String, prefix: String) -> Result<Self, StoreError> {
        if bucket.is_empty() || prefix.starts_with('/') || prefix.contains("..") {
            return Err(StoreError::Backend("invalid S3 configuration".into()));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| StoreError::Backend("S3 runtime unavailable".into()))?;
        Ok(Self {
            client,
            bucket,
            prefix,
            runtime,
        })
    }

    /// The object key for one blob path.
    ///
    /// A trailing slash is refused here, not trimmed. `list` names a range
    /// of paths and accepts one, but a path names exactly one blob, and
    /// normalising `rec/` to `rec` for a write would make the S3 backend
    /// store bytes the `file` backend refuses.
    fn key(&self, path: &str) -> Result<String, StoreError> {
        validate_path(path)?;
        Ok(format!("{}{}", self.prefix, path))
    }

    /// Read configuration evidence; unknown evidence is an error, never eligible.
    ///
    /// A *known absence* of configuration is not unknown evidence. A bucket
    /// with no lifecycle rule answers `NoSuchLifecycleConfiguration` and a
    /// bucket with no object lock answers `ObjectLockConfigurationNotFoundError`;
    /// both are facts about the bucket, and both are exactly what the
    /// classification needs to decide `None`. Only a genuine failure — a
    /// denied permission, a timeout, a malformed response — is unknown, and
    /// unknown evidence is never eligible.
    pub fn evidence(&self, _config: S3Configuration) -> Result<S3Evidence, StoreError> {
        let version = self
            .runtime
            .block_on(
                self.client
                    .get_bucket_versioning()
                    .bucket(&self.bucket)
                    .send(),
            )
            .map_err(|_| StoreError::Backend("S3 versioning inspection failed".into()))?;
        // A suspended bucket retains old versions too. Only a bucket which
        // has never enabled versioning can qualify in future revisions.
        let versioned = version.status().is_some();
        let rules = self.runtime.block_on(
            self.client
                .get_bucket_lifecycle_configuration()
                .bucket(&self.bucket)
                .send(),
        );
        let lifecycle = match rules {
            Ok(response) => response
                .rules()
                .iter()
                .any(|rule| rule_covers_prefix(rule, &self.prefix)),
            Err(error) if is_service_code(&error, NO_SUCH_LIFECYCLE) => false,
            Err(_) => {
                return Err(StoreError::Backend(
                    "S3 lifecycle configuration unknown".into(),
                ));
            }
        };
        let lock = self.runtime.block_on(
            self.client
                .get_object_lock_configuration()
                .bucket(&self.bucket)
                .send(),
        );
        let soft_delete = match lock {
            Ok(output) => output
                .object_lock_configuration()
                .and_then(|configuration| configuration.object_lock_enabled())
                .is_some(),
            Err(error) if is_service_code(&error, NO_SUCH_OBJECT_LOCK) => false,
            Err(_) => {
                return Err(StoreError::Backend(
                    "S3 retention configuration unknown".into(),
                ));
            }
        };
        Ok(S3Evidence {
            versioned,
            soft_delete,
            lifecycle_covers_prefix: lifecycle,
            lifecycle_expiration: lifecycle,
            canary_absent: false,
        })
    }
}

/// The service error code for a bucket with no lifecycle configuration.
const NO_SUCH_LIFECYCLE: &str = "NoSuchLifecycleConfiguration";
/// The service error code for a bucket with no object lock configuration.
const NO_SUCH_OBJECT_LOCK: &str = "ObjectLockConfigurationNotFoundError";

/// Whether the service answered with the given error code.
///
/// The SDK models both reads as a single unhandled error, so the code is
/// read from the error metadata. A transport failure carries no code and is
/// therefore never mistaken for a known absence.
fn is_service_code<E, R>(error: &aws_sdk_s3::error::SdkError<E, R>, code: &str) -> bool
where
    E: aws_sdk_s3::error::ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    use aws_sdk_s3::error::ProvideErrorMetadata;
    error.code() == Some(code)
}

fn rule_covers_prefix(rule: &LifecycleRule, prefix: &str) -> bool {
    if rule.status() != &ExpirationStatus::Enabled {
        return false;
    }
    let Some(expiry) = rule.expiration() else {
        return false;
    };
    if expiry.days().unwrap_or(0) <= 0 || expiry.expired_object_delete_marker().unwrap_or(false) {
        return false;
    }
    if let Some(filter) = rule.filter() {
        if filter.tag().is_some()
            || filter.and().is_some()
            || filter.object_size_greater_than().is_some()
            || filter.object_size_less_than().is_some()
        {
            return false;
        }
        return filter.prefix().is_none_or(|p| prefix.starts_with(p));
    }
    false
}

impl ksp_record::version::BlobStore for S3Store {
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let key = self.key(path)?;
        match self.runtime.block_on(
            self.client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .send(),
        ) {
            Ok(output) => {
                let collected = self
                    .runtime
                    .block_on(output.body.collect())
                    .map_err(|_| StoreError::Backend("S3 object read failed".into()))?;
                Ok(Some(collected.into_bytes().to_vec()))
            }
            Err(error) if error.as_service_error().is_some_and(|e| e.is_no_such_key()) => Ok(None),
            Err(_) => Err(StoreError::Backend("S3 object read failed".into())),
        }
    }

    fn put_if_absent(&self, path: &str, bytes: &[u8]) -> Result<bool, StoreError> {
        let key = self.key(path)?;
        match self.runtime.block_on(
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .if_none_match("*")
                .body(ByteStream::from(bytes.to_vec()))
                .send(),
        ) {
            Ok(_) => Ok(true),
            Err(e)
                if e.raw_response()
                    .is_some_and(|r| r.status().as_u16() == 412 || r.status().as_u16() == 409) =>
            {
                Ok(false)
            }
            Err(_) => Err(StoreError::Backend("S3 conditional create failed".into())),
        }
    }

    fn compare_and_set(
        &self,
        path: &str,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<bool, StoreError> {
        let key = self.key(path)?;
        let mut put = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(replacement.to_vec()));
        if let Some(expected) = expected {
            let fetched = match self.runtime.block_on(
                self.client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(&key)
                    .send(),
            ) {
                Ok(fetched) => fetched,
                // A missing object cannot match an expectation. That is a
                // lost race, not a backend failure: the contract says a
                // refusal and a lost race are different situations and only
                // one is worth retrying.
                Err(error) if error.as_service_error().is_some_and(|e| e.is_no_such_key()) => {
                    return Ok(false);
                }
                Err(_) => {
                    return Err(StoreError::Backend("S3 conditional read failed".into()));
                }
            };
            let etag = fetched
                .e_tag()
                .ok_or(StoreError::ConditionalReplaceUnsupported)?
                .to_owned();
            let collected = self
                .runtime
                .block_on(fetched.body.collect())
                .map_err(|_| StoreError::Backend("S3 conditional read failed".into()))?;
            if collected.into_bytes().as_ref() != expected {
                return Ok(false);
            }
            put = put.if_match(etag);
        } else {
            put = put.if_none_match("*");
        }
        match self.runtime.block_on(put.send()) {
            Ok(_) => Ok(true),
            Err(e)
                if e.raw_response()
                    .is_some_and(|r| r.status().as_u16() == 412 || r.status().as_u16() == 409) =>
            {
                Ok(false)
            }
            Err(_) => Err(StoreError::Backend("S3 conditional replace failed".into())),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        validate_prefix(prefix)?;
        let trimmed = prefix.strip_suffix('/').unwrap_or(prefix);
        let key_prefix = format!("{}{}", self.prefix, trimmed);
        let mut token = None;
        let mut found = Vec::new();
        loop {
            let mut list = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&key_prefix);
            if let Some(previous) = token {
                list = list.continuation_token(previous);
            }
            let page = self
                .runtime
                .block_on(list.send())
                .map_err(|_| StoreError::Backend("S3 listing failed".into()))?;
            for object in page.contents() {
                if let Some(key) = object.key().and_then(|s| s.strip_prefix(&self.prefix)) {
                    found.push(key.to_owned());
                }
            }
            if page.is_truncated() != Some(true) {
                break;
            }
            token = Some(
                page.next_continuation_token()
                    .ok_or_else(|| StoreError::Backend("S3 pagination failed".into()))?
                    .to_owned(),
            );
        }
        Ok(found)
    }
}

impl BlobStore for S3Store {
    fn delete(&self, path: &str) -> Result<(), StoreError> {
        let key = self.key(path)?;
        self.runtime
            .block_on(
                self.client
                    .delete_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send(),
            )
            .map_err(|_| StoreError::Backend("S3 delete failed".into()))?;
        Ok(())
    }
}

impl ArmingStore for S3Store {
    fn arm_once(
        &self,
        identity: &str,
        bytes: &[u8],
        _deadline: i64,
    ) -> Result<Durability, ArmError> {
        if identity.is_empty() || identity.contains('/') || identity.contains("..") {
            return Err(ArmError::InvalidIdentity);
        }
        let path = format!("intents/{identity}");
        match self.put_if_absent(&path, bytes) {
            Ok(true) => Ok(Durability::RemoteAccepted),
            Ok(false) => match self.get(&path) {
                Ok(Some(stored)) if stored == bytes => Ok(Durability::RemoteAccepted),
                Ok(Some(_)) => Err(ArmError::IdentityConflict),
                _ => Err(ArmError::Uncertain),
            },
            Err(_) => Err(ArmError::Uncertain),
        }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use LifecycleRule as Rule;
    use aws_sdk_s3::types::{
        LifecycleExpiration, LifecycleRuleAndOperator, LifecycleRuleFilter, Tag,
    };

    fn expiration_days(days: i32) -> LifecycleExpiration {
        LifecycleExpiration::builder().days(days).build()
    }

    fn rule_with_filter(filter: LifecycleRuleFilter) -> Rule {
        Rule::builder()
            .status(ExpirationStatus::Enabled)
            .expiration(expiration_days(30))
            .filter(filter)
            .build()
            .unwrap()
    }

    #[test]
    fn a_disabled_rule_covers_nothing() {
        let rule = Rule::builder()
            .status(ExpirationStatus::Disabled)
            .expiration(expiration_days(30))
            .build()
            .unwrap();
        assert!(!rule_covers_prefix(&rule, "ksp/"));
    }

    #[test]
    fn a_rule_without_expiration_covers_nothing() {
        let rule = Rule::builder()
            .status(ExpirationStatus::Enabled)
            .build()
            .unwrap();
        assert!(!rule_covers_prefix(&rule, "ksp/"));
    }

    #[test]
    fn a_zero_day_expiration_covers_nothing() {
        let rule = Rule::builder()
            .status(ExpirationStatus::Enabled)
            .expiration(expiration_days(0))
            .build()
            .unwrap();
        assert!(!rule_covers_prefix(&rule, "ksp/"));
    }

    #[test]
    fn a_delete_marker_expiration_covers_nothing() {
        let expiration = LifecycleExpiration::builder()
            .expired_object_delete_marker(true)
            .build();
        let rule = Rule::builder()
            .status(ExpirationStatus::Enabled)
            .expiration(expiration)
            .build()
            .unwrap();
        assert!(!rule_covers_prefix(&rule, "ksp/"));
    }

    #[test]
    fn a_rule_without_a_filter_covers_nothing() {
        // A rule with no filter applies to the whole bucket, which is not a
        // statement about *this* prefix. Treating it as coverage would let an
        // unrelated bucket-wide rule qualify the prefix.
        let rule = Rule::builder()
            .status(ExpirationStatus::Enabled)
            .expiration(expiration_days(30))
            .build()
            .unwrap();
        assert!(!rule_covers_prefix(&rule, "ksp/"));
    }

    #[test]
    fn a_matching_prefix_filter_covers_the_prefix() {
        let rule = rule_with_filter(LifecycleRuleFilter::builder().prefix("ksp/").build());
        assert!(rule_covers_prefix(&rule, "ksp/records/"));
    }

    #[test]
    fn a_prefix_filter_that_does_not_match_covers_nothing() {
        let rule = rule_with_filter(LifecycleRuleFilter::builder().prefix("other/").build());
        assert!(!rule_covers_prefix(&rule, "ksp/records/"));
    }

    #[test]
    fn a_tag_filtered_rule_covers_nothing() {
        let rule = rule_with_filter(
            LifecycleRuleFilter::builder()
                .prefix("ksp/")
                .tag(Tag::builder().key("k").value("v").build().unwrap())
                .build(),
        );
        assert!(!rule_covers_prefix(&rule, "ksp/records/"));
    }

    #[test]
    fn an_and_filtered_rule_covers_nothing() {
        let rule = rule_with_filter(
            LifecycleRuleFilter::builder()
                .prefix("ksp/")
                .and(
                    LifecycleRuleAndOperator::builder()
                        .prefix("ksp/records/")
                        .build(),
                )
                .build(),
        );
        assert!(!rule_covers_prefix(&rule, "ksp/records/"));
    }
}
