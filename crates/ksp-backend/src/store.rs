//! Blob Store operations over opaque bytes; no key or decrypt operation.

pub use ksp_record::version::StoreError;

/// A Blob Store never receives plaintext or a decryption key.
///
/// The contract extends the record subsystem's immutable publication
/// operations with exact-version removal. Conditional replace must be atomic
/// at the store, not a read followed by a blind write.
pub trait BlobStore: ksp_record::version::BlobStore {
    /// Remove one exact path, without inferring physical erasure.
    fn delete(&self, path: &str) -> Result<(), StoreError>;
}

/// Validate a blob path before it reaches a backend.
///
/// Every backend must agree on what a valid path is, or the same call works
/// against one backend and fails against another. The rules are narrow on
/// purpose:
///
/// * no empty path,
/// * no leading or trailing `/`,
/// * no empty interior segment, so `a//b` is refused rather than silently
///   read as `a/b` — a local filesystem collapses the empty segment, which
///   would let two distinct path strings name the same blob,
/// * no `.` or `..` component.
pub fn validate_path(path: &str) -> Result<(), StoreError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(StoreError::Backend("invalid blob path".into()));
    }
    Ok(())
}

/// Validate a listing prefix.
///
/// A prefix names a range of paths rather than one path, so a single
/// trailing `/` is permitted and is not significant: `records/` and
/// `records` must list the same set. The empty prefix names the whole
/// namespace.
pub fn validate_prefix(prefix: &str) -> Result<(), StoreError> {
    let trimmed = prefix.strip_suffix('/').unwrap_or(prefix);
    if trimmed.is_empty() {
        return Ok(());
    }
    validate_path(trimmed)
}
