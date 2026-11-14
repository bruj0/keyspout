//! The user-facing Shamir recovery operation.
//!
//! WP01 provides the GF(256) primitives; this module is the operation the user
//! actually runs. It splits the user's **own sealed bundle** and reconstructs it
//! from `k` of `n` shares, reporting the threshold explicitly when too few
//! shares are presented (FR-008).
//!
//! # What recovery restores, and what it does not
//!
//! Shamir restores a **sealed** bundle, never a lost phrase. A phrase that is
//! lost is fatal without another explicitly supported unseal method. Recovery
//! also does not resurrect keys that were rotated away: rotation changes future
//! minting and trust state, and old artifacts keep decrypting under the old key
//! rather than being recalled.
//!
//! # Only the user's own bundle
//!
//! The split takes a [`SealedBundle`], so a caller cannot pass raw bytes where a
//! sealed bundle is required. The type cannot verify provenance — that the
//! bundle is the user's own and not an admin-supplied value is the caller's
//! responsibility (FR-007). What it can do, and does, is make the bytes pass
//! through a type that names them a sealed bundle.

use ksp_types::shamir::{recover, split};
use ksp_types::{SealedBundle, ShamirError, Share, ShareCount, Threshold};

/// Why a recovery operation could not complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    /// The share set or the threshold is not usable.
    #[error(transparent)]
    Shamir(#[from] ShamirError),
    /// No shares were produced or presented.
    #[error("the recovery operation needs at least one share")]
    NoShares,
    /// The phrase is not one this format can read.
    #[error("the recovery phrase is not usable: {0}")]
    Phrase(&'static str),
    /// The new sealed bytes could not be stored, so no phrase may be handed out.
    #[error("the re-sealed vault could not be stored: {reason}")]
    Persist {
        /// Why the caller could not store it.
        reason: String,
    },
}

impl RecoveryError {
    /// The threshold the user needed, when the failure was too few shares.
    ///
    /// Exposed separately from the display text because a caller that wants to
    /// tell the user "you have 2 of the 3 you need" should not have to parse a
    /// message.
    pub fn required_threshold(&self) -> Option<usize> {
        match self {
            Self::Shamir(ShamirError::InsufficientShares { threshold, .. }) => Some(*threshold),
            _ => None,
        }
    }

    /// How many shares were presented, when the failure was too few shares.
    pub fn presented_shares(&self) -> Option<usize> {
        match self {
            Self::Shamir(ShamirError::InsufficientShares { presented, .. }) => Some(*presented),
            _ => None,
        }
    }
}

/// Split the user's own sealed bundle into `shares` shares, `threshold` of which
/// reconstruct it.
///
/// The caller must pass only the user's own bundle (FR-007). The scheme is the
/// same one `ksp_types::split` uses; this wrapper exists so that the recovery
/// surface is one call and so an empty request is refused early.
pub fn split_vault_bundle(
    bundle: &SealedBundle,
    threshold: Threshold,
    shares: ShareCount,
) -> Result<Vec<Share>, RecoveryError> {
    if shares.0 == 0 {
        return Err(RecoveryError::NoShares);
    }
    Ok(split(bundle, threshold, shares)?)
}

/// Reconstruct the user's sealed bundle from `threshold` or more shares.
///
/// Fewer shares than the threshold fail explicitly and name the threshold
/// (FR-008). Shares that disagree fail too: a wrong share is not averaged away.
pub fn recover_vault_bundle(
    shares: &[Share],
    threshold: Threshold,
) -> Result<SealedBundle, RecoveryError> {
    if shares.is_empty() {
        return Err(RecoveryError::NoShares);
    }
    Ok(recover(shares, threshold)?)
}

/// A share set as an operator can write it down.
///
/// # Why a rendering exists at all
///
/// A recovery phrase is the only copy of the recovery material, so it has to be
/// text an operator can print, store offline and type back. It is not a second
/// format for the bundle: it carries the threshold and the shares, and
/// [`RecoveryPhrase::recover`] reconstructs exactly what
/// [`recover_vault_bundle`] reconstructs.
///
/// # Parsing is strict on purpose
///
/// A phrase that has been mistyped must fail, not recover something. The header
/// names the threshold, every share carries its own index, and a duplicated
/// index is refused rather than treated as two shares — the second would
/// contribute nothing and would silently turn a `k`-of-`n` set into a
/// `(k-1)`-of-`n` one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPhrase {
    threshold: Threshold,
    shares: Vec<Share>,
}

impl RecoveryPhrase {
    /// The line that names the format and the threshold.
    pub const HEADER: &'static str = "keyspout-recovery-v1";

    /// Build a phrase from a share set, refusing a set that cannot reconstruct.
    pub fn new(threshold: Threshold, shares: Vec<Share>) -> Result<Self, RecoveryError> {
        if shares.is_empty() {
            return Err(RecoveryError::NoShares);
        }
        if threshold.0 == 0 || threshold.0 > shares.len() {
            return Err(RecoveryError::Shamir(ShamirError::InvalidThreshold {
                threshold: threshold.0,
                shares: shares.len(),
            }));
        }
        // Every share of one bundle has the same length, so a short one is a
        // typing error rather than a different share. Checked here rather than in
        // `parse` so the constructor cannot build a phrase it would refuse.
        if let Some(first) = shares.first()
            && shares
                .iter()
                .any(|share| share.value.len() != first.value.len())
        {
            return Err(RecoveryError::Phrase(
                "the shares are not all the same length",
            ));
        }
        // Two shares at one evaluation point cannot both contribute, so a set
        // that holds one twice is not the set it claims to be.
        let mut seen = std::collections::BTreeSet::new();
        for share in &shares {
            // Index zero is where the polynomial's constant term sits, so a share
            // at zero *is* the secret. `split` refuses to produce one for exactly
            // that reason, which makes zero a value a phrase can never carry.
            if share.index == 0 {
                return Err(RecoveryError::Phrase("a share index may not be zero"));
            }
            if !seen.insert(share.index) {
                return Err(RecoveryError::Phrase("two shares carry the same index"));
            }
        }
        Ok(Self { threshold, shares })
    }

    /// The threshold this phrase needs.
    pub fn threshold(&self) -> Threshold {
        self.threshold
    }

    /// The shares this phrase carries.
    pub fn shares(&self) -> &[Share] {
        &self.shares
    }

    /// Render the phrase for a person to store.
    pub fn render(&self) -> String {
        let mut text = format!(
            "{} k={} n={}\n",
            Self::HEADER,
            self.threshold.0,
            self.shares.len()
        );
        for share in &self.shares {
            text.push_str(&format!("share {} {}\n", share.index, hex(&share.value)));
        }
        text
    }

    /// Parse a phrase, refusing anything that is not exactly one.
    pub fn parse(text: &str) -> Result<Self, RecoveryError> {
        let mut lines = text.lines().filter(|line| !line.trim().is_empty());

        let header = lines
            .next()
            .ok_or(RecoveryError::Phrase("the phrase is empty"))?;
        let mut fields = header.split_whitespace();
        if fields.next() != Some(Self::HEADER) {
            return Err(RecoveryError::Phrase("the phrase header is not recognised"));
        }
        let threshold = Self::field(fields.next(), "k=")?;
        let declared = Self::field(fields.next(), "n=")?;
        if fields.next().is_some() {
            return Err(RecoveryError::Phrase("the phrase header has extra fields"));
        }

        let mut shares = Vec::new();
        for line in lines {
            let mut parts = line.split_whitespace();
            if parts.next() != Some("share") {
                return Err(RecoveryError::Phrase("a share line is not recognised"));
            }
            let index = parts
                .next()
                .ok_or(RecoveryError::Phrase("a share line has no index"))?
                .parse::<u8>()
                .map_err(|_| RecoveryError::Phrase("a share index is not a number"))?;
            let value = parts
                .next()
                .ok_or(RecoveryError::Phrase("a share line has no value"))?;
            if parts.next().is_some() {
                return Err(RecoveryError::Phrase("a share line has extra fields"));
            }
            let value = unhex(value)?;
            shares.push(Share { index, value });
        }

        if shares.len() != declared {
            return Err(RecoveryError::Phrase(
                "the phrase declares a share count it does not carry",
            ));
        }
        // `new` owns the set-level invariants: threshold bounds, equal lengths,
        // a duplicated index and the index-zero rule all live in one place.
        Self::new(Threshold(threshold), shares)
    }

    /// Reconstruct the sealed bundle this phrase describes.
    pub fn recover(&self) -> Result<SealedBundle, RecoveryError> {
        recover_vault_bundle(&self.shares, self.threshold)
    }

    /// Read one `prefix=number` field.
    fn field(field: Option<&str>, prefix: &str) -> Result<usize, RecoveryError> {
        let number = field
            .and_then(|value| value.strip_prefix(prefix))
            .ok_or(RecoveryError::Phrase("the phrase header is not recognised"))?;
        // A header that parses as a phrase but carries `k=abc` is a typo in the
        // number, not an unknown format, and saying so saves an operator a hunt.
        number
            .parse::<usize>()
            .map_err(|_| RecoveryError::Phrase("a threshold or share count is not a number"))
    }
}

/// Render bytes as lower-case hex.
///
/// One buffer rather than one `String` per byte: a phrase is share material, and
/// a per-byte temporary would leave each byte in a small allocation the compiler
/// is under no obligation to wipe.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a String cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Parse lower-case or upper-case hex.
fn unhex(text: &str) -> Result<Vec<u8>, RecoveryError> {
    if !text.len().is_multiple_of(2) {
        return Err(RecoveryError::Phrase(
            "a share value has an odd number of digits",
        ));
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks(2) {
        // `from_str_radix` accepts a leading `+`, so `+1` would parse as hex 01.
        // Parsing is the boundary that decides whether a mistyped phrase opens
        // something, so the accepted alphabet is checked rather than trusted.
        if !pair.iter().all(u8::is_ascii_hexdigit) {
            return Err(RecoveryError::Phrase("a share value is not hex"));
        }
        let digits = std::str::from_utf8(pair)
            .map_err(|_| RecoveryError::Phrase("a share value is not text"))?;
        bytes.push(
            u8::from_str_radix(digits, 16)
                .map_err(|_| RecoveryError::Phrase("a share value is not hex"))?,
        );
    }
    Ok(bytes)
}

/// Re-seal the vault and re-split it, handing the new bytes to `persist` first.
///
/// The phrase is returned only after `persist` succeeded. That ordering is the
/// whole point of the signature: a phrase an operator writes down is the only
/// copy of the recovery material, and returning one for bytes that are not
/// durable would leave the operator holding a phrase that opens nothing.
pub fn reshare_vault_bundle<P>(
    sealed: &SealedBundle,
    threshold: Threshold,
    shares: ShareCount,
    persist: P,
) -> Result<RecoveryPhrase, RecoveryError>
where
    P: FnOnce(&SealedBundle) -> Result<(), String>,
{
    // Split and validate *before* persisting. The split can fail (a threshold
    // outside 1..=n), and persisting first would then have replaced the file with
    // a bundle the operator holds no phrase for — while their old phrase no
    // longer matches it either. Nothing is written until a phrase is guaranteed.
    let produced = split_vault_bundle(sealed, threshold, shares)?;
    let phrase = RecoveryPhrase::new(threshold, produced)?;

    // The bundle is persisted as it will be reconstructed, so what is written and
    // what the phrase restores are the same bytes by construction.
    persist(sealed).map_err(|reason| RecoveryError::Persist { reason })?;
    Ok(phrase)
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn bundle() -> SealedBundle {
        SealedBundle::new(b"sealed user key bundle, never a phrase".to_vec())
    }

    #[test]
    fn k_of_n_reconstructs_the_bundle() {
        let sealed = bundle();
        let shares = split_vault_bundle(&sealed, Threshold(3), ShareCount(5)).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = recover_vault_bundle(&shares[..3], Threshold(3)).unwrap();
        assert_eq!(recovered, sealed);
    }

    /// Every set of exactly `k` shares recovers the same bundle, not just the
    /// first `k` in the produced order.
    #[test]
    fn any_k_of_n_reconstructs_the_bundle() {
        let sealed = bundle();
        let shares = split_vault_bundle(&sealed, Threshold(2), ShareCount(3)).unwrap();
        for pair in [[0usize, 1], [0, 2], [1, 2]] {
            let chosen = vec![shares[pair[0]].clone(), shares[pair[1]].clone()];
            let recovered = recover_vault_bundle(&chosen, Threshold(2)).unwrap();
            assert_eq!(recovered, sealed, "shares {pair:?} did not recover");
        }
    }

    /// `k - 1` shares fail, and the failure names the threshold (FR-008).
    #[test]
    fn k_minus_one_shares_fail_and_name_the_threshold() {
        let sealed = bundle();
        let shares = split_vault_bundle(&sealed, Threshold(3), ShareCount(5)).unwrap();

        let error = recover_vault_bundle(&shares[..2], Threshold(3))
            .expect_err("k-1 shares must not reconstruct");

        assert_eq!(error.required_threshold(), Some(3));
        assert_eq!(error.presented_shares(), Some(2));
        let message = error.to_string();
        assert!(
            message.contains('3'),
            "the refusal must name the threshold, got {message:?}"
        );
    }

    /// The boundary either way: exactly `k` succeeds, `k-1` does not.
    #[test]
    fn the_threshold_boundary_is_exact() {
        let sealed = bundle();
        let shares = split_vault_bundle(&sealed, Threshold(2), ShareCount(4)).unwrap();
        assert!(recover_vault_bundle(&shares[..1], Threshold(2)).is_err());
        assert!(recover_vault_bundle(&shares[..2], Threshold(2)).is_ok());
    }

    #[test]
    fn an_empty_share_set_is_refused_by_name() {
        assert_eq!(
            recover_vault_bundle(&[], Threshold(1)),
            Err(RecoveryError::NoShares)
        );
    }

    #[test]
    fn an_impossible_threshold_is_refused() {
        let sealed = bundle();
        match split_vault_bundle(&sealed, Threshold(4), ShareCount(3)) {
            Err(RecoveryError::Shamir(ShamirError::InvalidThreshold { threshold, shares })) => {
                assert_eq!((threshold, shares), (4, 3));
            }
            other => panic!("expected an invalid-threshold refusal, got {other:?}"),
        }
    }
}
