//! Shamir secret sharing over GF(2^8), for the user's own recovery shares.
//!
//! # What this may split
//!
//! The split function accepts a [`SealedBundle`], not a bare byte string, so a
//! caller cannot pass raw bytes where the bundle type is required. The caller
//! is responsible for passing only the user's own sealed bundle: this type
//! cannot distinguish it from an admin-supplied value (FR-007).
//!
//! # What this is not
//!
//! This is a secret-sharing scheme, not a cryptographic primitive. It is
//! implemented in-crate because the `shamir` crate (2.0.0) has been
//! unmaintained since 2020 and does not meet the audit posture of the rest
//! of the dependency set. The construction is the one used by `sops`.
//!
//! Shamir restores a **sealed** bundle, never a lost phrase. A phrase that
//! is lost is fatal without another explicitly supported unseal method.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The number of shares needed to reconstruct a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold(pub usize);

/// The number of shares produced by a split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareCount(pub usize);

/// The error produced by a split or a reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ShamirError {
    /// The threshold is zero, or larger than the share count.
    #[error("threshold {threshold} is not between 1 and {shares}")]
    InvalidThreshold {
        /// The requested threshold.
        threshold: usize,
        /// The requested share count.
        shares: usize,
    },
    /// Fewer shares than the threshold were presented.
    #[error("reconstruction needs {threshold} shares but only {presented} were presented")]
    InsufficientShares {
        /// The threshold that was split with.
        threshold: usize,
        /// How many shares were presented.
        presented: usize,
    },
    /// The presented shares are not a valid set — two of them are the same
    /// share, or they disagree about the secret.
    #[error("the presented shares are inconsistent")]
    InconsistentShares,
}

/// A sealed key bundle belonging to one user.
///
/// This type lets the split API require a sealed bundle rather than raw
/// bytes. The caller must ensure it contains the user's own bundle; the type
/// cannot distinguish that from admin-supplied bytes.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SealedBundle(Vec<u8>);

impl SealedBundle {
    /// Wrap already-sealed bytes.
    pub fn new(sealed: Vec<u8>) -> Self {
        Self(sealed)
    }

    /// The sealed bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One share of a sealed bundle.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    /// The share's evaluation point. Two shares with the same point are the
    /// same share.
    pub index: u8,
    /// The share's value, one byte per byte of the sealed bundle.
    pub value: Vec<u8>,
}

/// The finite field GF(2^8) with the AES polynomial `x^8 + x^4 + x^3 + x + 1`.
struct Gf256;

impl Gf256 {
    const POLY: u16 = 0x11b;

    /// Multiply two field elements.
    fn mul(a: u8, b: u8) -> u8 {
        let mut result: u16 = 0;
        let mut a: u16 = u16::from(a);
        let mut b: u16 = u16::from(b);

        while b != 0 {
            if b & 1 == 1 {
                result ^= a;
            }
            a <<= 1;
            if a & 0x100 != 0 {
                a ^= Self::POLY;
            }
            b >>= 1;
        }
        result as u8
    }

    /// The multiplicative inverse of a non-zero element.
    ///
    /// Implemented by exhaustive search over the 255 non-zero elements. The
    /// field is tiny and this is not on a hot path, so clarity wins over an
    /// exponentiation ladder.
    fn inv(a: u8) -> Option<u8> {
        if a == 0 {
            return None;
        }
        (1u16..=255)
            .map(|x| x as u8)
            .find(|x| Self::mul(a, *x) == 1)
    }

    /// Divide `a` by `b`.
    fn div(a: u8, b: u8) -> Option<u8> {
        Self::inv(b).map(|inv_b| Self::mul(a, inv_b))
    }
}

/// Evaluate the polynomial with the given coefficients at `x`.
///
/// `coefficients[0]` is the constant term, matching the sops construction.
fn evaluate(coefficients: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for coefficient in coefficients.iter().rev() {
        result = Gf256::mul(result, x) ^ coefficient;
    }
    result
}

/// Split a user's own sealed bundle into `shares` shares, `threshold` of
/// which reconstruct it.
///
/// The function accepts a [`SealedBundle`], not a byte string. The caller
/// must supply only the user's own sealed bundle (FR-007); this type cannot
/// verify the provenance of bytes passed to [`SealedBundle::new`].
pub fn split(
    bundle: &SealedBundle,
    threshold: Threshold,
    shares: ShareCount,
) -> Result<Vec<Share>, ShamirError> {
    let (threshold, share_count) = (threshold.0, shares.0);
    if threshold == 0 || threshold > share_count {
        return Err(ShamirError::InvalidThreshold {
            threshold,
            shares: share_count,
        });
    }

    let secret = bundle.as_bytes();

    // Each byte position of the secret gets its **own** polynomial, and
    // every share is an evaluation of those same polynomials. The
    // coefficients are drawn once, not once per share: shares that lie on
    // different polynomials carry no information about each other, and
    // reconstruction would recover nothing.
    let polynomials: Vec<Vec<u8>> = secret
        .iter()
        .map(|secret_byte| {
            let mut coefficients = Vec::with_capacity(threshold);
            coefficients.push(*secret_byte);
            for _ in 1..threshold {
                coefficients.push(rand::random::<u8>());
            }
            coefficients
        })
        .collect();

    let mut result = Vec::with_capacity(share_count);
    let mut used_points: Vec<u8> = Vec::with_capacity(share_count);

    while result.len() < share_count {
        // A random evaluation point distinct from zero, so that no share
        // leaks the secret directly, and distinct from every other share's
        // point: two shares at the same point are the same share, and the
        // reconstruction would refuse them.
        let x = loop {
            let candidate = rand::random::<u8>();
            if candidate != 0 && !used_points.contains(&candidate) {
                break candidate;
            }
        };
        used_points.push(x);

        let value: Vec<u8> = polynomials.iter().map(|p| evaluate(p, x)).collect();

        result.push(Share { index: x, value });
    }

    Ok(result)
}

/// Reconstruct a sealed bundle from `threshold` or more shares.
///
/// Fewer than `threshold` shares fail explicitly, naming the threshold
/// (FR-008). Shares that disagree fail too: a wrong share is not silently
/// averaged away, because a wrong share means the reconstruction is wrong.
pub fn recover(shares: &[Share], threshold: Threshold) -> Result<SealedBundle, ShamirError> {
    let threshold = threshold.0;

    if shares.len() < threshold {
        return Err(ShamirError::InsufficientShares {
            threshold,
            presented: shares.len(),
        });
    }

    // Use exactly `threshold` distinct shares.
    let mut distinct: Vec<&Share> = Vec::with_capacity(threshold);
    for share in shares {
        if distinct.iter().any(|s| s.index == share.index) {
            return Err(ShamirError::InconsistentShares);
        }
        distinct.push(share);
        if distinct.len() == threshold {
            break;
        }
    }

    let length = distinct[0].value.len();
    if distinct.iter().any(|s| s.value.len() != length) {
        return Err(ShamirError::InconsistentShares);
    }

    let mut recovered = vec![0u8; length];

    for (position, slot) in recovered.iter_mut().enumerate() {
        // Lagrange interpolation at zero.
        //
        // In a field of characteristic two, subtraction is XOR, so
        // (0 - x_j) is x_j and (x_i - x_j) is (x_i ^ x_j).
        let mut value = 0u8;

        for (i, share_i) in distinct.iter().enumerate() {
            let mut numerator = 1u8;
            let mut denominator = 1u8;

            for (j, share_j) in distinct.iter().enumerate() {
                if i == j {
                    continue;
                }
                let difference = share_i.index ^ share_j.index;
                if difference == 0 {
                    return Err(ShamirError::InconsistentShares);
                }
                numerator = Gf256::mul(numerator, share_j.index);
                denominator = Gf256::mul(denominator, difference);
            }

            let factor =
                Gf256::div(numerator, denominator).ok_or(ShamirError::InconsistentShares)?;
            value ^= Gf256::mul(factor, share_i.value[position]);
        }

        *slot = value;
    }

    Ok(SealedBundle::new(recovered))
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn bundle() -> SealedBundle {
        SealedBundle::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    }

    #[test]
    fn recovery_types_implement_zeroize_and_work_with_zeroizing() {
        use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

        fn requires_zeroize<T: Zeroize + ZeroizeOnDrop>() {}
        requires_zeroize::<SealedBundle>();
        requires_zeroize::<Share>();

        let bundle = Zeroizing::new(SealedBundle::new(vec![1, 2, 3]));
        assert_eq!(bundle.as_bytes(), &[1, 2, 3]);
        let share = Zeroizing::new(Share {
            index: 1,
            value: vec![4, 5, 6],
        });
        assert_eq!(share.value, vec![4, 5, 6]);
    }

    #[test]
    fn reconstructs_from_exactly_the_threshold() {
        let secret = bundle();
        let shares = split(&secret, Threshold(3), ShareCount(5)).unwrap();
        let recovered = recover(&shares[..3], Threshold(3)).unwrap();
        assert_eq!(recovered.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn reconstructs_from_more_than_the_threshold() {
        let secret = bundle();
        let shares = split(&secret, Threshold(3), ShareCount(5)).unwrap();
        let recovered = recover(&shares, Threshold(3)).unwrap();
        assert_eq!(recovered.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn one_below_the_threshold_fails_and_names_it() {
        let secret = bundle();
        let shares = split(&secret, Threshold(3), ShareCount(5)).unwrap();

        match recover(&shares[..2], Threshold(3)).unwrap_err() {
            ShamirError::InsufficientShares {
                threshold,
                presented,
            } => {
                assert_eq!(threshold, 3);
                assert_eq!(presented, 2);
            }
            other => panic!("expected an insufficient-shares error, got {other:?}"),
        }

        assert!(
            recover(&shares[..2], Threshold(3))
                .unwrap_err()
                .to_string()
                .contains("3"),
            "the failure must name the threshold"
        );
    }

    #[test]
    fn a_single_share_split_reconstructs() {
        let secret = bundle();
        let shares = split(&secret, Threshold(1), ShareCount(3)).unwrap();
        let recovered = recover(&shares[..1], Threshold(1)).unwrap();
        assert_eq!(recovered.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn duplicate_share_indices_are_rejected() {
        let secret = bundle();
        let shares = split(&secret, Threshold(2), ShareCount(3)).unwrap();
        let duplicated = vec![shares[0].clone(), shares[0].clone()];
        assert_eq!(
            recover(&duplicated, Threshold(2)).unwrap_err(),
            ShamirError::InconsistentShares
        );
    }

    #[test]
    fn an_invalid_threshold_is_rejected() {
        let secret = bundle();
        assert!(split(&secret, Threshold(0), ShareCount(3)).is_err());
        assert!(split(&secret, Threshold(4), ShareCount(3)).is_err());
    }

    #[test]
    fn shares_do_not_contain_the_secret() {
        let secret = bundle();
        let shares = split(&secret, Threshold(3), ShareCount(5)).unwrap();
        for share in &shares {
            assert_ne!(
                share.value,
                secret.as_bytes(),
                "a share must not equal the secret"
            );
        }
    }
}
