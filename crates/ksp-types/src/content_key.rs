//! The content key: the symmetric key that protects one record version's
//! payload.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The length of a content key in bytes.
pub const CONTENT_KEY_LEN: usize = 32;

/// The key bytes, in a type that reports its own erasure.
///
/// The report goes to an observer, so a test can watch the erasure happen
/// on the real key rather than on a stand-in for it. The bytes themselves
/// are erased by [`Zeroize`], which both the `ContentKey` implementation and
/// the derived drop path call.
struct KeyBytes([u8; CONTENT_KEY_LEN]);

impl Zeroize for KeyBytes {
    fn zeroize(&mut self) {
        // The observer records the bytes before and after the erasure, so a
        // test can prove both that the bytes which passed through this path
        // were the bytes the key actually held, and that those bytes were
        // really erased.
        #[cfg(any(test, feature = "test-observer"))]
        let before = self.0;

        self.0.zeroize();

        #[cfg(any(test, feature = "test-observer"))]
        ERASURE_OBSERVER.with(|observer| {
            *observer.borrow_mut() = Some(Erasure {
                before,
                after: self.0,
            });
        });
    }
}

// The bytes a content key held when it was last erased on this thread.
//
// The observer exists so a test can watch the erasure happen on the real
// type. It is compiled only into a test build or into a build with the
// `test-observer` feature, so a shipped crate holds no copy of erased
// bytes.
//
// The `test-observer` feature retains a copy of the key bytes in a
// thread-local. It must never be enabled in a shipped build; the
// workspace enables it only through a development dependency.
//
// The observer is thread-local and holds at most one erased key.
#[cfg(any(test, feature = "test-observer"))]
thread_local! {
    static ERASURE_OBSERVER: std::cell::RefCell<Option<Erasure>> =
        const { std::cell::RefCell::new(None) };
}

/// One observed erasure of a content key.
///
/// The two snapshots are what make the observation worth anything: the
/// bytes *before* the erasure show which key passed through the path, and
/// the bytes *after* the erasure show that the path really erased them.
#[cfg(any(test, feature = "test-observer"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Erasure {
    /// The bytes the key held immediately before the erasure.
    pub before: [u8; CONTENT_KEY_LEN],
    /// The bytes the key held immediately after the erasure.
    pub after: [u8; CONTENT_KEY_LEN],
}

/// The last erasure observed on this thread.
///
/// Returns `None` when no content key has been erased on this thread since
/// the last observation.
#[cfg(any(test, feature = "test-observer"))]
pub fn last_erasure() -> Option<Erasure> {
    ERASURE_OBSERVER.with(|observer| *observer.borrow())
}

/// Take the last erasure observed on this thread.
///
/// The observation is cleared, so a later call reports `None` until the
/// next erasure.
#[cfg(any(test, feature = "test-observer"))]
pub fn take_erasure() -> Option<Erasure> {
    ERASURE_OBSERVER.with(|observer| observer.borrow_mut().take())
}

/// A fresh random 256-bit symmetric key that encrypts one record version's
/// payload.
///
/// The key exists in the clear only inside the sealing process. Every saved
/// or transferred artifact carries it *sealed* to a recipient key — never
/// raw.
///
/// The key is zeroized on drop, so a dropped `ContentKey` leaves no key
/// material behind in the heap.
///
/// The `Zeroize` and `ZeroizeOnDrop` implementations are derived. A
/// hand-written drop path does not imply the `Zeroize` trait
/// implementation, and a `ContentKey` that is not `Zeroize` cannot be held
/// in a `Zeroizing`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContentKey(KeyBytes);

impl ContentKey {
    /// Wrap exactly 32 bytes as a content key.
    pub fn from_bytes(bytes: [u8; CONTENT_KEY_LEN]) -> Self {
        Self(KeyBytes(bytes))
    }

    /// Generate a fresh random content key.
    ///
    /// The randomness comes from the operating system's CSPRNG through
    /// `rand`. `rand`'s thread-local generator is infallible on the
    /// platforms this targets: it panics rather than returning a weaker
    /// source, which is the correct behaviour for a key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; CONTENT_KEY_LEN];
        rand::fill(&mut bytes);
        Self(KeyBytes(bytes))
    }

    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8; CONTENT_KEY_LEN] {
        &self.0.0
    }
}

impl Clone for ContentKey {
    fn clone(&self) -> Self {
        Self(KeyBytes(self.0.0))
    }
}

// The key must never reach a debug representation: `Debug` would print the
// bytes.
impl core::fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ContentKey([redacted])")
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use zeroize::Zeroizing;

    /// The trait bounds a downstream crate depends on.
    ///
    /// A hand-written drop path satisfies `ZeroizeOnDrop` but not
    /// `Zeroize`, and a `ContentKey` that is not `Zeroize` cannot be held
    /// in a `Zeroizing`. The bounds are checked here so the regression
    /// cannot come back silently.
    fn assert_zeroize<T: Zeroize>() {}
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn the_content_key_implements_both_zeroize_traits() {
        assert_zeroize::<ContentKey>();
        assert_zeroize_on_drop::<ContentKey>();
    }

    #[test]
    fn a_content_key_can_be_held_in_a_zeroizing_wrapper() {
        let wrapped: Zeroizing<ContentKey> = Zeroizing::new(ContentKey::generate());
        assert!(wrapped.as_bytes().iter().any(|b| *b != 0));
    }

    #[test]
    fn a_generated_key_is_not_zero() {
        let key = ContentKey::generate();
        assert!(key.as_bytes().iter().any(|b| *b != 0));
    }

    #[test]
    fn two_generated_keys_differ() {
        let a = ContentKey::generate();
        let b = ContentKey::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn debug_does_not_reveal_the_key() {
        let key = ContentKey::from_bytes([0x42; CONTENT_KEY_LEN]);
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("42"), "the key leaked into Debug");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn the_drop_path_erases_the_key() {
        // The observation must be about the real type. A test that only
        // checks the trait bound cannot tell the working drop path from a
        // broken one.
        let _ = take_erasure();

        drop(ContentKey::from_bytes([0xCD; CONTENT_KEY_LEN]));

        let erasure = take_erasure().expect("dropping a content key must erase it");
        assert_eq!(
            erasure.before, [0xCD; CONTENT_KEY_LEN],
            "the erasure must be about the bytes the key actually held"
        );
        assert_eq!(
            erasure.after, [0u8; CONTENT_KEY_LEN],
            "the erasure must really erase the bytes"
        );
    }

    #[test]
    fn the_zeroize_trait_erases_the_key_in_place() {
        let mut key = ContentKey::from_bytes([0xEF; CONTENT_KEY_LEN]);
        key.zeroize();
        assert!(
            key.as_bytes().iter().all(|b| *b == 0),
            "the Zeroize implementation must erase the bytes in place"
        );
    }
}
