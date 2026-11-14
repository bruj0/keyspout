//! The contract of the blob store: opaque bytes in, opaque bytes out.
//!
//! WP02 acceptance criterion 9 asks for a proof that the blob store trait
//! exposes no decrypt method and no key-taking method. The misfit it closes
//! is the one the whole design rests on: the moment a store can be asked to
//! decrypt — or is handed a key — the storage boundary stops being a
//! boundary, and every backend becomes a place where plaintext secrets live.
//!
//! Three layers assert it, and each one fails for a different reason:
//!
//! * A fake store implements the trait in full. It can only be written
//!   against the exact operation set the trait declares today, so an
//!   operation the trait *demands* breaks the build.
//! * A source-level reflection over the trait declarations, read at compile
//!   time, fails loudly when a forbidden name appears — including a name
//!   that arrives with a default body and so would not break the fake.
//! * A method-resolution probe asks the compiler which implementation of a
//!   forbidden operation name answered the call. The fallback is only
//!   reachable when the store trait has no such operation.
//!
//! The fake store only ever sees bytes and path strings. It holds no key
//! material, no passphrase and no plaintext secret, and no test in this file
//! needs any.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::HashMap;

use ksp_backend::store::{BlobStore, StoreError};
// The backend trait extends the record-level one, so the supertrait has to
// be in scope for `get`, `put_if_absent`, `compare_and_set` and `list` to
// resolve on the fake store.
use ksp_record::version::BlobStore as RecordBlobStore;

/// The backend trait declaration, read at compile time.
const BACKEND_TRAIT_SOURCE: &str = include_str!("../src/store.rs");
/// The record-level trait declaration, read at compile time.
///
/// The backend trait extends it, so a key-taking operation added there
/// would be inherited by every backend and would be just as much a breach.
const RECORD_TRAIT_SOURCE: &str = include_str!("../../ksp-record/src/version.rs");

/// The words that must not name, or appear in, an operation of the store
/// trait. A store that takes or returns any of these is a store that holds
/// secrets, and a store that holds secrets is not the boundary the design
/// assumes.
const FORBIDDEN_WORDS: &[&str] = &[
    "decrypt",
    "encrypt",
    "key",
    "plain",
    "secret",
    "unwrap",
    "open",
    "seal",
    "sign",
    "derive",
    "passphrase",
    "password",
    "credential",
    "token",
];

/// The method names the store trait is allowed to expose.
const EXPECTED_METHODS: &[&str] = &["compare_and_set", "delete", "get", "list", "put_if_absent"];

/// A store that holds opaque bytes in memory.
///
/// It is deliberately dull: it can only be written against the operation set
/// the trait declares, so it is also a compile-time witness of that set.
///
/// The store operations take `&self`, so the bytes live behind a `RefCell`.
/// That is the point of the trait: a store is written to through a shared
/// reference and never hands back anything but bytes.
#[derive(Default)]
struct MemoryStore {
    blobs: RefCell<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    /// The bytes currently held, for the assertions that read them back.
    fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut held: Vec<(String, Vec<u8>)> = self
            .blobs
            .borrow()
            .iter()
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect();
        held.sort();
        held
    }
}
impl RecordBlobStore for MemoryStore {
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.blobs.borrow().get(path).cloned())
    }

    fn put_if_absent(&self, path: &str, bytes: &[u8]) -> Result<bool, StoreError> {
        let mut blobs = self.blobs.borrow_mut();
        if blobs.contains_key(path) {
            return Ok(false);
        }
        blobs.insert(path.to_string(), bytes.to_vec());
        Ok(true)
    }

    fn compare_and_set(
        &self,
        path: &str,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<bool, StoreError> {
        let mut blobs = self.blobs.borrow_mut();
        let current = blobs.get(path).map(|bytes| bytes.as_slice());
        if current != expected {
            return Ok(false);
        }
        blobs.insert(path.to_string(), replacement.to_vec());
        Ok(true)
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut found: Vec<String> = self
            .blobs
            .borrow()
            .keys()
            .filter(|path| path.starts_with(prefix))
            .cloned()
            .collect();
        found.sort();
        Ok(found)
    }
}

impl BlobStore for MemoryStore {
    fn delete(&self, path: &str) -> Result<(), StoreError> {
        self.blobs.borrow_mut().remove(path);
        Ok(())
    }
}

/// The fallback that answers a call the store trait cannot answer.
///
/// The forbidden names are declared on a blanket impl whose methods take
/// `&mut self`. That places them one step below the `&self` methods of the
/// store trait in the method-resolution order: an autoref beats an
/// autoref-mut. So when the store trait *does* expose a name, its own
/// method is found first and the fallback never answers.
mod fallback {
    use std::cell::Cell;

    // The store trait has to be in scope here, or the probe would find only
    // the fallback and could never tell the two apart.
    use ksp_backend::store::BlobStore;

    thread_local! {
        /// Set when a fallback method was the one that answered the call.
        static ANSWERED: Cell<bool> = const { Cell::new(false) };
    }

    /// Forget the last answer.
    pub fn reset() {
        ANSWERED.with(|flag| flag.set(false));
    }

    /// Report whether a fallback method answered the last call.
    pub fn answered() -> bool {
        ANSWERED.with(Cell::get)
    }

    /// Record that a fallback method answered the call.
    fn mark() {
        ANSWERED.with(|flag| flag.set(true));
    }

    /// Declare the forbidden operation names once.
    ///
    /// The expansion provides the fallback trait, the list of names, and
    /// the probe, so the three can never drift apart: a name that is
    /// probed is a name that is listed, and a name that is listed is a name
    /// that is probed.
    macro_rules! forbidden_methods {
        ($($name:ident),* $(,)?) => {
            /// The forbidden operation names.
            pub const FORBIDDEN: &[&str] = &[$(stringify!($name)),*];

            /// A trait that declares every forbidden name on every type.
            pub trait Forbidden {
                $(fn $name(&mut self, path: &str, key: &[u8]) -> u8;)*
            }

            impl<T> Forbidden for T {
                $(
                    fn $name(&mut self, _path: &str, _key: &[u8]) -> u8 {
                        mark();
                        0
                    }
                )*
            }

            /// The control operation: a name the store trait *does* expose.
            ///
            /// The probe must reach the store trait's own method rather
            /// than this fallback, which is what makes the probe meaningful.
            pub trait Control {
                fn delete(&mut self, path: &str) -> u8;
            }

            impl<T> Control for T {
                fn delete(&mut self, _path: &str) -> u8 {
                    mark();
                    0
                }
            }

            /// Ask the compiler whether the store trait has each forbidden
            /// operation.
            pub fn probe(mut store: crate::MemoryStore) {
                $(
                    reset();
                    let _answer = store.$name("probe/path", b"probe-key-material");
                    assert!(
                        answered(),
                        "the blob store trait must not expose a `{}` operation",
                        stringify!($name)
                    );
                )*
            }

            /// The control run of the probe.
            ///
            /// The `mut` is needed only when the store trait lacks the
            /// control name and the fallback has to answer instead, which is
            /// exactly the case this control exists to detect.
            #[allow(unused_mut)]
            pub fn probe_control(mut store: crate::MemoryStore) {
                // The fallback is reachable when it is called explicitly,
                // so the assertion below is about which of the two wins a
                // method-syntax call, not about the fallback being dead
                // code.
                reset();
                let _ = Control::delete(&mut store, "probe/path");
                assert!(
                    answered(),
                    "the control fallback must be reachable at all"
                );

                // The same name, resolved by method syntax. The store
                // trait's own method is found first, so the fallback must
                // not answer.
                reset();
                let _answer = store.delete("probe/path");
                assert!(
                    !answered(),
                    "the probe must reach the store trait's own method, not the fallback"
                );
            }
        };
    }

    forbidden_methods!(
        decrypt,
        decrypt_blob,
        decrypt_bytes,
        decrypt_path,
        decrypt_with_key,
        derive,
        derive_key,
        encrypt,
        encrypt_blob,
        get_key,
        get_plaintext,
        get_secret,
        key,
        keys,
        new_key,
        open,
        open_secret,
        plaintext,
        put_key,
        put_plaintext,
        put_secret,
        seal,
        seal_blob,
        seal_key,
        sign,
        sign_blob,
        unwrap,
        unwrap_key,
        unwrap_secret,
    );
}

/// Remove comments and string literals, so that a scan sees code only.
///
/// A doc comment that mentions a forbidden word is not an operation; a
/// parameter that is named `key` is.
fn strip_comments_and_strings(source: &str) -> String {
    let characters: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut index = 0;
    while index < characters.len() {
        let current = characters[index];
        let next = characters.get(index + 1).copied();
        if current == '/' && next == Some('/') {
            while index < characters.len() && characters[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if current == '/' && next == Some('*') {
            index += 2;
            while index + 1 < characters.len()
                && !(characters[index] == '*' && characters[index + 1] == '/')
            {
                index += 1;
            }
            index = (index + 2).min(characters.len());
            out.push(' ');
            continue;
        }
        if current == '"' {
            index += 1;
            while index < characters.len() && characters[index] != '"' {
                if characters[index] == '\\' {
                    index += 1;
                }
                index += 1;
            }
            index = (index + 1).min(characters.len());
            out.push('"');
            continue;
        }
        out.push(current);
        index += 1;
    }
    out
}

/// The body of the `pub trait BlobStore` declaration, without comments.
fn trait_block(source: &str) -> String {
    let code = strip_comments_and_strings(source);
    let start = code
        .find("pub trait BlobStore")
        .expect("the blob store trait is declared");
    let open = code[start..]
        .find('{')
        .expect("the blob store trait has a body")
        + start;
    let mut depth = 0usize;
    let mut end = open;
    for (offset, character) in code[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + offset;
                    break;
                }
            }
            _ => {}
        }
    }
    code[open..=end].to_string()
}

/// The names of the operations a trait block declares.
fn method_names(block: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = block;
    while let Some(at) = rest.find("fn ") {
        let after = &rest[at + 3..];
        let name: String = after
            .chars()
            .take_while(|character| character.is_alphanumeric() || *character == '_')
            .collect();
        if !name.is_empty() {
            names.push(name);
        }
        rest = &rest[at + 3..];
    }
    names
}

/// The identifiers a trait block mentions.
fn identifiers(block: &str) -> Vec<String> {
    block
        .split(|character: char| !(character.is_alphanumeric() || character == '_'))
        .filter(|word| !word.is_empty())
        .map(|word| word.to_lowercase())
        .collect()
}

#[test]
fn the_store_trait_declares_exactly_the_opaque_operations() {
    let backend = trait_block(BACKEND_TRAIT_SOURCE);
    let record = trait_block(RECORD_TRAIT_SOURCE);

    let mut declared: Vec<String> = method_names(&backend)
        .into_iter()
        .chain(method_names(&record))
        .collect();
    declared.sort();
    declared.dedup();

    let mut expected: Vec<String> = EXPECTED_METHODS
        .iter()
        .map(|name| name.to_string())
        .collect();
    expected.sort();

    assert_eq!(
        declared, expected,
        "the blob store trait must expose only opaque byte operations"
    );

    // The backend trait adds removal and nothing else; the record trait
    // carries the rest. An operation that arrives on either side changes
    // one of these two sets.
    assert_eq!(
        method_names(&backend),
        vec!["delete".to_string()],
        "the backend trait must add removal and no other operation"
    );
    assert_eq!(
        method_names(&record),
        vec![
            "get".to_string(),
            "put_if_absent".to_string(),
            "compare_and_set".to_string(),
            "list".to_string(),
        ],
        "the record-level trait must expose only the opaque byte operations"
    );
}

#[test]
fn the_store_trait_names_no_key_taking_or_plaintext_operation() {
    for source in [BACKEND_TRAIT_SOURCE, RECORD_TRAIT_SOURCE] {
        let block = trait_block(source);
        for name in method_names(&block) {
            let lowered = name.to_lowercase();
            for word in FORBIDDEN_WORDS {
                assert!(
                    !lowered.contains(*word),
                    "the blob store trait must not expose an operation named `{name}`"
                );
            }
        }
        // A parameter, a type or a return that mentions key material is as
        // much a breach as an operation named after it.
        for word in identifiers(&block) {
            for forbidden in FORBIDDEN_WORDS {
                assert!(
                    !word.contains(*forbidden),
                    "the blob store trait must not mention `{word}`"
                );
            }
        }
    }
}

#[test]
fn the_probe_reaches_the_store_trait_and_not_the_fallback() {
    // The control proves the probe is live: `delete` is on the store trait,
    // so the store trait's own method must answer the call even though a
    // fallback of the same name exists.
    fallback::probe_control(MemoryStore::default());
}

#[test]
fn the_store_trait_exposes_none_of_the_forbidden_operations() {
    fallback::probe(MemoryStore::default());
}

#[test]
fn every_forbidden_name_is_covered_by_the_word_scan() {
    let mut names: Vec<&str> = fallback::FORBIDDEN.to_vec();
    names.sort();
    names.dedup();
    assert_eq!(
        names.len(),
        fallback::FORBIDDEN.len(),
        "the forbidden name list must stay free of duplicates"
    );

    // Every name the probe calls is caught by the word scan as well, so the
    // reflection layer is never weaker than the probe.
    for name in fallback::FORBIDDEN {
        let lowered = name.to_lowercase();
        assert!(
            FORBIDDEN_WORDS.iter().any(|word| lowered.contains(*word)),
            "the forbidden name `{name}` is not covered by the word scan"
        );
    }
}

#[test]
fn the_store_sees_only_opaque_bytes() {
    let store = MemoryStore::default();

    // Bytes that are not valid UTF-8, so a lossy conversion anywhere in the
    // stack cannot make the assertion pass by accident.
    let payload: Vec<u8> = vec![0x00, 0xff, 0x10, 0x80, 0x7f, 0x00];

    assert!(
        store.put_if_absent("p/blob", &payload).unwrap(),
        "the first write of an absent path must succeed"
    );
    assert_eq!(
        store.get("p/blob").unwrap(),
        Some(payload.clone()),
        "the bytes must read back exactly"
    );

    assert!(
        !store.put_if_absent("p/blob", b"other").unwrap(),
        "a second write must be refused"
    );
    assert_eq!(
        store.get("p/blob").unwrap(),
        Some(payload.clone()),
        "the refused write must leave the bytes unchanged"
    );

    assert!(
        store
            .compare_and_set("p/blob", Some(&payload), b"replacement")
            .unwrap(),
        "a conditional replace against the current bytes must succeed"
    );
    assert_eq!(
        store.get("p/blob").unwrap(),
        Some(b"replacement".to_vec()),
        "the replaced bytes must be the replacement"
    );

    store.put_if_absent("q/other", b"elsewhere").unwrap();
    assert_eq!(
        store.list("p/").unwrap(),
        vec!["p/blob".to_string()],
        "a listing must be confined to the requested prefix"
    );

    store.delete("p/blob").unwrap();
    assert_eq!(
        store.get("p/blob").unwrap(),
        None,
        "a delete must remove exactly the named path"
    );
    assert_eq!(
        store.list("").unwrap(),
        vec!["q/other".to_string()],
        "a delete must leave every other path alone"
    );

    // The store holds bytes and path strings. Nothing else — no key, no
    // passphrase, no plaintext secret.
    assert_eq!(
        store.snapshot(),
        vec![("q/other".to_string(), b"elsewhere".to_vec())],
        "the store must hold nothing but opaque bytes"
    );
}
