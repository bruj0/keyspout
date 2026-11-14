//! The acceptance criteria for WP08, driven through the public API.
//!
//! The property under test is an *order*, and orders are easy to test badly:
//! a test that only exercises the failure first passes whether or not the
//! success path respects the order. So the publication here is a closure that
//! records what it was given (and, for criterion 5, inspects the store at the
//! moment it runs), and the store records every write. "No token byte" is then
//! an assertion about an empty vector, not about a returned error.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
//! The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use ksp_backend::admission::{Classification, admit_at_gate};
use ksp_backend::arming::{ArmError, ArmingStore, Durability};
use ksp_identity::{
    AdminSigningKey, EnrolmentFingerprint, FingerprintSubject, KeyId, MintBinding, MintRefusal,
    MintRequest, Policy, PolicyBody, PolicyRequest, PolicyVerifier, RecipientPublicKey,
    SigningSecretKey, TrustAnchors, TrustedEnrolmentKeys, VerifyingPublicKey, mint,
};
use ksp_types::evidence::DeletionIntent;
use ksp_types::{ActorId, Level, OpaqueSecretId, RecordVersion};

/// The two keys a lease involves: the admin's signs the policy, the user's signs
/// the lease. One key for both is the single-account deployment the tests used to
/// model, and it hid the fact that a mint never needs the admin's half.
struct Issuer {
    admin: AdminSigningKey,
    user: SigningSecretKey,
}

impl Issuer {
    fn new() -> Self {
        Self {
            admin: AdminSigningKey::generate(),
            user: SigningSecretKey::generate(),
        }
    }
}

const ADMIN_ID: &str = "admin-1";
const NOT_BEFORE: u64 = 1_000;
const NOT_AFTER: u64 = 2_000;
const DURING: u64 = 1_500;
const MAX_TTL: u64 = 3_600;

fn vault() -> ksp_types::VaultId {
    ksp_types::VaultId::new("vault-1")
}

fn user() -> ksp_types::PrincipalId {
    ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap()
}

fn agent_level() -> Level {
    Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap())
}

/// The enrolment the policy is written against, generated once per process.
///
/// A fixture that generated fresh keys per call would make the confirmed
/// fingerprint differ from the recomputed one for a reason unrelated to the
/// code under test.
fn trusted_keys() -> TrustedEnrolmentKeys {
    static SIGNING: std::sync::OnceLock<VerifyingPublicKey> = std::sync::OnceLock::new();
    TrustedEnrolmentKeys {
        signing_key: *SIGNING.get_or_init(|| SigningSecretKey::generate().verifying_public()),
        recipient_key: RecipientPublicKey::from_bytes([21u8; 32]),
        signing_key_id: KeyId::new("alice-ed25519-1"),
        recipient_key_id: KeyId::new("alice-x25519-1"),
    }
}

fn subject() -> FingerprintSubject {
    let keys = trusted_keys();
    FingerprintSubject {
        identity: ActorId::User(user()),
        signing_key: keys.signing_key.to_bytes(),
        recipient_key: keys.recipient_key.to_bytes(),
        signing_key_id: keys.signing_key_id.clone(),
        recipient_key_id: keys.recipient_key_id.clone(),
    }
}

fn confirmed_fingerprint() -> EnrolmentFingerprint {
    EnrolmentFingerprint::compute(&subject()).unwrap()
}

fn binding() -> MintBinding {
    let keys = trusted_keys();
    MintBinding {
        identity: ActorId::User(user()),
        signing_key: keys.signing_key,
        recipient_key: keys.recipient_key,
        signing_key_id: keys.signing_key_id.clone(),
        recipient_key_id: keys.recipient_key_id.clone(),
        confirmed_fingerprint: confirmed_fingerprint(),
    }
}

fn policy_request() -> PolicyRequest {
    PolicyRequest {
        vault: vault(),
        user: user(),
        source: Level::User,
        target: agent_level(),
        secret: OpaqueSecretId::new("secret-1"),
        agent: ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
        path: "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000007/secret-1/1".to_string(),
        scope: agent_level().path_segment(),
        requested_ttl_secs: 300,
        record_version: RecordVersion(1),
    }
}

fn policy_body() -> PolicyBody {
    PolicyBody::new(
        5,
        vault(),
        user(),
        trusted_keys(),
        vec![OpaqueSecretId::new("secret-1")],
        vec![ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()],
        MAX_TTL,
        MAX_TTL,
        NOT_BEFORE,
        NOT_AFTER,
    )
}

fn policy(admin: &AdminSigningKey) -> Policy {
    Policy::new(admin, KeyId::new(ADMIN_ID), policy_body()).unwrap()
}

fn verifier(admin: &AdminSigningKey) -> PolicyVerifier {
    let mut anchors = TrustAnchors::new();
    anchors.pin(KeyId::new(ADMIN_ID), admin.verifying_public());
    PolicyVerifier::new(anchors, None)
}

/// The deleters the user authorised for this version.
fn deleters() -> Vec<ActorId> {
    vec![
        ActorId::User(user()),
        ActorId::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()),
        ActorId::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000008").unwrap()),
    ]
}

fn intent() -> DeletionIntent {
    DeletionIntent {
        intent_id: "intent-1".to_string(),
        vault_id: vault(),
        user_id: user(),
        level: agent_level(),
        secret_id: OpaqueSecretId::new("secret-1"),
        version: 1,
        deadline: 9_999,
        authorized_deleters: deleters(),
    }
}

fn request() -> MintRequest {
    MintRequest {
        binding: binding(),
        policy_request: policy_request(),
        intended_recipient: trusted_keys().recipient_key,
        intent: intent(),
        operation_identity: "op-1".to_string(),
        remaining_uses: None,
    }
}

/// The ledger row a mint would record for [`request`].
///
/// Derived from the request so the row names the same agent, secret and version
/// the sequence validates, which is what a caller must do as well.
fn issuance() -> ksp_identity::issuance::Issuance {
    let request = policy_request();
    ksp_identity::issuance::Issuance {
        token_id: "op-1".to_string(),
        agent: request.agent,
        secret: request.secret,
        version: request.record_version,
        deadline: i64::try_from(DURING).unwrap_or(i64::MAX) + 48 * 3_600,
        policy_revision: 1,
    }
}

/// A backend with a declared 24h sweep, which is what sets the 48h floor.
fn scheduled_24h() -> Classification {
    Classification {
        capability: ksp_types::LeaseCapability::Scheduled {
            interval: Duration::from_secs(24 * 3_600),
        },
        mechanism: "temporary key with a declared sweep cadence",
        declared_cadence: Some(Duration::from_secs(24 * 3_600)),
        proven_cadence: Some(Duration::from_secs(24 * 3_600)),
        proof_age: Some(0),
        cleanup_lag: None,
        retention: None,
        state: None,
    }
}

fn no_mechanism() -> Classification {
    Classification {
        capability: ksp_types::LeaseCapability::None,
        mechanism: "no configured cleanup",
        declared_cadence: None,
        proven_cadence: None,
        proof_age: None,
        cleanup_lag: None,
        retention: None,
        state: None,
    }
}

/// A store that records writes by operation identity, so a duplicate is visible
/// as a second key rather than a second write to the same one.
#[derive(Default)]
struct FakeStore {
    records: RefCell<BTreeMap<String, Vec<u8>>>,
    /// Number of `arm_once` calls, including retries that did not add a record.
    attempts: RefCell<usize>,
    /// Drop the next `read_arm` result, simulating a lost acknowledgement.
    lose_ack: RefCell<bool>,
    /// Fail the next `arm_once` before writing anything.
    fail_arm: RefCell<bool>,
}

impl FakeStore {
    fn record_count(&self) -> usize {
        self.records.borrow().len()
    }

    fn attempts(&self) -> usize {
        *self.attempts.borrow()
    }

    fn contains(&self, identity: &str) -> bool {
        self.records.borrow().contains_key(identity)
    }
}

impl ArmingStore for FakeStore {
    fn arm_once(
        &self,
        identity: &str,
        bytes: &[u8],
        _deadline: i64,
    ) -> Result<Durability, ArmError> {
        *self.attempts.borrow_mut() += 1;
        if *self.fail_arm.borrow() {
            *self.fail_arm.borrow_mut() = false;
            return Err(ArmError::Uncertain);
        }
        self.records
            .borrow_mut()
            .insert(identity.to_string(), bytes.to_vec());
        Ok(Durability::LocalSync)
    }

    fn read_arm(&self, identity: &str) -> Result<Option<Vec<u8>>, ArmError> {
        let stored = self.records.borrow().get(identity).cloned();
        // A lost acknowledgement is a lost *read-back of a write*, not a read of
        // an empty store: latching on the first read would model a store that
        // never wrote anything, which is a different failure.
        if *self.lose_ack.borrow() && stored.is_some() {
            *self.lose_ack.borrow_mut() = false;
            return Ok(None);
        }
        Ok(stored)
    }
}

fn run(
    store: &Rc<FakeStore>,
    issuer: &Issuer,
    classification: &Classification,
    hours: u64,
    request: MintRequest,
    published: &Rc<RefCell<Vec<u8>>>,
) -> Result<ksp_identity::MintOutcome<Result<Vec<u8>, std::convert::Infallible>>, MintRefusal> {
    let policy = policy(&issuer.admin);
    let verifier = verifier(&issuer.admin);
    let sink = Rc::clone(published);
    // These tests are about the order of the arm and the publication, so the
    // ledger only has to exist and be writable.
    let ledger_home = tempfile::TempDir::new().expect("a temporary ledger home");
    let ledger = ksp_identity::IssuanceLedger::at(ledger_home.path().join("issuance.jsonl"));
    mint(
        &**store,
        &ledger,
        &issuer.user,
        &verifier,
        &policy,
        classification,
        // The helper reads in hours; the API takes seconds.
        hours * 3_600,
        DURING,
        request,
        issuance(),
        move |authority| {
            let bytes = format!("token-for-{}", authority.acknowledgement().intent_id).into_bytes();
            sink.borrow_mut().extend_from_slice(&bytes);
            Ok::<Vec<u8>, std::convert::Infallible>(bytes)
        },
    )
}

// ---------------------------------------------------------------------------
// Criterion 1 — no token byte before the durable arm
// ---------------------------------------------------------------------------

#[test]
fn a_mint_refused_before_the_arm_publishes_no_token_byte() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    // A `None` backend refuses at the admission gate, which is upstream of the arm.
    let refusal = run(&store, &admin, &no_mechanism(), 24, request(), &published).unwrap_err();

    assert_eq!(refusal.exit_code(), 7);
    assert!(
        published.borrow().is_empty(),
        "a refusal upstream of the arm must not publish a byte"
    );
    assert_eq!(store.attempts(), 0, "no arming attempt may be made");
}

// ---------------------------------------------------------------------------
// Criterion 2 — a failed arm publishes nothing and leaves no record
// ---------------------------------------------------------------------------

#[test]
fn an_arming_failure_publishes_no_token_and_leaves_no_arm_record() {
    let store = Rc::new(FakeStore::default());
    *store.fail_arm.borrow_mut() = true;
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    let refusal = run(&store, &admin, &scheduled_24h(), 48, request(), &published).unwrap_err();

    assert!(matches!(refusal, MintRefusal::Uncertain(_)));
    assert_eq!(refusal.exit_code(), 7);
    assert!(published.borrow().is_empty());
    assert_eq!(store.record_count(), 0);
}

// ---------------------------------------------------------------------------
// Criteria 3, 4 — a lost acknowledgement reconciles, and publishes nothing
// until it does
// ---------------------------------------------------------------------------

#[test]
fn a_lost_acknowledgement_publishes_nothing_until_the_reconciliation_succeeds() {
    let store = Rc::new(FakeStore::default());
    *store.lose_ack.borrow_mut() = true;
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    let refusal = run(&store, &admin, &scheduled_24h(), 48, request(), &published).unwrap_err();
    assert!(matches!(refusal, MintRefusal::Uncertain(_)));
    assert!(
        published.borrow().is_empty(),
        "an uncertain arm must not publish while the acknowledgement is missing"
    );

    // Retrying under the same operation identity reconciles against the record
    // the first attempt wrote.
    run(&store, &admin, &scheduled_24h(), 48, request(), &published).unwrap();
    assert!(!published.borrow().is_empty());
}

#[test]
fn reconciling_a_lost_acknowledgement_does_not_duplicate_the_arm_record() {
    let store = Rc::new(FakeStore::default());
    *store.lose_ack.borrow_mut() = true;
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    let _ = run(&store, &admin, &scheduled_24h(), 48, request(), &published);
    run(&store, &admin, &scheduled_24h(), 48, request(), &published).unwrap();

    assert_eq!(
        store.record_count(),
        1,
        "the retry must reconcile the existing record, not add a second one"
    );
    assert_eq!(
        store.attempts(),
        2,
        "the retry does re-arm under the same key"
    );
}

// ---------------------------------------------------------------------------
// Criterion 5 — after the arm, before the token, the record exists
// ---------------------------------------------------------------------------

#[test]
fn the_arm_record_exists_at_the_moment_publication_runs() {
    let store = Rc::new(FakeStore::default());
    let issuer = Issuer::new();
    let observed = Rc::new(RefCell::new(None));
    let policy = policy(&issuer.admin);
    let verifier = verifier(&issuer.admin);

    let probe = Rc::clone(&store);
    let flag = Rc::clone(&observed);
    let ledger_home = tempfile::TempDir::new().expect("a temporary ledger home");
    let ledger = ksp_identity::IssuanceLedger::at(ledger_home.path().join("issuance.jsonl"));
    let outcome = mint(
        &*store,
        &ledger,
        &issuer.user,
        &verifier,
        &policy,
        &scheduled_24h(),
        48 * 3_600,
        DURING,
        request(),
        issuance(),
        move |_authority| {
            let present = probe.contains("op-1");
            let count = probe.record_count();
            *flag.borrow_mut() = Some((present, count));
            Ok::<Vec<u8>, std::convert::Infallible>(Vec::new())
        },
    )
    .unwrap();

    assert_eq!(
        observed.borrow().as_ref().copied(),
        Some((true, 1)),
        "the cleanup must be able to proceed from an existing record"
    );
    assert_eq!(outcome.acknowledgement.operation_identity, "op-1");
}

// ---------------------------------------------------------------------------
// Criterion 6 — a fingerprint that does not bind all four items refuses before
// the arm
// ---------------------------------------------------------------------------

#[test]
fn a_substituted_recipient_key_is_refused_before_any_arm_record_is_written() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    // The fingerprint is genuine and the key IDs are untouched: only the key
    // that will receive the secret is swapped.
    let mut request = request();
    request.binding.recipient_key = RecipientPublicKey::from_bytes([99u8; 32]);
    request.intended_recipient = RecipientPublicKey::from_bytes([99u8; 32]);

    let refusal = run(&store, &admin, &scheduled_24h(), 48, request, &published).unwrap_err();

    assert_eq!(refusal.exit_code(), 2);
    assert!(matches!(refusal, MintRefusal::FingerprintMismatch));
    assert_eq!(store.attempts(), 0, "refusal must precede any arming write");
    assert_eq!(store.record_count(), 0);
    assert!(published.borrow().is_empty());
}

#[test]
fn sealing_to_a_key_the_fingerprint_does_not_bind_is_refused() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    // The binding is intact — the fingerprint verifies — but the seal would go
    // to a different recipient. A fingerprint check alone would let this pass.
    let mut request = request();
    request.intended_recipient = RecipientPublicKey::from_bytes([77u8; 32]);

    let refusal = run(&store, &admin, &scheduled_24h(), 48, request, &published).unwrap_err();

    assert!(matches!(refusal, MintRefusal::RecipientKeyMismatch));
    assert_eq!(refusal.exit_code(), 2);
    assert_eq!(store.record_count(), 0);
    assert!(published.borrow().is_empty());
}

#[test]
fn a_substituted_signing_key_id_is_refused_before_any_arm_record_is_written() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    let mut request = request();
    request.binding.signing_key_id = KeyId::new("MallorysKey");

    let refusal = run(&store, &admin, &scheduled_24h(), 48, request, &published).unwrap_err();

    assert!(matches!(refusal, MintRefusal::FingerprintMismatch));
    assert_eq!(store.record_count(), 0);
}

// ---------------------------------------------------------------------------
// Criteria 7, 8, 9 — the duration gate
// ---------------------------------------------------------------------------

#[test]
fn a_none_capability_refuses_with_exit_7() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    let refusal = run(&store, &admin, &no_mechanism(), 24, request(), &published).unwrap_err();

    assert_eq!(refusal.exit_code(), 7);
    assert_eq!(store.attempts(), 0);
}

#[test]
fn a_47h_lease_on_a_24h_sweep_refuses_naming_the_cadence_and_the_minimum() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    let refusal = run(&store, &admin, &scheduled_24h(), 47, request(), &published).unwrap_err();

    assert_eq!(refusal.exit_code(), 7);
    let message = refusal.to_string();
    assert!(message.contains("169200s"), "names the request: {message}");
    assert!(message.contains("86400s"), "names the cadence: {message}");
    assert!(message.contains("172800s"), "names the minimum: {message}");
    assert_eq!(store.attempts(), 0);
}

#[test]
fn a_48h_lease_passes_the_duration_gate_but_still_needs_the_policy_gate() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    // 48h is exactly the floor, so admission admits it.
    assert!(admit_at_gate(&scheduled_24h(), Duration::from_secs(48 * 3_600)).is_ok());

    // And a policy refusal still stops the mint: the duration gate is not the
    // only gate, and passing it authorises nothing on its own.
    let mut request = request();
    request.policy_request.requested_ttl_secs = MAX_TTL + 1;
    let refusal = run(&store, &admin, &scheduled_24h(), 48, request, &published).unwrap_err();

    assert_eq!(refusal.exit_code(), 2);
    assert!(matches!(refusal, MintRefusal::Policy { .. }));
    assert_eq!(store.attempts(), 0);
    assert!(published.borrow().is_empty());
}

// ---------------------------------------------------------------------------
// Criterion 10 — a policy failure refuses with exit 2 and publishes nothing
// ---------------------------------------------------------------------------

#[test]
fn a_policy_failure_refuses_with_exit_2_and_publishes_no_token() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    let mut request = request();
    request.policy_request.secret = OpaqueSecretId::new("not-in-the-policy");

    let refusal = run(&store, &admin, &scheduled_24h(), 48, request, &published).unwrap_err();

    assert_eq!(refusal.exit_code(), 2);
    assert!(published.borrow().is_empty());
    assert_eq!(
        store.record_count(),
        0,
        "no cleanup record for a refused mint"
    );
}

// ---------------------------------------------------------------------------
// Criteria 11, 12 — the intent is key-free and names the right actors
// ---------------------------------------------------------------------------

#[test]
fn the_serialized_intent_contains_no_key_material() {
    let bytes = ksp_types::cbor::encode(&intent()).unwrap();
    let keys = trusted_keys();

    for (label, key) in [
        ("signing key", keys.signing_key.to_bytes()),
        ("recipient key", keys.recipient_key.to_bytes()),
    ] {
        assert!(
            !bytes.windows(key.len()).any(|window| window == key),
            "the intent must not carry the {label}"
        );
    }

    // And nothing else 32 bytes wide that looks like a key: the intent's own
    // fields are an id, a version, a deadline and the actor list.
    let round_tripped: DeletionIntent = ksp_types::cbor::decode(&bytes).unwrap();
    assert_eq!(round_tripped, intent());
}

#[test]
fn the_intent_authorizes_exactly_the_deleters_the_user_permitted() {
    let intent = intent();
    assert_eq!(intent.authorized_deleters, deleters());
    assert!(intent.authorized_deleters.contains(&ActorId::User(user())));
    assert!(!intent.authorized_deleters.contains(&ActorId::User(
        ksp_types::PrincipalId::parse("bad00000-0000-4000-8000-000000000003").unwrap()
    )));
}

// ---------------------------------------------------------------------------
// Criterion 13 — a deletion-intent signature is not a token signature
// ---------------------------------------------------------------------------

#[test]
fn a_deletion_intent_signature_is_not_accepted_as_a_token_signature() {
    let user = SigningSecretKey::generate();
    let record = ksp_identity::sign_arm_record(&user, intent(), "op-1", None).unwrap();

    // The same body, under the token domain. The intent domain prefix is what
    // makes the two signatures non-interchangeable; without it this would
    // verify and the two artifacts would share a signature.
    //
    // The body is rebuilt from the record's own fields rather than from fresh
    // literals: a hand-written preimage that differs from the signer's would
    // make this test pass for the wrong reason.
    let body = ksp_types::cbor::encode(&(
        record.operation_identity.as_str(),
        &record.intent,
        record.signer_key_id.as_str(),
        record.remaining_uses,
    ))
    .unwrap();
    let mut as_token = Vec::from(ksp_types::domains::DOMAIN_TOKEN);
    as_token.extend_from_slice(&body);

    assert!(
        !user
            .verifying_public()
            .verify(&as_token, &record.signature.clone().try_into().unwrap()),
        "an intent signature must not verify as a token signature"
    );

    let mut as_intent = Vec::from(ksp_types::domains::DOMAIN_DELETE_INTENT);
    as_intent.extend_from_slice(&body);
    assert!(
        user.verifying_public()
            .verify(&as_intent, &record.signature.clone().try_into().unwrap()),
        "the same bytes must verify under their own domain"
    );
}

#[test]
fn the_arm_record_names_the_key_that_signed_it() {
    let user = SigningSecretKey::generate();
    let other = SigningSecretKey::generate();

    let record = ksp_identity::sign_arm_record(&user, intent(), "op-1", None).unwrap();
    let expected: String = user
        .verifying_public()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    assert_eq!(
        record.signer_key_id, expected,
        "the arm must name the key a later verifier has to check it against"
    );
    assert_ne!(
        ksp_identity::sign_arm_record(&other, intent(), "op-1", None)
            .unwrap()
            .signer_key_id,
        record.signer_key_id,
        "two signers must not share an identifier"
    );
}

// ---------------------------------------------------------------------------
// Criterion 14 — two mints, one arm record
// ---------------------------------------------------------------------------

#[test]
fn two_mints_with_the_same_operation_identity_produce_one_arm_record() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    run(&store, &admin, &scheduled_24h(), 48, request(), &published).unwrap();
    run(&store, &admin, &scheduled_24h(), 48, request(), &published).unwrap();

    assert_eq!(store.record_count(), 1);
    assert_eq!(store.attempts(), 2);
}

// ---------------------------------------------------------------------------
// The refusal codes are distinct where it matters
// ---------------------------------------------------------------------------

#[test]
fn an_empty_operation_identity_is_a_caller_error_not_a_storage_failure() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    let mut request = request();
    request.operation_identity = String::new();

    let refusal = run(&store, &admin, &scheduled_24h(), 48, request, &published).unwrap_err();

    assert_eq!(
        refusal.exit_code(),
        2,
        "an unusable identity is the caller's mistake, not the backend's"
    );
    assert!(published.borrow().is_empty());
}

#[test]
fn authorisation_and_storage_refusals_carry_distinct_exit_codes() {
    assert_eq!(MintRefusal::FingerprintMismatch.exit_code(), 2);
    assert_eq!(MintRefusal::RecipientKeyMismatch.exit_code(), 2);
    assert_eq!(
        MintRefusal::Policy {
            reason: String::new()
        }
        .exit_code(),
        2
    );
    assert_eq!(
        MintRefusal::Inadmissible {
            reason: String::new()
        }
        .exit_code(),
        7
    );
    assert_eq!(ksp_identity::EXIT_REFUSED, 2);
    assert_eq!(ksp_identity::EXIT_INADMISSIBLE, 7);
}

// ---------------------------------------------------------------------------
// An operation identity is an idempotency key, not a label
// ---------------------------------------------------------------------------

#[test]
fn reusing_an_operation_identity_for_a_different_intent_is_refused() {
    let store = Rc::new(FakeStore::default());
    let admin = Issuer::new();
    let published = Rc::new(RefCell::new(Vec::new()));

    run(&store, &admin, &scheduled_24h(), 48, request(), &published).unwrap();
    let first_record = store.records.borrow().get("op-1").cloned().unwrap();
    let first_token_len = published.borrow().len();

    // Same identity, different lease: another version, another deadline.
    let mut second = request();
    second.intent.version = 9;
    second.intent.deadline = 123_456;
    let refusal = run(&store, &admin, &scheduled_24h(), 48, second, &published).unwrap_err();

    assert!(
        matches!(refusal, MintRefusal::IdentityConflict { .. }),
        "got {refusal:?}"
    );
    assert_eq!(refusal.exit_code(), 2);
    assert_eq!(
        store.records.borrow().get("op-1").cloned().unwrap(),
        first_record,
        "the first lease must keep the record that names it"
    );
    assert_eq!(
        published.borrow().len(),
        first_token_len,
        "the refused mint must publish nothing"
    );
}
