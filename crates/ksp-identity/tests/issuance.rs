//! The acceptance criteria for WP20, driven through the public API.
//!
//! Two misfits meet here. Misfit R is a foreground process that leaves no
//! durable record of what it minted, so a later invocation cannot say what this
//! host issued; the ledger is that record, and every test that reads it back
//! through a *fresh* `IssuanceLedger` is testing the reload rather than a value
//! still in memory. Misfit H is a trust anchor a client must be able to see
//! change: a withdrawn grant and a marked token are only useful if a client can
//! read them without re-verifying a whole policy.
//!
//! The honest half is tested as hard as the useful half. Revocation is trust
//! state, so the test that a pre-revocation artifact **still opens with the
//! agent's own key** is here beside the test that a revoked identifier is
//! refused — otherwise "revoked" would be a claim the code cannot keep.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
//! The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ksp_backend::admission::Classification;
use ksp_backend::arming::{ArmError, ArmingStore, Durability};
use ksp_identity::issuance::{
    IssuanceLedger, LedgerError, LedgerState, PublishError, RevocationReason, TokenStanding,
    Withdrawal, admin_revoke, ledger_scope,
};
use ksp_identity::{
    AdminSigningKey, DeliveryArtifact, EnrollmentRecord, EnrolmentFingerprint, FingerprintSubject,
    KeyId, MintBinding, MintRequest, Policy, PolicyBody, PolicyRefusal, PolicyRequest,
    RecipientPublicKey, SelectedContentKeys, SelectedRecord, SigningSecretKey, TrustAnchors,
    TrustedEnrolmentKeys, UnsignedEnrolment, VerifiedRecipientKey, VerifyingPublicKey, mint, open,
    seal, verify,
};
use ksp_types::evidence::DeletionIntent;
use ksp_types::{ActorId, AgentId, ContentKey, Level, OpaqueSecretId, RecordVersion, VaultId};
use tempfile::TempDir;

const ADMIN_ID: &str = "admin-1";
const NOT_BEFORE: u64 = 1_000;
const NOT_AFTER: u64 = 2_000;
const DURING: u64 = 1_500;
const MAX_TTL: u64 = 86_400;

// ---------------------------------------------------------------------------
// Fixtures — shared shapes, one instance per process where a key is generated
// ---------------------------------------------------------------------------

fn vault() -> VaultId {
    VaultId::new("vault-1")
}

fn user() -> ksp_types::PrincipalId {
    ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap()
}

fn agent() -> AgentId {
    ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()
}

fn agent_level() -> Level {
    Level::Agent(agent())
}

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

fn binding() -> MintBinding {
    let keys = trusted_keys();
    MintBinding {
        identity: ActorId::User(user()),
        signing_key: keys.signing_key,
        recipient_key: keys.recipient_key,
        signing_key_id: keys.signing_key_id.clone(),
        recipient_key_id: keys.recipient_key_id.clone(),
        confirmed_fingerprint: EnrolmentFingerprint::compute(&subject()).unwrap(),
    }
}

fn policy_request() -> PolicyRequest {
    PolicyRequest {
        vault: vault(),
        user: user(),
        source: Level::User,
        target: agent_level(),
        secret: OpaqueSecretId::new("secret-1"),
        agent: agent(),
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
        vec![agent()],
        MAX_TTL,
        MAX_TTL,
        NOT_BEFORE,
        NOT_AFTER,
    )
}

fn policy(admin: &AdminSigningKey) -> Policy {
    Policy::new(admin, KeyId::new(ADMIN_ID), policy_body()).unwrap()
}

fn verifier(admin: &AdminSigningKey) -> ksp_identity::PolicyVerifier {
    let mut anchors = TrustAnchors::new();
    anchors.pin(KeyId::new(ADMIN_ID), admin.verifying_public());
    ksp_identity::PolicyVerifier::new(anchors, None)
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
        authorized_deleters: vec![ActorId::User(user())],
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

/// The entry a mint would record for the request above.
fn issuance() -> ksp_identity::issuance::Issuance {
    ksp_identity::issuance::Issuance {
        token_id: "jti-1".to_string(),
        agent: agent(),
        secret: OpaqueSecretId::new("secret-1"),
        version: RecordVersion(1),
        deadline: 9_999,
        policy_revision: 5,
    }
}

fn ledger_in(dir: &TempDir) -> IssuanceLedger {
    IssuanceLedger::at(dir.path().join("issuance.jsonl"))
}

fn record(ledger: &IssuanceLedger) {
    ledger
        .publish_recorded(issuance(), || {
            Ok::<Vec<u8>, std::convert::Infallible>(vec![1])
        })
        .unwrap();
}

/// A store that keeps arm records in memory: the mint needs one, and this WP is
/// not about arming.
#[derive(Default)]
struct FakeStore {
    records: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl ArmingStore for FakeStore {
    fn arm_once(
        &self,
        identity: &str,
        bytes: &[u8],
        _deadline: i64,
    ) -> Result<Durability, ArmError> {
        self.records
            .borrow_mut()
            .insert(identity.to_string(), bytes.to_vec());
        Ok(Durability::LocalSync)
    }

    fn read_arm(&self, identity: &str) -> Result<Option<Vec<u8>>, ArmError> {
        Ok(self.records.borrow().get(identity).cloned())
    }
}

/// One sealed delivery, with the private key the agent needs to open it.
struct Sealed {
    user: SigningSecretKey,
    artifact: DeliveryArtifact,
    agent_secret: [u8; 32],
    keys: Vec<(SelectedRecord, ContentKey)>,
}

fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = [seed; 32];
    let public = ksp_record::kem::public_key_for(&secret).unwrap();
    (secret, public)
}

fn sealed() -> Sealed {
    let admin = AdminSigningKey::generate();
    let signer = SigningSecretKey::generate();
    let (agent_secret, agent_public) = keypair(7);
    let signing = SigningSecretKey::generate().verifying_public();
    let unsigned = UnsignedEnrolment::bind(
        ActorId::Agent(agent()),
        signing,
        RecipientPublicKey::from_bytes(agent_public),
        KeyId::new("agent-7-ed"),
        KeyId::new("agent-7-x"),
    )
    .unwrap();
    let record: EnrollmentRecord = admin
        .sign_enrolment(unsigned, KeyId::new(ADMIN_ID))
        .unwrap();
    let recipient = VerifiedRecipientKey::confirm(&record, record.fingerprint()).unwrap();

    let head = ksp_identity::DeliveryHeader::new(
        vault(),
        user(),
        KeyId::new(ADMIN_ID),
        agent(),
        signing,
        RecipientPublicKey::from_bytes(agent_public),
        KeyId::new("agent-7-ed"),
        KeyId::new("agent-7-x"),
        agent_level(),
        Level::User,
        agent_level().path_segment(),
        vec![SelectedRecord {
            secret: OpaqueSecretId::new("secret-1"),
            version: RecordVersion(1),
        }],
        500,
        "jti-1".to_string(),
    )
    .unwrap();
    let keys: Vec<(SelectedRecord, ContentKey)> = head
        .records()
        .iter()
        .map(|record| (record.clone(), ContentKey::generate()))
        .collect();
    let selection = SelectedContentKeys::new(&head, keys.clone()).unwrap();
    let artifact = seal(&signer, &head, &selection, &recipient).unwrap();

    Sealed {
        user: signer,
        artifact,
        agent_secret,
        keys,
    }
}

// ---------------------------------------------------------------------------
// Criterion 1 — one entry, inside the publish closure, and none without a
// publication
// ---------------------------------------------------------------------------

#[test]
fn a_mint_records_exactly_one_entry() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    let store = FakeStore::default();
    let admin = AdminSigningKey::generate();
    let user = SigningSecretKey::generate();

    let outcome = mint(
        &store,
        &ledger,
        &user,
        &verifier(&admin),
        &policy(&admin),
        &scheduled_24h(),
        48 * 3_600,
        DURING,
        request(),
        issuance(),
        |_authority| Ok::<Vec<u8>, std::convert::Infallible>(vec![7]),
    )
    .unwrap();
    assert_eq!(outcome.token.unwrap(), vec![7]);

    // A fresh reader: the entry is durable, not a value the test still holds.
    let listing = IssuanceLedger::at(ledger.path()).listing().unwrap();
    assert_eq!(listing.state, LedgerState::Present);
    assert_eq!(listing.entries.len(), 1, "a mint records exactly one entry");
    assert_eq!(listing.entries[0].issuance, issuance());
}

#[test]
fn a_mint_that_publishes_nothing_records_nothing() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    let store = FakeStore::default();
    let admin = AdminSigningKey::generate();
    let user = SigningSecretKey::generate();

    // The seal fails: the closure reports failure, so nothing was published.
    let failed = mint(
        &store,
        &ledger,
        &user,
        &verifier(&admin),
        &policy(&admin),
        &scheduled_24h(),
        48 * 3_600,
        DURING,
        request(),
        issuance(),
        |_authority| Err::<Vec<u8>, &'static str>("the seal failed"),
    )
    .unwrap();
    assert!(matches!(failed.token, Err("the seal failed")));
    assert!(
        ledger.listing().unwrap().entries.is_empty(),
        "a publication that failed must leave no ledger entry"
    );

    // A mint refused before the arm never reaches the closure at all.
    let refused = mint(
        &store,
        &ledger,
        &user,
        &verifier(&admin),
        &policy(&admin),
        &scheduled_24h(),
        3_600,
        DURING,
        request(),
        issuance(),
        |_authority| Ok::<Vec<u8>, std::convert::Infallible>(vec![7]),
    )
    .unwrap_err();
    assert_eq!(refused.exit_code(), 7);
    assert!(
        ledger.listing().unwrap().entries.is_empty(),
        "an armed-but-unpublished mint must leave no ledger entry"
    );
}

#[test]
fn a_ledger_that_cannot_be_written_publishes_nothing() {
    let dir = TempDir::new().unwrap();
    // A directory where a file is expected: the append cannot succeed.
    let ledger = IssuanceLedger::at(dir.path());

    let outcome = ledger.publish_recorded(issuance(), || Ok::<Vec<u8>, ()>(vec![9]));
    assert!(
        matches!(outcome, Err(PublishError::Ledger(_))),
        "a ledger that refuses the entry must fail the publication"
    );
}

// ---------------------------------------------------------------------------
// Criterion 2 — what this host minted, and nothing global
// ---------------------------------------------------------------------------

#[test]
fn an_absent_ledger_lists_nothing_and_makes_no_claim_about_other_hosts() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);

    let listing = IssuanceLedger::at(ledger.path()).listing().unwrap();
    assert_eq!(listing.state, LedgerState::Absent);
    assert!(listing.entries.is_empty(), "an empty ledger lists no token");

    let scope = listing.scope();
    assert!(
        scope.contains("this host"),
        "the listing must scope itself to this host, got: {scope}"
    );
    assert!(
        !scope.contains("no tokens exist"),
        "the listing must not turn a local absence into a global claim, got: {scope}"
    );
}

#[test]
fn an_empty_ledger_is_present_and_still_lists_nothing() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);
    assert_eq!(ledger.listing().unwrap().entries.len(), 1);

    // Same file, no events: "present and empty" is not the same state as
    // "absent", because only the first is evidence a host is buzzing.
    std::fs::write(ledger.path(), "").unwrap();
    let listing = IssuanceLedger::at(ledger.path()).listing().unwrap();
    assert_eq!(listing.state, LedgerState::Present);
    assert!(listing.entries.is_empty());
}

#[test]
fn the_scope_sentence_never_claims_empty_means_nowhere_else() {
    let listing = ksp_identity::issuance::LedgerListing {
        state: LedgerState::Present,
        entries: Vec::new(),
        torn_tail: false,
    };
    let scope = listing.scope();
    assert!(scope.contains("this host"), "got: {scope}");
    assert!(
        scope.contains("unknown"),
        "a token minted elsewhere is unknown here, and the sentence must say so: {scope}"
    );
}

// ---------------------------------------------------------------------------
// Criteria 3 and 4 — a revoked identifier is refused; an unknown one is not
// ---------------------------------------------------------------------------

#[test]
fn a_revoked_identifier_is_refused_by_the_next_local_run() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);

    let live = ledger.standing("jti-1").unwrap();
    assert!(matches!(live, TokenStanding::Live(_)));
    assert!(!live.refuses_run(), "a live token is not refused");

    let mark = ledger.revoke("jti-1", 1_600).unwrap();
    assert_eq!(mark.token_id, "jti-1");

    let revoked = ledger.standing("jti-1").unwrap();
    assert!(revoked.refuses_run(), "a revoked token is refused");
    assert_eq!(revoked.reason(), Some(&RevocationReason::TokenMarked));
}

#[test]
fn a_token_the_ledger_does_not_name_is_unknown_and_not_refused() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);

    let standing = ledger.standing("minted-elsewhere").unwrap();
    assert!(matches!(
        standing,
        TokenStanding::Unknown {
            ledger_present: true
        }
    ));
    assert!(
        !standing.refuses_run(),
        "a token minted elsewhere is unremarkable here, not invalid"
    );
    let note = standing.note().to_lowercase();
    assert!(note.contains("unknown"), "got: {note}");
}

#[test]
fn a_host_without_a_ledger_says_it_cannot_judge() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);

    let standing = ledger.standing("jti-1").unwrap();
    assert!(matches!(
        standing,
        TokenStanding::Unknown {
            ledger_present: false
        }
    ));
    assert!(!standing.refuses_run());
    let note = standing.note().to_lowercase();
    assert!(
        note.contains("cannot judge"),
        "a host with no ledger must say it cannot judge, got: {note}"
    );
}

#[test]
fn revoking_an_identifier_the_ledger_does_not_name_is_refused() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);
    let before = std::fs::read(ledger.path()).unwrap();

    let refusal = ledger.revoke("minted-elsewhere", 1_600).unwrap_err();
    assert!(matches!(refusal, LedgerError::UnknownToken { .. }));
    assert_eq!(
        std::fs::read(ledger.path()).unwrap(),
        before,
        "a refused mark must not change the ledger"
    );
}

#[test]
fn revoking_twice_records_one_mark() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);

    let first = ledger.revoke("jti-1", 1_600).unwrap();
    let second = ledger.revoke("jti-1", 1_700).unwrap();
    assert_eq!(first, second, "the earlier mark stands; a retry is a no-op");

    let text = std::fs::read_to_string(ledger.path()).unwrap();
    assert_eq!(
        text.matches("\"token_revoked\"").count(),
        1,
        "one mark, not two: {text}"
    );
}

// ---------------------------------------------------------------------------
// Criterion 5 — the reach of a revocation, stated and demonstrated
// ---------------------------------------------------------------------------

#[test]
fn a_copy_taken_before_the_revocation_still_opens_with_the_agents_key() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);

    // The agent copied the artifact before the revocation.
    let sealed = sealed();
    let copy = sealed.artifact.to_bytes().unwrap();

    ledger.revoke("jti-1", 1_600).unwrap();
    assert!(ledger.standing("jti-1").unwrap().refuses_run());

    // The copy is not recalled: the bytes are unchanged and the agent's own key
    // still opens them.
    let reparsed = DeliveryArtifact::from_bytes(&copy).unwrap();
    let verified = verify(&reparsed, &sealed.user.verifying_public()).unwrap();
    let opened = open(&verified, &sealed.agent_secret).unwrap();
    for (record, key) in &sealed.keys {
        assert_eq!(
            opened
                .get(&record.secret, record.version)
                .map(|k| k.as_bytes()),
            Some(key.as_bytes()),
            "a revocation must not reach a copy the holder already has"
        );
    }
}

#[test]
fn the_revocation_reach_states_both_halves() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);
    let standing = {
        ledger.revoke("jti-1", 1_600).unwrap();
        ledger.standing("jti-1").unwrap()
    };

    let note = standing.note().to_lowercase();
    assert!(
        note.contains("future mints") && note.contains("ledger"),
        "the note must state what it does reach, got: {note}"
    );
    assert!(
        note.contains("does not recall") && note.contains("copy"),
        "the note must state what it does not reach, got: {note}"
    );
}

// ---------------------------------------------------------------------------
// Criterion 6 — no key, content key or value in an entry
// ---------------------------------------------------------------------------

#[test]
fn an_entry_carries_no_key_content_key_or_value() {
    let sealed = sealed();
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);

    let text = std::fs::read_to_string(ledger.path()).unwrap();
    for (_, key) in &sealed.keys {
        let bytes = key.as_bytes();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !text.contains(&hex),
            "a content key reached the ledger: {text}"
        );
    }
    for forbidden in ["\"key\"", "content_key", "value", "plaintext", "ciphertext"] {
        assert!(
            !text.contains(forbidden),
            "an entry must carry no {forbidden}: {text}"
        );
    }
    for allowed in [
        "\"token_id\"",
        "\"agent\"",
        "\"secret\"",
        "\"version\"",
        "\"deadline\"",
        "\"policy_revision\"",
    ] {
        assert!(
            text.contains(allowed),
            "the entry must record {allowed}: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// T106 — admin revocation: a narrower revision, and the same decision in the
// ledger
// ---------------------------------------------------------------------------

#[test]
fn admin_revoke_narrows_the_policy_and_the_next_mint_refuses() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);
    let admin = AdminSigningKey::generate();
    let policy = policy(&admin);
    let verifier = verifier(&admin);

    // Before: the grant is present and the mint is authorised.
    assert!(
        verifier
            .verify(&policy, &policy_request(), DURING)
            .is_verified()
    );

    let revocation = admin_revoke(
        &ledger,
        &admin,
        &policy,
        Withdrawal::Secret(OpaqueSecretId::new("secret-1")),
        1_600,
    )
    .unwrap();

    assert_eq!(revocation.policy.revision(), policy.revision() + 1);
    assert!(
        revocation.policy.shareable_secrets().is_empty(),
        "the withdrawn grant must be gone"
    );
    assert!(
        revocation.policy.verify_issuer(&admin.verifying_public()),
        "the narrower revision must be signed by the same admin"
    );

    // The next mint refuses on any host holding the narrower revision.
    match verifier.verify(&revocation.policy, &policy_request(), DURING) {
        ksp_identity::VerificationOutcome::Refused(PolicyRefusal::SecretGrant { .. }) => {}
        other => panic!("the next mint must refuse the withdrawn grant, got {other:?}"),
    }

    // And a local client sees the same decision without verifying a policy.
    let standing = ledger.standing("jti-1").unwrap();
    assert!(standing.refuses_run());
    assert_eq!(
        standing.reason(),
        Some(&RevocationReason::GrantWithdrawn { policy_revision: 6 })
    );
}

#[test]
fn withdrawing_a_grant_that_was_never_granted_is_refused_without_a_mark() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);
    let admin = AdminSigningKey::generate();

    let refusal = admin_revoke(
        &ledger,
        &admin,
        &policy(&admin),
        Withdrawal::Agent(
            ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000099").unwrap(),
        ),
        1_600,
    )
    .unwrap_err();
    assert!(
        matches!(refusal, ksp_identity::issuance::RevocationError::Policy(_)),
        "a withdrawal that withdraws nothing must be refused, got {refusal:?}"
    );
    assert!(
        matches!(ledger.standing("jti-1").unwrap(), TokenStanding::Live(_)),
        "a refused withdrawal must not mark anything"
    );
}

#[test]
fn a_token_minted_after_the_grant_was_restored_is_not_revoked() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    let admin = AdminSigningKey::generate();
    let policy = policy(&admin);
    record(&ledger);

    // Withdrawn at revision 6 …
    admin_revoke(
        &ledger,
        &admin,
        &policy,
        Withdrawal::Secret(OpaqueSecretId::new("secret-1")),
        1_600,
    )
    .unwrap();
    // … and re-granted at revision 8, where a later token is minted.
    let regranted = Policy::new(
        &admin,
        KeyId::new(ADMIN_ID),
        PolicyBody::new(
            8,
            vault(),
            user(),
            trusted_keys(),
            vec![OpaqueSecretId::new("secret-1")],
            vec![agent()],
            MAX_TTL,
            MAX_TTL,
            NOT_BEFORE,
            NOT_AFTER,
        ),
    )
    .unwrap();

    let mut later = issuance();
    later.token_id = "jti-2".to_string();
    later.policy_revision = regranted.revision();
    ledger
        .publish_recorded(later, || Ok::<Vec<u8>, std::convert::Infallible>(vec![2]))
        .unwrap();

    assert!(
        matches!(ledger.standing("jti-2").unwrap(), TokenStanding::Live(_)),
        "a withdrawal older than a token's own revision does not reach it"
    );
    assert!(
        ledger.standing("jti-1").unwrap().refuses_run(),
        "the token minted under the withdrawn grant is still revoked"
    );
}

// ---------------------------------------------------------------------------
// The file's own properties — owner-only, and honest about a torn append
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn the_ledger_refuses_to_append_to_a_file_others_can_read() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);
    std::fs::set_permissions(ledger.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

    let refusal = ledger.revoke("jti-1", 1_600).unwrap_err();
    assert!(
        matches!(refusal, LedgerError::InsecurePermissions { .. }),
        "got {refusal:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_new_ledger_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);
    let mode = std::fs::metadata(ledger.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the ledger must be owner-only");
}

#[test]
fn a_torn_tail_is_reported_and_the_complete_entries_survive() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);

    // A crash in the middle of an append leaves a partial line.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(ledger.path())
        .unwrap();
    std::io::Write::write_all(&mut file, br#"{"event":"token_revoked","mark":{"token_i"#).unwrap();

    let listing = ledger.listing().unwrap();
    assert_eq!(listing.entries.len(), 1, "complete entries survive");
    assert!(listing.torn_tail, "a torn append must be reported");
}

#[test]
fn a_corrupt_line_before_the_end_is_an_error_not_a_torn_tail() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);
    let text = std::fs::read_to_string(ledger.path()).unwrap();
    std::fs::write(ledger.path(), format!("{{not json\n{text}")).unwrap();

    let refusal = ledger.listing().unwrap_err();
    assert!(
        matches!(refusal, LedgerError::Corrupt { line: 1 }),
        "a damaged middle line is corruption, not a torn tail, got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// Review v1 — the append path, the owner-only claim, and the untested surface
// ---------------------------------------------------------------------------

#[test]
fn a_revocation_after_a_torn_tail_is_refused_rather_than_lost() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(ledger.path())
        .unwrap();
    std::io::Write::write_all(&mut file, br#"{"event":"token_revoked","mark":{"token_i"#).unwrap();
    drop(file);
    let before = std::fs::read(ledger.path()).unwrap();

    let refusal = ledger.revoke("jti-1", 1_600).unwrap_err();
    assert!(
        matches!(refusal, LedgerError::TornTail { .. }),
        "a torn tail must refuse the append, got {refusal:?}"
    );
    assert_eq!(
        std::fs::read(ledger.path()).unwrap(),
        before,
        "a refused append must not touch the file"
    );
    assert!(
        matches!(ledger.standing("jti-1").unwrap(), TokenStanding::Live(_)),
        "nothing may be reported as revoked when nothing was recorded"
    );
}

#[test]
fn a_complete_last_line_missing_its_newline_is_refused_too() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);

    // Not a torn tail as far as parsing goes, but appending would still glue the
    // new event onto it.
    let text = std::fs::read_to_string(ledger.path()).unwrap();
    std::fs::write(ledger.path(), text.trim_end_matches('\n')).unwrap();

    let refusal = ledger.revoke("jti-1", 1_600).unwrap_err();
    assert!(
        matches!(refusal, LedgerError::TornTail { .. }),
        "got {refusal:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_ledger_is_not_written_through() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("elsewhere.txt");
    std::fs::write(&target, b"not a ledger\n").unwrap();
    let link = dir.path().join("issuance.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let ledger = IssuanceLedger::at(&link);
    let outcome = ledger.publish_recorded(issuance(), || Ok::<Vec<u8>, ()>(vec![1]));
    assert!(
        matches!(outcome, Err(PublishError::Ledger(LedgerError::Io { .. }))),
        "a symlinked ledger must be refused, got {outcome:?}"
    );
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"not a ledger\n",
        "the link target must be untouched"
    );
}

#[cfg(unix)]
#[test]
fn a_directory_created_for_the_ledger_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let outer = dir.path().join("keyspout");
    let inner = outer.join("state");
    let ledger = IssuanceLedger::at(inner.join("issuance.jsonl"));
    record(&ledger);

    for path in [&outer, &inner] {
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{} must be owner-only", path.display());
    }
}

#[test]
fn the_standing_says_whether_this_host_can_judge_at_all() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);

    assert!(
        !ledger.standing("jti-1").unwrap().can_judge(),
        "a host with no ledger cannot judge"
    );

    record(&ledger);
    assert!(ledger.standing("jti-1").unwrap().can_judge());
    assert!(
        ledger.standing("minted-elsewhere").unwrap().can_judge(),
        "a host with a ledger can judge an identifier it does not name"
    );

    ledger.revoke("jti-1", 1_600).unwrap();
    assert!(ledger.standing("jti-1").unwrap().can_judge());
}

#[test]
fn a_revoked_listing_entry_carries_the_time_of_its_mark() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);
    ledger.revoke("jti-1", 1_600).unwrap();

    let listing = ledger.listing().unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].revoked_at, Some(1_600));
    assert_eq!(
        listing.entries[0].reason,
        Some(RevocationReason::TokenMarked)
    );
}

#[cfg(unix)]
#[test]
fn an_append_whose_ledger_path_is_not_a_directory_reports_failure() {
    // The failure class this asserts is the one that matters: a write whose
    // durability cannot be established must not be reported as published. The
    // precondition is a path component that is a regular file, which holds for
    // every uid — a mode-based denial does not, because `root` bypasses DAC and
    // the suite runs as `root` for the cross-principal tests.
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state");
    std::fs::write(&state, b"not a directory").unwrap();

    let ledger = IssuanceLedger::at(state.join("issuance.jsonl"));
    let outcome = ledger.publish_recorded(issuance(), || Ok::<Vec<u8>, ()>(vec![1]));

    assert!(
        matches!(outcome, Err(PublishError::Ledger(LedgerError::Io { .. }))),
        "a record whose durability could not be established must not be reported as published, got {outcome:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_read_denied_directory_cannot_be_synced() {
    use std::os::unix::fs::PermissionsExt;

    // `0300` denies read, so the directory handle the durability step needs
    // cannot be opened. That is a discretionary-access check, and `root` passes
    // it, so this variant is only meaningful for an unprivileged uid; the test
    // above covers the same "not published" property where root can run it.
    // SAFETY: `geteuid` takes no arguments and touches no memory.
    #[allow(unsafe_code)]
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return;
    }

    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o300)).unwrap();

    let ledger = IssuanceLedger::at(state.join("issuance.jsonl"));
    let outcome = ledger.publish_recorded(issuance(), || Ok::<Vec<u8>, ()>(vec![1]));

    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(outcome, Err(PublishError::Ledger(LedgerError::Io { .. }))),
        "a record whose durability could not be established must not be reported as published, got {outcome:?}"
    );
}

#[test]
fn the_first_append_creates_the_file_through_the_directory_sync_path() {
    // The directory sync itself cannot be observed from a test; what can be is
    // that the creation path is the branch taken and that it completes, rather
    // than failing on a directory handle opened the wrong way.
    let dir = TempDir::new().unwrap();
    let ledger = IssuanceLedger::at(dir.path().join("state/issuance.jsonl"));
    assert!(!ledger.path().exists());

    record(&ledger);
    assert!(ledger.path().exists());
    assert_eq!(ledger.listing().unwrap().entries.len(), 1);
}

#[test]
fn retrying_admin_revoke_after_a_lost_policy_write_repeats_one_record() {
    let dir = TempDir::new().unwrap();
    let ledger = ledger_in(&dir);
    record(&ledger);
    let admin = AdminSigningKey::generate();
    let policy = policy(&admin);
    let withdrawal = Withdrawal::Secret(OpaqueSecretId::new("secret-1"));

    let first = admin_revoke(&ledger, &admin, &policy, withdrawal.clone(), 1_600).unwrap();
    // The caller crashed before writing `first.policy`; the retry starts from the
    // same original policy, at a later second.
    let second = admin_revoke(&ledger, &admin, &policy, withdrawal, 1_700).unwrap();

    assert_eq!(
        first.policy.revision(),
        second.policy.revision(),
        "the retry must produce the same revision"
    );
    assert_eq!(
        first.withdrawal, second.withdrawal,
        "the retry must report the record that is already in force"
    );
    let text = std::fs::read_to_string(ledger.path()).unwrap();
    assert_eq!(
        text.matches("\"grant_withdrawn\"").count(),
        1,
        "one decision, one record: {text}"
    );
}

// ---------------------------------------------------------------------------
// Vocabulary pinning — the scope sentence is reachable without a listing
// ---------------------------------------------------------------------------

#[test]
fn the_scope_sentence_is_stable_for_a_caller_without_a_ledger() {
    let sentence = ledger_scope(LedgerState::Absent, 0);
    assert!(sentence.contains("this host"), "got: {sentence}");
}

#[test]
fn a_revocation_reason_names_the_grant_it_withdrew() {
    let reason = RevocationReason::GrantWithdrawn { policy_revision: 6 };
    assert!(
        reason.to_string().contains("6"),
        "the reason must name the revision, got: {reason}"
    );
}

#[test]
fn the_ledger_path_is_the_one_it_was_built_with() {
    let dir = TempDir::new().unwrap();
    let path: PathBuf = dir.path().join("issuance.jsonl");
    let ledger = IssuanceLedger::at(&path);
    assert_eq!(ledger.path(), Path::new(&path));
}
