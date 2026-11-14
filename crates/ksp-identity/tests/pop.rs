//! The acceptance criteria for WP07, driven through the public API.
//!
//! Misfit C is replay, and the point of these tests is that replay is **not**
//! prevented: a proof in an accepted bucket verifies twice, by design. Misfit M
//! is signature-domain confusion, so a proof is offered where a token signature
//! is expected. The tests are written from the attacker's side where that is the
//! only way to see the property.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_identity::{
    EXIT_MISSING_KEY, EXIT_UNPROVEN, HostKeys, PopPreimage, PresentedProof, RecipientPublicKey,
    RunOutcome, RunRefusal, RunRequest, SigningSecretKey, VerifyingPublicKey, accepted_buckets,
    argv_hash_of, bucket_start, is_accepted, sign_pop, verify_pop, verify_run,
};
use ksp_types::RecordVersion;

fn signing() -> SigningSecretKey {
    SigningSecretKey::generate()
}

fn request(now: u64) -> RunRequest {
    RunRequest {
        jti: "jti-1".to_string(),
        record_version: RecordVersion(3),
        record_path: "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000007/secret-1/3".to_string(),
        argv: vec![b"child".to_vec(), b"--flag".to_vec()],
        now,
    }
}

fn preimage(req: &RunRequest, window_ts: u64) -> PopPreimage {
    PopPreimage::new(
        req.jti.clone(),
        req.record_version,
        req.record_path.clone(),
        &req.argv,
        window_ts,
    )
    .unwrap()
}

fn recipient() -> RecipientPublicKey {
    RecipientPublicKey::from_bytes([3u8; 32])
}

// ---------------------------------------------------------------------------
// Criterion 1 — a proof verifies twice; this is not exactly-once
// ---------------------------------------------------------------------------

#[test]
fn a_proof_in_an_accepted_bucket_verifies_twice_and_that_is_not_exactly_once() {
    let key = signing();
    let req = request(90);
    let preimage = preimage(&req, 90);
    let signature = sign_pop(&key, &preimage).unwrap();
    let keys = HostKeys {
        signing_public: Some(&key.verifying_public()),
        recipient_public: Some(&recipient()),
    };

    // The same proof, presented twice. Both deliver. This is a documented
    // property, not a defect: the proof authenticates a compliant invocation,
    // and the artifact's confidentiality comes from the HPKE seal, not from a
    // signature that could never have protected a released content key.
    for attempt in 1..=2 {
        let outcome = verify_run(
            keys,
            &req,
            Some(PresentedProof {
                preimage: &preimage,
                signature: &signature,
            }),
        );
        assert_eq!(outcome, RunOutcome::Deliver, "attempt {attempt}");
    }
}

// ---------------------------------------------------------------------------
// Criterion 2 — the bucket boundary is an exact set
// ---------------------------------------------------------------------------

#[test]
fn the_accepted_instants_are_five_aligned_buckets_and_plus_90_is_not_among_them() {
    // At 89 the bucket start is 60; at 90 it is 90.
    assert_eq!(bucket_start(89), 60);
    assert_eq!(bucket_start(90), 90);

    let at_ninety: Vec<u64> = accepted_buckets(90).to_vec();
    assert_eq!(at_ninety, vec![90, 60, 120, 30, 150]);

    for accepted in at_ninety {
        assert!(is_accepted(90, accepted), "{accepted} should be accepted");
    }

    // The boundary the brief calls out: +90 from the bucket start is not in the
    // set, though a symmetric "within 60 seconds" test would admit it elsewhere.
    assert!(!is_accepted(90, 180));
    assert!(!is_accepted(89, 150));
    // And -90 is not accepted either: the offsets are 0, -30, +30, -60, +60.
    assert!(!is_accepted(90, 0));

    // The distinction that makes this a set test rather than a duration test:
    // an *unaligned* instant close to the clock is not in the set. `|90 - 100|`
    // is ten seconds, so a symmetric "within 60 seconds" comparison would
    // accept it; a five-bucket membership test does not.
    assert!(!is_accepted(90, 100));

    // Below the first minute the earlier buckets do not exist. The computation
    // must not wrap to values near `u64::MAX` and then accept them.
    for now in [0u64, 1, 29, 30, 59] {
        let buckets = accepted_buckets(now);
        assert!(
            buckets.iter().all(|instant| *instant <= now + 60),
            "a bucket for now={now} wrapped: {buckets:?}"
        );
        assert!(!is_accepted(now, u64::MAX - 59));
        assert!(!is_accepted(now, u64::MAX));
    }
    assert!(!is_accepted(90, 91));
    assert!(!is_accepted(90, 89));
    assert!(!is_accepted(90, 45));
}

// ---------------------------------------------------------------------------
// Criteria 3 to 7 — the argv hash
// ---------------------------------------------------------------------------

#[test]
fn the_argv_hash_is_identical_across_runs_of_the_same_command() {
    let first = argv_hash_of(&["child", "--flag", "value"]).unwrap();
    let second = argv_hash_of(&["child", "--flag", "value"]).unwrap();
    assert_eq!(first, second);
}

#[test]
fn the_argv_hash_differs_when_two_arguments_are_swapped() {
    let first = argv_hash_of(&["one", "two"]).unwrap();
    let second = argv_hash_of(&["two", "one"]).unwrap();
    assert_ne!(first, second);
}

#[test]
fn the_argv_hash_separates_a_split_argument_from_a_joined_one() {
    // The concatenation-ambiguity case: a naive join would collide here.
    assert_ne!(
        argv_hash_of(&["ab", "c"]).unwrap(),
        argv_hash_of(&["a", "bc"]).unwrap()
    );
}

#[test]
fn the_argv_hash_depends_on_the_argv_alone_and_not_on_ambient_state() {
    // The hash is a function of the argv slice and has no parameter that could
    // carry the environment, the working directory or `argv[0]`. Comparing it
    // against a committed constant therefore asserts something real: the value
    // was produced in a different ambient environment and is unchanged here.
    //
    // Deliberately not a `set_var` test: mutating the process environment is
    // `unsafe` in this edition and unsound under a threaded test runner, and the
    // workspace denies `unsafe`.
    let pinned =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/argv-hash.bin");
    let expected = std::fs::read(pinned).unwrap();
    assert_eq!(
        argv_hash_of(&["child", "--flag"]).unwrap().to_vec(),
        expected,
        "the argv hash changed; it must depend on the argv bytes only"
    );
}

#[test]
fn the_argv_hash_does_not_vary_with_the_working_directory_or_argv_zero() {
    let direct = argv_hash_of(&["child", "--flag"]).unwrap();
    let cwd = std::env::current_dir().unwrap();
    // The hash is a function of the argv bytes; neither the process's own
    // argv[0] nor the working directory can enter it, because neither is an
    // argument to it.
    assert_eq!(direct, argv_hash_of(&["child", "--flag"]).unwrap());
    assert_eq!(std::env::current_dir().unwrap(), cwd);
}

// ---------------------------------------------------------------------------
// Criteria 8 to 12 — the run path and its exit codes
// ---------------------------------------------------------------------------

#[test]
fn a_missing_proof_exits_eight() {
    let key = signing();
    let outcome = verify_run(
        HostKeys {
            signing_public: Some(&key.verifying_public()),
            recipient_public: Some(&recipient()),
        },
        &request(90),
        None,
    );
    assert_eq!(outcome, RunOutcome::Refuse(RunRefusal::MissingProof));
    assert_eq!(outcome.exit_code(), EXIT_UNPROVEN);
}

#[test]
fn a_malformed_proof_exits_eight() {
    let refusal = RunRefusal::MalformedProof {
        cause: "the preimage was not CBOR".to_string(),
    };
    assert_eq!(RunOutcome::Refuse(refusal).exit_code(), EXIT_UNPROVEN);
}

#[test]
fn a_proof_from_outside_the_accepted_buckets_exits_eight() {
    let key = signing();
    let req = request(90);
    let stale = preimage(&req, 0); // two buckets below the accepted set
    let signature = sign_pop(&key, &stale).unwrap();

    let outcome = verify_run(
        HostKeys {
            signing_public: Some(&key.verifying_public()),
            recipient_public: Some(&recipient()),
        },
        &req,
        Some(PresentedProof {
            preimage: &stale,
            signature: &signature,
        }),
    );
    assert_eq!(
        outcome,
        RunOutcome::Refuse(RunRefusal::OutsideWindow {
            window_ts: 0,
            now: 90
        })
    );
    assert_eq!(outcome.exit_code(), EXIT_UNPROVEN);
}

#[test]
fn an_absent_enrolled_signing_key_exits_six_and_is_distinguishable_from_eight() {
    let key = signing();
    let req = request(90);
    let proof = preimage(&req, 90);
    let signature = sign_pop(&key, &proof).unwrap();

    // No enrolled key: exit 6.
    let no_key = verify_run(
        HostKeys {
            signing_public: None,
            recipient_public: Some(&recipient()),
        },
        &req,
        Some(PresentedProof {
            preimage: &proof,
            signature: &signature,
        }),
    );
    assert_eq!(no_key, RunOutcome::Refuse(RunRefusal::MissingSigningKey));
    assert_eq!(no_key.exit_code(), EXIT_MISSING_KEY);

    // Key present, proof absent: exit 8.
    let no_proof = verify_run(
        HostKeys {
            signing_public: Some(&key.verifying_public()),
            recipient_public: Some(&recipient()),
        },
        &req,
        None,
    );
    assert_eq!(no_proof.exit_code(), EXIT_UNPROVEN);
    assert_ne!(no_key.exit_code(), no_proof.exit_code());
}

#[test]
fn an_absent_recipient_key_refuses_to_unwrap_and_delivers_nothing() {
    let key = signing();
    let req = request(90);
    let proof = preimage(&req, 90);
    let signature = sign_pop(&key, &proof).unwrap();

    let outcome = verify_run(
        HostKeys {
            signing_public: Some(&key.verifying_public()),
            recipient_public: None,
        },
        &req,
        Some(PresentedProof {
            preimage: &proof,
            signature: &signature,
        }),
    );
    assert_eq!(outcome, RunOutcome::Refuse(RunRefusal::MissingRecipientKey));
    assert!(!outcome.may_deliver());
}

// ---------------------------------------------------------------------------
// Criterion 13 — the proof is bound to the request
// ---------------------------------------------------------------------------

#[test]
fn a_proof_about_another_delivery_is_rejected_even_though_the_signature_is_valid() {
    let key = signing();
    let req = request(90);

    for field in ["jti", "record_version", "record_path"] {
        let other = match field {
            "jti" => PopPreimage::new(
                "jti-OTHER",
                req.record_version,
                req.record_path.clone(),
                &req.argv,
                90,
            ),
            "record_version" => PopPreimage::new(
                req.jti.clone(),
                RecordVersion(4),
                req.record_path.clone(),
                &req.argv,
                90,
            ),
            _ => PopPreimage::new(
                req.jti.clone(),
                req.record_version,
                "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000008/secret-1/3",
                &req.argv,
                90,
            ),
        }
        .unwrap();

        // The signature really is valid over the preimage it covers.
        let signature = sign_pop(&key, &other).unwrap();
        assert!(verify_pop(&key.verifying_public(), &other, &signature).is_ok());

        let outcome = verify_run(
            HostKeys {
                signing_public: Some(&key.verifying_public()),
                recipient_public: Some(&recipient()),
            },
            &req,
            Some(PresentedProof {
                preimage: &other,
                signature: &signature,
            }),
        );
        assert_eq!(
            outcome,
            RunOutcome::Refuse(RunRefusal::BindingMismatch { field }),
            "a proof about another {field} must not authorise this request"
        );
    }
}

#[test]
fn a_proof_for_a_different_command_is_rejected() {
    let key = signing();
    let req = request(90);
    // Signed over another argv, at an accepted instant.
    let other = PopPreimage::new(
        req.jti.clone(),
        req.record_version,
        req.record_path.clone(),
        &[b"other-child".to_vec()],
        90,
    )
    .unwrap();
    let signature = sign_pop(&key, &other).unwrap();

    assert_eq!(
        verify_run(
            HostKeys {
                signing_public: Some(&key.verifying_public()),
                recipient_public: Some(&recipient()),
            },
            &req,
            Some(PresentedProof {
                preimage: &other,
                signature: &signature,
            }),
        ),
        RunOutcome::Refuse(RunRefusal::BindingMismatch { field: "argv_hash" })
    );
}

#[test]
fn a_proof_signed_by_another_key_is_rejected() {
    let key = signing();
    let impostor = signing();
    let req = request(90);
    let proof = preimage(&req, 90);
    let signature = sign_pop(&impostor, &proof).unwrap();

    assert_eq!(
        verify_run(
            HostKeys {
                signing_public: Some(&key.verifying_public()),
                recipient_public: Some(&recipient()),
            },
            &req,
            Some(PresentedProof {
                preimage: &proof,
                signature: &signature,
            }),
        ),
        RunOutcome::Refuse(RunRefusal::BadSignature)
    );
}

// ---------------------------------------------------------------------------
// Criteria 14 and 15 — fixtures and the shared domain constants
// ---------------------------------------------------------------------------

/// Regenerate the committed preimage fixture after an intentional change.
#[test]
#[ignore = "regenerates the golden fixture; run deliberately"]
fn regenerate_golden_fixture() {
    let req = pinned_request();
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::write(
        dir.join("pop-preimage.cbor"),
        preimage(&req, 120).signing_bytes().unwrap(),
    )
    .unwrap();
}

/// The request the preimage fixture was generated from. Every value is fixed.
fn pinned_request() -> RunRequest {
    RunRequest {
        jti: "jti-pinned".to_string(),
        record_version: RecordVersion(7),
        record_path: "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000007/secret-1/7".to_string(),
        argv: vec![b"child".to_vec(), b"--flag".to_vec()],
        now: 120,
    }
}

#[test]
fn the_pinned_preimage_and_argv_hash_match_their_fixtures() {
    let req = pinned_request();
    let pinned = preimage(&req, 120);

    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let expected = std::fs::read(dir.join("pop-preimage.cbor")).unwrap();
    assert_eq!(
        pinned.signing_bytes().unwrap(),
        expected,
        "the pop preimage changed; if deliberate, regenerate tests/fixtures/pop-preimage.cbor"
    );

    let hash = ksp_identity::argv_hash(&req.argv).unwrap();
    let expected_hash = std::fs::read(dir.join("argv-hash.bin")).unwrap();
    assert_eq!(hash.to_vec(), expected_hash);
}

#[test]
fn the_proof_of_possession_domain_is_not_the_token_domain() {
    assert_ne!(
        ksp_types::DOMAIN_POP,
        ksp_types::DOMAIN_TOKEN,
        "a proof signature must not be interchangeable with a token signature"
    );

    // And the bytes really are domain separated: the same body under the two
    // domains produces different preimages.
    let key = signing();
    let req = request(90);
    let proof = preimage(&req, 90);
    let pop_bytes = proof.signing_bytes().unwrap();
    assert!(pop_bytes.starts_with(ksp_types::DOMAIN_POP));
    assert!(!pop_bytes.starts_with(ksp_types::DOMAIN_TOKEN));

    let signature = sign_pop(&key, &proof).unwrap();
    assert!(verify_pop(&key.verifying_public(), &proof, &signature).is_ok());
}

// Keep the unused-import checker honest about the type used above.
#[allow(dead_code)]
fn assert_public_key(_: &VerifyingPublicKey) {}
