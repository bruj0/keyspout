//! A recovery phrase as an operator actually handles it.
//!
//! # What these tests hold
//!
//! A phrase is the only copy of the recovery material, so two failures matter
//! more than anything else here: a phrase that opens *nothing* after being
//! written down (because it was handed out before the bytes it describes were
//! durable), and a phrase that opens something *wrong* after being mistyped
//! (because parsing was lenient). The first is prevented by the shape of
//! `reshare_vault_bundle` — the phrase is a return value of a call that has
//! already persisted — and the second by refusing every malformed input rather
//! than salvaging it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_identity::{
    RecoveryError, RecoveryPhrase, SealedVault, UserVault, VaultBinding, recover_vault_bundle,
    reshare_vault_bundle, split_vault_bundle,
};
use ksp_types::shamir::{ShareCount, Threshold as ShamirThreshold};
use ksp_types::{ActorId, SealedBundle};

const PASSWORD: &str = "a long enough password";

fn binding() -> VaultBinding {
    VaultBinding {
        identity: ActorId::User(
            ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        ),
        signing_key_id: ksp_identity::KeyId::new("alice-ed25519-1"),
        recipient_key_id: ksp_identity::KeyId::new("alice-x25519-1"),
    }
}

/// A vault sealed under `PASSWORD`, and the bytes a phrase would split.
fn sealed() -> (SealedVault, SealedBundle) {
    let vault = UserVault::generate();
    let sealed = vault.seal(PASSWORD.as_bytes(), &binding()).unwrap();
    let bytes = ksp_types::cbor::encode(&sealed).unwrap();
    (sealed, SealedBundle::new(bytes))
}

#[test]
fn a_rendered_phrase_parses_back_to_the_share_set_it_describes() {
    let (_sealed, bundle) = sealed();
    let shares = split_vault_bundle(&bundle, ShamirThreshold(2), ShareCount(3)).unwrap();
    let phrase = RecoveryPhrase::new(ShamirThreshold(2), shares.clone()).unwrap();

    let parsed = RecoveryPhrase::parse(&phrase.render()).unwrap();
    assert_eq!(parsed.threshold(), ShamirThreshold(2));
    assert_eq!(parsed.shares(), shares.as_slice());
    // The phrase is a rendering, not a second format: it reconstructs the same
    // bytes the split produced.
    assert_eq!(parsed.recover().unwrap(), bundle);
}

#[test]
fn any_threshold_subset_of_a_parsed_phrase_recovers_the_bundle() {
    let (_sealed, bundle) = sealed();
    let shares = split_vault_bundle(&bundle, ShamirThreshold(2), ShareCount(3)).unwrap();
    let phrase = RecoveryPhrase::parse(
        &RecoveryPhrase::new(ShamirThreshold(2), shares)
            .unwrap()
            .render(),
    )
    .unwrap();

    for pair in [[0usize, 1], [0, 2], [1, 2]] {
        let subset = vec![
            phrase.shares()[pair[0]].clone(),
            phrase.shares()[pair[1]].clone(),
        ];
        assert_eq!(
            recover_vault_bundle(&subset, phrase.threshold()).unwrap(),
            bundle
        );
    }
}

#[test]
fn parsing_refuses_a_duplicated_share_index() {
    // Two shares at one evaluation point contribute one share's worth of
    // information, so accepting the pair would silently turn a 2-of-3 phrase
    // into a 1-of-3 one.
    let (_sealed, bundle) = sealed();
    let shares = split_vault_bundle(&bundle, ShamirThreshold(2), ShareCount(3)).unwrap();
    let text = RecoveryPhrase::new(ShamirThreshold(2), shares)
        .unwrap()
        .render();
    let mut lines: Vec<&str> = text.lines().collect();
    let duplicated = lines[1].to_string();
    lines[2] = &duplicated;
    let tampered = lines.join("\n") + "\n";

    assert!(matches!(
        RecoveryPhrase::parse(&tampered),
        Err(RecoveryError::Phrase(_))
    ));
}

#[test]
fn parsing_refuses_what_it_cannot_read_exactly() {
    let (_sealed, bundle) = sealed();
    let shares = split_vault_bundle(&bundle, ShamirThreshold(2), ShareCount(3)).unwrap();
    let text = RecoveryPhrase::new(ShamirThreshold(2), shares)
        .unwrap()
        .render();

    let cases = [
        // Wrong header.
        text.replacen("keyspout-recovery-v1", "keyspout-recovery-v2", 1),
        // Declares three shares and carries two.
        text.replacen("n=3", "n=4", 1),
        // A truncated value.
        text.replacen('0', "zz", 1),
        // A threshold above the share count.
        text.replacen("k=2", "k=9", 1),
        // Empty.
        String::new(),
    ];
    for case in cases {
        // Any refusal is acceptable; what is not is a lenient parse that salvages
        // a phrase and then recovers garbage. A threshold above the share count is
        // refused by the share-set validator, so the variant differs by case.
        assert!(
            RecoveryPhrase::parse(&case).is_err(),
            "parsing accepted: {case}"
        );
    }
}

#[test]
fn a_failing_persist_yields_no_phrase_at_all() {
    let (_sealed, bundle) = sealed();
    let mut handed = Vec::new();

    let result = reshare_vault_bundle(&bundle, ShamirThreshold(2), ShareCount(3), |bytes| {
        handed.push(bytes.clone());
        Err("the disk is full".to_string())
    });

    assert!(matches!(result, Err(RecoveryError::Persist { .. })));
    // The bytes were offered — the failure is the store's, not a silent skip —
    // and no phrase escaped.
    assert_eq!(handed.len(), 1);
    assert_eq!(handed[0], bundle);
}

#[test]
fn a_value_that_is_not_hex_is_refused_rather_than_read_as_hex() {
    // Review Issue 3: `u8::from_str_radix("+1", 16)` is Ok(1), so a lenient
    // parser would read a hand-edited `+1` as hex 01 instead of refusing it.
    let text = "keyspout-recovery-v1 k=1 n=1\nshare 1 +1\n";
    assert!(
        matches!(RecoveryPhrase::parse(text), Err(RecoveryError::Phrase(_))),
        "a non-hex value was read as hex"
    );
}

#[test]
fn a_failing_split_writes_nothing() {
    // Review Issue 1: the split can fail (a threshold outside 1..=n). If the
    // bytes were persisted first, the operator would be left with a replaced file
    // and no phrase — and an old phrase that no longer matches it.
    let (_sealed, bundle) = sealed();
    let mut calls = 0usize;

    let result = reshare_vault_bundle(&bundle, ShamirThreshold(5), ShareCount(3), |_| {
        calls += 1;
        Ok(())
    });

    assert!(
        result.is_err(),
        "a threshold above the share count must fail"
    );
    assert_eq!(calls, 0, "the bytes were persisted before the split failed");
}

#[test]
fn the_parser_refuses_a_share_index_the_scheme_never_produces() {
    // Index zero evaluates a polynomial at its constant term, which is the
    // secret. `split` refuses to produce one, so a phrase carrying one is not a
    // phrase.
    let (_sealed, bundle) = sealed();
    let shares = split_vault_bundle(&bundle, ShamirThreshold(2), ShareCount(3)).unwrap();
    let text = RecoveryPhrase::new(ShamirThreshold(2), shares)
        .unwrap()
        .render();

    // Only the first share is moved to zero, and the others keep their own
    // indices: moving all of them would make the duplicate-index rule reject the
    // phrase, and the test would pass without the zero rule existing at all.
    let mut moved = false;
    let zeroed = text
        .lines()
        .map(|line| {
            if !moved && line.starts_with("share ") {
                moved = true;
                let rest = line.split_once(' ').unwrap().1;
                let value = rest.split_once(' ').unwrap().1;
                format!("share 0 {value}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    assert!(
        matches!(
            RecoveryPhrase::parse(&zeroed),
            Err(RecoveryError::Phrase(_))
        ),
        "the parser accepted a share at index zero"
    );
}

#[test]
fn the_phrase_returned_describes_the_bytes_that_were_persisted() {
    let (_sealed, bundle) = sealed();
    let mut persisted: Option<SealedBundle> = None;

    let phrase = reshare_vault_bundle(&bundle, ShamirThreshold(2), ShareCount(3), |bytes| {
        persisted = Some(bytes.clone());
        Ok(())
    })
    .unwrap();

    // The phrase reconstructs exactly what the caller was told to store: writing
    // one set of bytes and handing out a phrase for another is the failure this
    // API shape exists to make impossible.
    assert_eq!(phrase.recover().unwrap(), persisted.unwrap());
}

#[test]
fn a_rekeyed_vault_keeps_its_identity_and_no_longer_matches_the_old_phrase() {
    let vault = UserVault::generate();
    let before = vault.seal(PASSWORD.as_bytes(), &binding()).unwrap();
    let before_bytes = ksp_types::cbor::encode(&before).unwrap();
    let old_phrase = RecoveryPhrase::new(
        ShamirThreshold(2),
        split_vault_bundle(
            &SealedBundle::new(before_bytes.clone()),
            ShamirThreshold(2),
            ShareCount(3),
        )
        .unwrap(),
    )
    .unwrap();

    // A rekey re-seals the same keys under the same password with a fresh salt
    // and nonce, so the file changes while the keys do not.
    let after = vault.seal(PASSWORD.as_bytes(), &binding()).unwrap();
    assert_ne!(before.salt(), after.salt(), "a re-seal must re-randomise");
    // The pre-rekey vault is still bound to its own password: a re-seal must not
    // have changed what opens the file.
    assert!(
        before.unseal(PASSWORD.as_bytes(), &binding()).is_ok(),
        "the pre-rekey vault must still open under its password"
    );
    assert!(
        before
            .unseal(b"a different long password", &binding())
            .is_err(),
        "a different password must not open the vault"
    );

    let after_bytes = ksp_types::cbor::encode(&after).unwrap();
    let phrase = reshare_vault_bundle(
        &SealedBundle::new(after_bytes.clone()),
        ShamirThreshold(2),
        ShareCount(3),
        |_| Ok(()),
    )
    .unwrap();

    // The new phrase restores the new file and opens it under the same password.
    let recovered: SealedVault =
        ksp_types::cbor::decode(phrase.recover().unwrap().as_bytes()).unwrap();
    let reopened = recovered.unseal(PASSWORD.as_bytes(), &binding()).unwrap();
    assert_eq!(
        reopened.signing_public().to_bytes(),
        vault.signing_public().to_bytes()
    );
    assert_eq!(
        reopened.recipient_public().to_bytes(),
        vault.recipient_public().to_bytes()
    );
    assert_eq!(
        reopened.vault_key().as_bytes(),
        vault.vault_key().as_bytes()
    );

    // The old phrase reconstructs the OLD bytes, which this host no longer
    // holds — so against the file that exists now it opens nothing.
    let old_recovered: SealedVault =
        ksp_types::cbor::decode(old_phrase.recover().unwrap().as_bytes()).unwrap();
    assert_ne!(
        ksp_types::cbor::encode(&old_recovered).unwrap(),
        after_bytes,
        "the old phrase must not reconstruct the new file"
    );
}
