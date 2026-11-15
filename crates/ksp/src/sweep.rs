//! `secret purge-expired` and `secret gc`: the sweep a host runs on itself.
//!
//! # Two commands, one sweep
//!
//! `purge-expired` is bounded so a foreground invocation on a large backlog
//! stays predictable, and `gc` is unbounded because a scheduled job has no
//! operator waiting on it. Both call the same `ksp_backend::sweep`, with the
//! bound as the only difference — a second implementation would be a second
//! answer to what "expired" means.
//!
//! # What this command cannot say
//!
//! Nothing here recalls a copy. A sweep removes versions this host still holds
//! under a deadline it armed; a copy taken earlier is already gone from this
//! host's reach. The counts are about *this* store, and the printed note comes
//! from the report so the caveat cannot drift away from the report that governs
//! it.

use std::path::PathBuf;

use ksp_backend::proof::{ProofGate, SignedSweepProof, SweepProof};
use ksp_backend::sweeper::SweeperArming;
use ksp_backend::{SweepBound, SweepReport, proof, sweep};
use ksp_deletion::{AcknowledgementJournal, EvidenceSigningKey};
use ksp_types::ActorId;

use crate::config::{self, Layout};
use crate::consume::{FileJournal, FileReports};
use crate::exit::{self, Outcome};

/// Why a sweep did not run, or did not finish.
#[derive(Debug, thiserror::Error)]
pub enum SweepCommandError {
    /// The deployment files this host needs are missing.
    #[error("this host is not provisioned")]
    NotProvisioned,
    /// The selected backend could not be opened.
    #[error("the selected backend could not be opened")]
    Store,
    /// The backend's admission classification could not be built.
    #[error("the backend's capability could not be classified")]
    Classification,
    /// The configured backend has no store this command can open.
    #[error(
        "this command can only sweep the local store, and the configured backend is {0}: \
         sweeping the file store while reporting another backend's capability would attach \
         one backend's work to another's claim"
    )]
    UnsupportedBackend(String),
    /// The admin key this host signs reports with could not be loaded.
    #[error("the admin key could not be loaded")]
    Keys,
    /// The armed records could not be enumerated.
    #[error("{0}")]
    Sweep(String),
    /// The run happened but its proof could not be written.
    ///
    /// A run whose evidence did not land is a run no reader can see, so it is a
    /// failure of the run and not a warning attached to a success.
    #[error("the proof of this run could not be written ({0})")]
    Proof(&'static str),
}

/// One sweep invocation: what it did and where its proof went.
pub struct Swept {
    /// The counts the command prints.
    pub report: SweepReport,
    /// The proof's path, or why it could not be written.
    pub proof: Result<PathBuf, SweepCommandError>,
}

impl SweepCommandError {
    /// The exit code this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NotProvisioned | Self::Keys | Self::Classification | Self::Store => {
                exit::MISSING_KEY
            }
            Self::UnsupportedBackend(_) => exit::CAPABILITY_REFUSAL,
            // Nothing was removed and nothing was claimed, so this is not the
            // "some deletions failed" code.
            Self::Sweep(_) | Self::Proof(_) => exit::INTERNAL,
        }
    }
}

/// Whether this command can open the configured backend at all.
///
/// The store this module opens is the local one, so a selection it cannot open
/// is refused rather than swept anyway: the report's capability would otherwise
/// describe a backend the removals did not happen on.
fn supported(selection: &config::BackendSelection) -> bool {
    matches!(selection, config::BackendSelection::File { .. })
}

/// How the run counts what it did, independent of whether it finished.
#[derive(Default)]
struct Counts {
    removed: u32,
    already_absent: u32,
    not_yet_due: u32,
    bound_reached: bool,
}

/// Run one sweep over this host's store and write the proof of the run.
///
/// # Which capability this run uses
///
/// The **configured** one, read from the verified arming record: the mechanism the run
/// is meant to keep. It is deliberately not the admission classification, which needs
/// a proof this run is about to write — a run that had to prove itself before it could
/// sweep would report `not_yet_due = 0` without ever reading an arm.
pub fn run(bound: SweepBound, layout: &Layout) -> Result<Swept, SweepCommandError> {
    run_as(bound, layout, false, None)
}

/// Run one sweep, as the admin or as the user.
///
/// The two differ in who signs and who is named as the actor, and in nothing
/// else: the removal rule, the report shape and the bound are the same. A user
/// sweep needs the vault password because her key lives in the sealed vault; an
/// admin sweep needs the admin key, which the user's account cannot read.
pub fn run_as(
    bound: SweepBound,
    layout: &Layout,
    user_signed: bool,
    passphrase_file: Option<&std::path::Path>,
) -> Result<Swept, SweepCommandError> {
    let (deployment, anchor) =
        crate::deployment::require(layout).map_err(|_| SweepCommandError::NotProvisioned)?;
    let selection = config::read_backend(layout).map_err(|_| SweepCommandError::Classification)?;
    if !supported(&selection) {
        return Err(SweepCommandError::UnsupportedBackend(
            selection.name().to_string(),
        ));
    }
    let recorded = crate::admission::recorded_arming(layout, &deployment, &anchor);
    let classification = crate::admission::sweep_classification(recorded.as_ref());

    // One store, two ports: the sweep reads the arm records and removes the
    // versions from the same place, and a second handle would be a second
    // configuration to keep in step.
    let store = config::open_file_store(layout).map_err(|_| SweepCommandError::Store)?;
    // The journal is a protected root, so it is created by the table rather than
    // by the writer's first append: an inherited `umask` would widen it and the
    // next `ksp status` would report a drift this command caused.
    crate::layout::ensure_row(layout.root(), &layout.journal_root())
        .map_err(|_| SweepCommandError::Store)?;
    let journal = FileJournal::new(layout.journal_root());
    let acknowledgement = AcknowledgementJournal::new(journal);
    let reports = FileReports::new(layout.journal_root().join("reports"));

    // Who signs decides whose cleanup this is. An admin sweep admits a lease and
    // is signed by the admin key; a user sweep removes the user's own copies and
    // is signed by her enrolled key, which is the only key that speaks for her.
    //
    // The user path deliberately does not load the admin key: a host where the
    // user's account cannot read `admin/` must still run her own cleanup, and an
    // admin key that was required here would make her sweep depend on a file she
    // is not supposed to have.
    // One seed, two uses: the sweep's own report and the proof that admission
    // reads. Both must be signed by the same key, or a proof would claim a run the
    // report attributes to someone else.
    let (seed, actor, signer_key_id, proof_principal) = if user_signed {
        let password = match passphrase_file {
            Some(path) => std::fs::read(path).map_err(|_| SweepCommandError::Keys)?,
            None => {
                let mut buffer = Vec::new();
                use std::io::Read as _;
                std::io::stdin()
                    .read_to_end(&mut buffer)
                    .map_err(|_| SweepCommandError::Keys)?;
                buffer
            }
        };
        let unsealed =
            crate::secret::unseal(layout, &password).map_err(|_| SweepCommandError::Keys)?;
        let key_id = deployment
            .user_signing_key_id
            .clone()
            .ok_or(SweepCommandError::Keys)?;
        let seed = unsealed
            .vault
            .with_signing_key(|key| key.with_secret(|seed| *seed));
        (
            seed,
            ActorId::User(deployment.user),
            key_id,
            deployment.user,
        )
    } else {
        let admin =
            crate::admin::load_admin(layout, &anchor).map_err(|_| SweepCommandError::Keys)?;
        let seed = admin.with_secret(|seed| *seed);
        (
            seed,
            ActorId::Admin(deployment.admin),
            anchor.key_id.clone(),
            deployment.admin,
        )
    };
    let signer: EvidenceSigningKey = EvidenceSigningKey::from_seed(seed);

    let started = i64::try_from(crate::run::now_seconds()).unwrap_or(i64::MAX);
    let result = sweep(
        &store,
        &classification,
        &store,
        &acknowledgement,
        &signer,
        &reports,
        &actor,
        signer_key_id.as_str(),
        started,
        bound,
    );
    let ended = i64::try_from(crate::run::now_seconds()).unwrap_or(started);

    let (counts, success, error_codes) = match &result {
        Ok(report) => (
            Counts {
                removed: u32::try_from(report.removed).unwrap_or(u32::MAX),
                already_absent: u32::try_from(report.already_absent).unwrap_or(u32::MAX),
                not_yet_due: u32::try_from(report.not_yet_due).unwrap_or(u32::MAX),
                bound_reached: report.bound_reached,
            },
            report.is_clean(),
            // Codes, never the reasons: a reason carries an operation identity.
            if report.is_clean() {
                Vec::new()
            } else {
                error_codes(report)
            },
        ),
        // A run that could not read the arms still leaves evidence that it ran and
        // failed. Its counts are zero because it produced none, not because the
        // backlog was empty.
        Err(_) => (Counts::default(), false, vec![exit::INTERNAL]),
    };

    // Both an admin run and a user run write a proof. Which key signs it is what
    // admission reads: the admin's proof admits an admin-signed lease, and the
    // user's admits a copy she bounded herself. A user arming that wrote no proof
    // could never mint the copy its own sweep would remove.
    let proof: Result<PathBuf, SweepCommandError> = {
        let verifying_bytes = if user_signed {
            deployment
                .user_signing_key
                .ok_or(SweepCommandError::Keys)?
                .to_bytes()
        } else {
            anchor.key.to_bytes()
        };
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&verifying_bytes)
            .map_err(|_| SweepCommandError::Keys)?;
        write_proof(
            layout,
            &deployment,
            ProofSigner {
                principal: proof_principal,
                key_id: signer_key_id.as_str().to_string(),
                verifying,
                signing: ed25519_dalek::SigningKey::from_bytes(&seed),
                _lifetime: std::marker::PhantomData,
            },
            recorded.as_ref(),
            &classification,
            started,
            ended,
            &counts,
            success,
            error_codes,
        )
    };
    match result {
        Ok(report) => Ok(Swept { report, proof }),
        Err(error) => {
            // The sweep's own reason is the one to report; a proof that also failed
            // to land is not a second error an operator can act on differently.
            Err(SweepCommandError::Sweep(error.to_string()))
        }
    }
}

/// One exit class per failure, in a stable order.
///
/// Codes only. `SweepFailure` also carries a reason and an operation identity, and
/// both can name a record; the proof directory is readable by every principal.
/// Multiplicity is kept on purpose: a collapsed `[9]` would report three failed
/// removals as one, and FR-055 asks the proof to carry every error.
///
/// `Arm` maps to the policy-denial class because the arm record **is** the
/// authorisation: a record this host cannot decode, or one that does not authorise
/// the actor, means no authorisation could be established. `Journal` and `Report`
/// failures are the writer's own, so they stay internal.
fn error_codes(report: &SweepReport) -> Vec<i32> {
    let mut codes: Vec<i32> = report
        .failures
        .iter()
        .map(|failure| match failure.stage {
            ksp_backend::FailureStage::Arm => exit::POLICY_DENIAL,
            ksp_backend::FailureStage::Remove => exit::DELETE_FAILED,
            ksp_backend::FailureStage::Journal | ksp_backend::FailureStage::Report => {
                exit::INTERNAL
            }
        })
        .collect();
    codes.sort_unstable();
    codes
}

/// Write the proof of this run, whichever way the run ended.
///
/// The window, the declaration the run served and the realised gap between scheduled
/// runs are recorded beside the counts. Nothing identifies a version, and the realised
/// interval is only measured for an armed run: an ad-hoc run must not speak about a
/// cadence at all.
/// Who signed a proof, and the key ID that names the signer.
///
/// The anchor is the key admission verifies against, so it is the signer's own
/// verifying key rather than the admin's: a proof signed by the user must be
/// checked against the user's pin, or it would verify against a key that never
/// touched it.
struct ProofSigner<'a> {
    /// The principal the run is recorded for.
    principal: ksp_types::PrincipalId,
    /// The key ID the proof names.
    key_id: String,
    /// The verifying key admission will check the signature against.
    verifying: ed25519_dalek::VerifyingKey,
    /// The signing key, lent to one closure.
    signing: ed25519_dalek::SigningKey,
    /// Keeps the borrow alive for the call.
    _lifetime: std::marker::PhantomData<&'a ()>,
}

#[allow(clippy::too_many_arguments)]
fn write_proof(
    layout: &Layout,
    deployment: &crate::deployment::Deployment,
    signer: ProofSigner<'_>,
    recorded: Option<&SweeperArming>,
    classification: &ksp_backend::admission::Classification,
    started: i64,
    ended: i64,
    counts: &Counts,
    success: bool,
    error_codes: Vec<i32>,
) -> Result<PathBuf, SweepCommandError> {
    let directory = layout.sweeper_proofs_dir();
    crate::layout::ensure_row(layout.root(), &directory)
        .map_err(|_| SweepCommandError::Proof("the sweeper/proofs directory is not usable"))?;
    let verifying = signer.verifying;
    let gate = ProofGate {
        directory: directory.clone(),
        anchor: &verifying,
        scope: crate::admission::deployment_scope(deployment),
    };

    let realised = if recorded.is_some() {
        gate.scan()
            .0
            .into_iter()
            .filter(|signed| signed.proof.success && signed.proof.cadence().is_some())
            .map(|signed| ended - signed.proof.run_end)
            .find(|gap| *gap > 0)
            .map(|gap| u64::try_from(gap).unwrap_or(u64::MAX))
    } else {
        None
    };
    let proof = SweepProof {
        scope: crate::admission::deployment_scope(deployment),
        arming_id: recorded.map(|arming| arming.arming_id.clone()),
        admin: signer.principal,
        run_start: started,
        run_end: ended,
        declared_interval_secs: classification
            .declared_cadence
            .map(|cadence| cadence.as_secs()),
        realised_interval_secs: realised,
        success,
        removed: counts.removed,
        already_absent: counts.already_absent,
        not_yet_due: counts.not_yet_due,
        bound_reached: counts.bound_reached,
        error_codes,
        signer_key_id: signer.key_id.clone(),
        prev_digest: gate.newest_digest(),
    };
    let signed = SignedSweepProof::sign(proof, &signer.signing)
        .map_err(|_| SweepCommandError::Proof("the proof could not be signed"))?;
    proof::write(&directory, &signed)
        .map_err(|_| SweepCommandError::Proof("the proof file could not be written"))
}

/// Print the report and return the outcome the process exits with.
///
/// A sweep that finished is a success even when it removed nothing, and a
/// backend with no mechanism is a success too: "nothing can be swept here" is an
/// answer, not a failure. A record that did not finish is not: some deletions
/// were attempted and did not happen, which is the delete-failed code.
pub fn outcome<W: std::io::Write>(
    report: &SweepReport,
    emitter: &mut crate::output::Emitter<W>,
) -> Outcome {
    let code = code(report);
    let summary = crate::output::SweepSummary::from_report(report);
    if emitter
        .report(&crate::output::Report::Sweep(summary))
        .is_err()
    {
        return Outcome::Failed(exit::INTERNAL);
    }
    if code == exit::SUCCESS {
        Outcome::Success
    } else {
        Outcome::Failed(code)
    }
}

/// The exit class a finished run produces, without printing anything.
///
/// Split from [`outcome`] so the audit record can carry the class of a run whose
/// report has not been written yet: the record is durable before the report, and a
/// record that had to guess the code would be a record of a guess.
pub fn code(report: &SweepReport) -> i32 {
    if report.is_clean() {
        exit::SUCCESS
    } else {
        exit::DELETE_FAILED
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::time::Duration;

    use ksp_backend::sweep::{FailureStage, SweepFailure};
    use ksp_types::LeaseCapability;

    use super::*;

    fn report(failures: Vec<SweepFailure>) -> SweepReport {
        SweepReport {
            capability: LeaseCapability::Scheduled {
                interval: Duration::from_secs(3_600),
            },
            selected: 1,
            removed: 0,
            already_absent: 0,
            not_yet_due: 2,
            failures,
            bound_reached: true,
            backlog: 0,
        }
    }

    /// A sweep that did not finish is not a success, and it is not the generic
    /// internal failure either: some deletion was attempted and did not happen.
    #[test]
    fn a_report_with_a_failure_exits_nine_and_still_prints_the_counts() {
        let report = report(vec![SweepFailure {
            operation_identity: "op-1".to_string(),
            stage: FailureStage::Remove,
            reason: "the backend refused the delete".to_string(),
        }]);
        let mut emitter = crate::output::Emitter::new(false, Vec::new());

        let outcome = outcome(&report, &mut emitter);

        assert_eq!(outcome, Outcome::Failed(exit::DELETE_FAILED));
        assert!(!report.is_clean());
    }

    /// FR-055: every error is reported, so a failure is not collapsed into its
    /// class. Two removals that failed are two failures, and the proof must say so.
    #[test]
    fn repeated_failures_are_not_collapsed_to_one_code() {
        let failure = |identity: &str, stage: FailureStage| SweepFailure {
            operation_identity: identity.to_string(),
            stage,
            reason: "the backend refused".to_string(),
        };
        let report = report(vec![
            failure("op-1", FailureStage::Remove),
            failure("op-2", FailureStage::Remove),
            failure("op-3", FailureStage::Arm),
        ]);

        assert_eq!(
            error_codes(&report),
            vec![
                exit::POLICY_DENIAL,
                exit::DELETE_FAILED,
                exit::DELETE_FAILED
            ],
            "three failures leave three classes, in a stable order"
        );
    }

    #[test]
    fn a_clean_report_is_a_success_even_when_the_bound_was_reached() {
        let mut emitter = crate::output::Emitter::new(false, Vec::new());

        assert_eq!(outcome(&report(Vec::new()), &mut emitter), Outcome::Success);
    }

    /// Only the local store can be swept, and the selection is what decides.
    #[test]
    fn a_selection_this_command_cannot_open_is_refused() {
        assert!(supported(&config::BackendSelection::File {
            root: std::path::PathBuf::from("/tmp/store"),
        }));
        assert!(!supported(&config::BackendSelection::Valkey {
            logical_expiry: true,
            append_only: true,
            append_fsync_always: true,
            waitaof_supported: true,
        }));
    }

    /// A backend with no mechanism is a success, and the note is the report's
    /// own sentence — the point of carrying it rather than writing one here.
    #[test]
    fn a_backend_with_no_mechanism_succeeds_and_the_note_says_what_it_cannot_claim() {
        let mut no_mechanism = report(Vec::new());
        no_mechanism.capability = LeaseCapability::None;
        no_mechanism.selected = 0;
        no_mechanism.not_yet_due = 0;
        no_mechanism.bound_reached = false;
        let mut sink = Vec::new();
        {
            let mut emitter = crate::output::Emitter::new(false, &mut sink);
            assert_eq!(outcome(&no_mechanism, &mut emitter), Outcome::Success);
        }
        let printed = String::from_utf8(sink).unwrap();
        assert!(
            printed.contains("says nothing about whether a copy still exists"),
            "the note is what keeps zero removals from reading as an erasure: {printed}"
        );
    }
}
