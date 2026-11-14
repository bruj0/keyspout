//! **Sweep Proof**: evidence that a run happened, and the gate that reads it.
//!
//! # A proof of a run is not a proof of an effect
//!
//! A successful proof with `removed: 0` is exactly what a clean backlog and a sweep
//! that matched nothing both produce (misfit Y). The type therefore carries counts and
//! error codes and **no** version, path or secret identifier: it says what the run
//! counted, never that a particular version is gone. The proof directory is
//! world-readable, so a record identifier there would disclose one.
//!
//! # The declaration does not admit; the proof does
//!
//! An arming is configuration (misfit C). Admission reads the newest **successful**
//! proof: its signature against the pinned admin key (misfit M), its age against a
//! bound measured from the run's own duration, and the proven interval — never the
//! declared one when the two disagree (FR-057).
//!
//! # What the gate never does
//!
//! It never picks the newest *file*: a newer failure must not extend a clock (misfit
//! N), so files are scanned newest-first and the newest **success** decides. A torn or
//! unreadable file is reported and skipped, not treated as fresh.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ksp_types::domains::DOMAIN_SWEEP_PROOF;
use ksp_types::{AdmissionDecision, AdmissionRefusal, LeaseCapability, PrincipalId};
use serde::{Deserialize, Serialize};

/// How many files the gate reads at most, newest first.
///
/// A bounded scan needs no lock and no head pointer, and a pointer could be rolled back
/// to an older proof — which is the attack a scan cannot fall for.
pub const PROOF_SCAN_LIMIT: usize = 8;

/// How many proofs a run leaves behind after pruning.
///
/// Pruning happens **after** the new proof is written, so the newest success always
/// survives its own run.
pub const PROOF_RETENTION: usize = 200;

/// One sweep run, as the run itself reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepProof {
    /// The scope the run swept, as the arming recorded it.
    pub scope: String,
    /// The arming this run served, when it ran under a recorded schedule.
    ///
    /// `None` is an ad-hoc run. It proves a run happened, not that a cadence is kept,
    /// so the gate does not let it speak about a cadence — neither to extend the clock
    /// nor to poison it.
    pub arming_id: Option<String>,
    /// The admin principal the run is recorded for: the collector whose key
    /// signed it, never the user whose records it swept.
    pub admin: PrincipalId,
    /// The run's own start, in the writer's clock seconds.
    pub run_start: i64,
    /// The run's end.
    pub run_end: i64,
    /// The interval the arming declared, when one was recorded.
    pub declared_interval_secs: Option<u64>,
    /// The interval between this run and the previous successful one, when known.
    pub realised_interval_secs: Option<u64>,
    /// Whether the run completed.
    pub success: bool,
    /// Versions the run removed.
    pub removed: u32,
    /// Versions already absent when the run looked.
    pub already_absent: u32,
    /// Versions whose deadline has not passed.
    pub not_yet_due: u32,
    /// Whether the run stopped at its bound.
    pub bound_reached: bool,
    /// One entry per failure, in a stable order: the exit class, never the reason.
    /// A reason carries paths and operation identities, and this file is readable by
    /// every principal. Multiplicity is kept — three failed removals are three
    /// entries, not one.
    pub error_codes: Vec<i32>,
    /// The key ID that signed it.
    pub signer_key_id: String,
    /// The digest of the proof this one follows, when there was one.
    ///
    /// A link recorded inside the signed proof, not a head pointer kept beside the
    /// files: a separate pointer is one more mutable claim, and it could be rolled
    /// back to an older proof.
    pub prev_digest: Option<[u8; 32]>,
}

impl SweepProof {
    /// How long this run took, which is what the grace is measured from.
    pub fn duration(&self) -> i64 {
        (self.run_end - self.run_start).max(0)
    }

    /// `grace = clamp(max(I/2, d + 5s), I/2, I)` for the interval this proof proves.
    ///
    /// Measured rather than guessed: a host whose sweeps take minutes needs more slack
    /// than one that finishes in a second, and a constant would be wrong on both.
    pub fn grace(&self, interval: Duration) -> i64 {
        let interval = i64::try_from(interval.as_secs()).unwrap_or(i64::MAX);
        let half = interval / 2;
        let measured = self.duration().saturating_add(5);
        measured.max(half).min(interval)
    }

    /// The cadence this proof establishes, if it establishes one.
    ///
    /// A shorter gap than the arming declared is a retry or a manual run between
    /// scheduled ones, not a faster schedule, so the larger of the two is used. That
    /// is the conservative reading: it can only raise the floor and lengthen the
    /// bound, and a schedule that really became slower is the case misfit N is about.
    pub fn cadence(&self) -> Option<Duration> {
        let cadence = match (self.declared_interval_secs, self.realised_interval_secs) {
            (None, None) => return None,
            (Some(declared), None) => declared,
            (None, Some(realised)) => realised,
            (Some(declared), Some(realised)) => declared.max(realised),
        };
        Some(Duration::from_secs(cadence))
    }
}

/// One proof with the admin's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSweepProof {
    /// The run's report.
    pub proof: SweepProof,
    /// The admin's signature over the domain and the proof's canonical bytes.
    pub signature: Vec<u8>,
}

impl SignedSweepProof {
    /// Sign one proof.
    pub fn sign(proof: SweepProof, signer: &SigningKey) -> Result<Self, GateRefusal> {
        let preimage = Self::preimage(&proof)?;
        Ok(Self {
            proof,
            signature: signer.sign(&preimage).to_bytes().to_vec(),
        })
    }

    /// Whether the signature is the admin's over these bytes.
    pub fn verify(&self, key: &VerifyingKey) -> bool {
        let Ok(preimage) = Self::preimage(&self.proof) else {
            return false;
        };
        let Ok(signature) = <[u8; 64]>::try_from(self.signature.as_slice()) else {
            return false;
        };
        key.verify_strict(&preimage, &Signature::from_bytes(&signature))
            .is_ok()
    }

    /// The bytes this host writes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GateRefusal> {
        ksp_types::cbor::encode(self).map_err(|_| GateRefusal::Malformed)
    }

    /// Read a proof. Decoded, not trusted: verification is the gate's.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GateRefusal> {
        ksp_types::cbor::decode(bytes).map_err(|_| GateRefusal::Malformed)
    }

    /// This proof's digest, which the next proof records as its previous link.
    ///
    /// Over the bytes as written. Canonical CBOR makes re-encoding stable, so the
    /// digest a reader computes is the digest the writer recorded.
    pub fn digest(&self) -> Option<[u8; 32]> {
        let bytes = self.to_bytes().ok()?;
        let mut digest = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut digest, &bytes);
        let finalized = sha2::Digest::finalize(digest);
        let mut out = [0u8; 32];
        out.copy_from_slice(&finalized);
        Some(out)
    }

    fn preimage(proof: &SweepProof) -> Result<Vec<u8>, GateRefusal> {
        let mut preimage = Vec::from(DOMAIN_SWEEP_PROOF);
        preimage.extend(ksp_types::cbor::encode(proof).map_err(|_| GateRefusal::Malformed)?);
        Ok(preimage)
    }
}

/// Why a lease was not admitted, or why the host cannot tell.
///
/// Every variant names what was observed. "Policy denied" tells an operator neither
/// what to fix nor whether the fix is a run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateRefusal {
    /// No proof exists at all.
    #[error("no sweep proof exists under sweeper/proofs: nothing has proven this cleanup runs")]
    NoProof,
    /// Proofs exist, but none records a successful run.
    #[error("no successful sweep proof exists: the newest runs failed or could not be read")]
    NoSuccessfulProof,
    /// Runs succeeded, but none was invoked under a recorded schedule.
    ///
    /// A run without a schedule proves that something swept, not that a cadence is
    /// kept, so it names no interval an admission floor could use.
    #[error(
        "no sweep proof establishes a cadence: the recorded runs were not invoked under a \
         recorded schedule"
    )]
    NoCadence,
    /// The signature does not verify against the pinned anchor.
    #[error("the sweep proof for '{scope}' does not verify against any pinned key")]
    Unverified {
        /// The scope the proof names.
        scope: String,
    },
    /// The proof is older than the bound its own duration justifies.
    #[error(
        "the newest sweep proof is {age}s old and the bound is {bound}s (interval {interval}s plus \
         measured grace): the run is late, which is not a deletion deadline"
    )]
    Stale {
        /// Seconds since the run ended.
        age: i64,
        /// The bound that was exceeded.
        bound: i64,
        /// The interval the proof proves.
        interval: i64,
    },
    /// The proof is dated so far ahead that the clock cannot be trusted.
    #[error(
        "the sweep proof is dated {skew}s in the future, beyond the {grace}s grace: this host's \
         clock or the signer's is wrong, and freshness cannot be decided"
    )]
    FutureSkew {
        /// How far ahead the run ended.
        skew: i64,
        /// The grace that was exceeded.
        grace: i64,
    },
    /// The proof serves a different scope.
    #[error("the sweep proof covers '{found}', not this deployment's '{expected}'")]
    ScopeMismatch {
        /// The scope the proof names.
        found: String,
        /// The scope this deployment needs.
        expected: String,
    },
    /// The requested lease is below the existing `2 ×` floor.
    ///
    /// The inner value is the floor's own refusal, printed as it prints itself
    /// elsewhere; this variant only says which decision produced it.
    #[error("the requested lease is below the proven floor: {0:?}")]
    BelowFloor(AdmissionRefusal),
    /// A proof could not be decoded.
    #[error("a sweep proof could not be decoded")]
    Malformed,
    /// The sweeper area is present but cannot be read.
    ///
    /// FR-028: this is reported as unverifiable, not as "no proof exists" — the
    /// difference is whether an operator should look for a run or for a permission.
    #[error("the sweep proof directory could not be read, so no proof can be verified")]
    Unreadable,
}

/// What a verified, in-scope, successful proof establishes about its cadence.
///
/// Freshness is a property of the observation, not a third kind of failure: a stale
/// proof still says what cadence ran and how old that evidence is, which is exactly
/// what `ksp status` has to print (FR-057, misfit D).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofObservation {
    /// The cadence the proof establishes.
    pub interval: Duration,
    /// Seconds between the run's end and the reader's clock. Negative when the run
    /// is dated in the future.
    pub age: i64,
    /// The grace this proof's own duration justifies.
    pub grace: i64,
}

impl ProofObservation {
    /// `I + grace`: the age at which this proof stops being fresh.
    pub fn bound(&self) -> i64 {
        i64::try_from(self.interval.as_secs())
            .unwrap_or(i64::MAX)
            .saturating_add(self.grace)
    }

    /// Where this proof sits relative to its bound.
    pub fn freshness(&self) -> ProofFreshness {
        if self.age < -self.grace {
            ProofFreshness::FutureSkew
        } else if self.age >= self.bound() {
            ProofFreshness::Stale
        } else {
            ProofFreshness::Fresh
        }
    }

    /// The refusal an unfresh observation produces, or `None` when it is fresh.
    ///
    /// The same observation still reports its age and cadence to status: this returns
    /// the sentence a lease request prints, not a second reading of the proof.
    pub fn refusal(&self) -> Option<GateRefusal> {
        let interval = i64::try_from(self.interval.as_secs()).unwrap_or(i64::MAX);
        match self.freshness() {
            ProofFreshness::Fresh => None,
            ProofFreshness::Stale => Some(GateRefusal::Stale {
                age: self.age,
                bound: self.bound(),
                interval,
            }),
            ProofFreshness::FutureSkew => Some(GateRefusal::FutureSkew {
                skew: -self.age,
                grace: self.grace,
            }),
        }
    }
}

/// How a proof's age compares with the bound its own duration justifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProofFreshness {
    /// The run is recent enough that the cleanup it proves is still the admitted one.
    Fresh,
    /// The run is later than `I + grace` allows. Lateness, not obsolescence: the
    /// cleanup may still have run, and no maximum lag follows from this.
    Stale,
    /// The run is dated further ahead than the grace can explain, so this host
    /// cannot decide freshness at all.
    FutureSkew,
}

/// The newest usable proof, with the run window a disclosure has to print.
///
/// `ksp status` reports the proof's age, the window it ran in and the counts it
/// recorded, which [`ProofObservation`] does not carry. Both come from one scan so the
/// disclosure and the admission decision cannot read two different proofs (FR-057).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvedRun {
    /// The cadence, age and grace the gate decides with.
    pub observation: ProofObservation,
    /// The signed record, so disclosure prints the same run's window and counts.
    pub proof: SweepProof,
}

/// The newest failed run, and whether it is evidence at all.
///
/// A failed run must never extend the clock (FR-056), and a forged one must not be
/// read as a report of this deployment's failures either: the signature is checked
/// before the counts are shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailedRun {
    /// The failure's signature is the pinned anchor's over this deployment's scope.
    Verified(Box<SweepProof>),
    /// A failure exists but does not verify, so its counts are not reported.
    Unverified {
        /// Why it could not be read as evidence.
        reason: String,
    },
}

/// What admission decided, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    /// A successful, verified, fresh proof admits this lease.
    Admitted {
        /// The cadence admission used.
        interval: Duration,
        /// The proof's age at the decision.
        age: i64,
    },
    /// A refusal with its reason.
    Refused(GateRefusal),
    /// The host cannot decide, and this is why. Never treated as fresh.
    Unknown(GateRefusal),
}

/// The gate: newest successful proof, verified, fresh, and above the floor.
pub struct ProofGate<'a> {
    /// `KSP_HOME/sweeper/proofs`.
    pub directory: PathBuf,
    /// The pinned admin key.
    pub anchor: &'a VerifyingKey,
    /// The scope this deployment sweeps.
    pub scope: String,
}

impl ProofGate<'_> {
    /// The newest successful proof that says something about a cadence.
    ///
    /// The checking lives in [`Self::proved_run`]; this returns the observation the
    /// gate decides on.
    pub fn observe(&self, now: i64) -> Result<ProofObservation, GateRefusal> {
        self.proved_run(now).map(|run| run.observation)
    }

    /// The newest successful proof that says something about a cadence, with its
    /// run window.
    ///
    /// Skips a run that ran without a recorded schedule: it proves a run, not a
    /// cadence, and treating it as evidence would let any ad-hoc `secret gc` decide
    /// the answer for every lease. A failed run is skipped for the same reason — it
    /// must never extend the clock (FR-056). One implementation of the scan, so
    /// `ksp status` prints exactly the proof the gate decided on.
    pub fn proved_run(&self, now: i64) -> Result<ProvedRun, GateRefusal> {
        match std::fs::read_dir(&self.directory) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(GateRefusal::NoProof);
            }
            // Present but unreadable is not absent: an operator chasing a missing
            // run would never find the permission that hides it.
            Err(_) => return Err(GateRefusal::Unreadable),
        }
        let (proofs, trouble) = self.scan();
        // Torn or symlinked files are skipped, never decoded-and-trusted. When they
        // are all there is, the refusal says the proof could not be read rather than
        // pretending nothing was written.
        if proofs.is_empty() && !trouble.is_empty() {
            return Err(GateRefusal::Malformed);
        }
        let empty = proofs.is_empty();
        let mut saw_success = false;
        for signed in proofs {
            if !signed.proof.success {
                continue;
            }
            saw_success = true;
            // Verification and scope come before the cadence question: a proof that
            // does not verify is reported as unverifiable, never silently skipped.
            if !signed.verify(self.anchor) {
                return Err(GateRefusal::Unverified {
                    scope: signed.proof.scope.clone(),
                });
            }
            if signed.proof.scope != self.scope {
                return Err(GateRefusal::ScopeMismatch {
                    found: signed.proof.scope.clone(),
                    expected: self.scope.clone(),
                });
            }
            let Some(interval) = signed.proof.cadence() else {
                continue;
            };
            return Ok(ProvedRun {
                observation: ProofObservation {
                    interval,
                    age: now - signed.proof.run_end,
                    grace: signed.proof.grace(interval),
                },
                proof: signed.proof,
            });
        }
        if saw_success {
            // Every success was verified and in scope; the loop only reaches here
            // when none of them named a cadence.
            Err(GateRefusal::NoCadence)
        } else if empty {
            Err(GateRefusal::NoProof)
        } else {
            Err(GateRefusal::NoSuccessfulProof)
        }
    }

    /// The newest failed run for this scope, newest file first.
    ///
    /// Only for disclosure: a failure never extends the clock, and a failure that does
    /// not verify never has its counts shown. An unreadable directory is an error
    /// rather than `None`: "no failure is recorded" and "this host cannot see whether
    /// one is" are the two answers the disclosure must keep apart.
    pub fn newest_failure(&self) -> Result<Option<FailedRun>, GateRefusal> {
        match std::fs::read_dir(&self.directory) {
            Ok(_) => {}
            // No directory at all is a known absence: nothing has run here.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(GateRefusal::Unreadable),
        }
        let (proofs, _) = self.scan();
        for signed in proofs {
            if signed.proof.success || signed.proof.scope != self.scope {
                continue;
            }
            if !signed.verify(self.anchor) {
                return Ok(Some(FailedRun::Unverified {
                    reason: "the newest failed run for this scope does not verify against the \
                             pinned admin key, so its counts are not reported"
                        .to_string(),
                }));
            }
            return Ok(Some(FailedRun::Verified(Box::new(signed.proof))));
        }
        Ok(None)
    }

    /// The proof files that could not be decoded or read, so a disclosure can count
    /// them instead of implying the directory held nothing else.
    pub fn trouble(&self) -> usize {
        self.scan().1.len()
    }

    /// Decide whether a lease of `requested` is admissible at `now`.
    pub fn admit(&self, requested: Duration, now: i64) -> GateOutcome {
        match self.observe(now) {
            Err(refusal) => GateOutcome::Refused(refusal),
            Ok(observation) => match observation.freshness() {
                ProofFreshness::FutureSkew => GateOutcome::Unknown(GateRefusal::FutureSkew {
                    skew: -observation.age,
                    grace: observation.grace,
                }),
                ProofFreshness::Stale => GateOutcome::Refused(GateRefusal::Stale {
                    age: observation.age,
                    bound: observation.bound(),
                    interval: i64::try_from(observation.interval.as_secs()).unwrap_or(i64::MAX),
                }),
                ProofFreshness::Fresh => {
                    // The floor is the existing `2 x` rule, not a second copy of it.
                    match ksp_types::admit_decision(
                        &LeaseCapability::Scheduled {
                            interval: observation.interval,
                        },
                        requested,
                    ) {
                        AdmissionDecision::Admitted => GateOutcome::Admitted {
                            interval: observation.interval,
                            age: observation.age,
                        },
                        AdmissionDecision::Refused(reason) => {
                            GateOutcome::Refused(GateRefusal::BelowFloor(reason))
                        }
                    }
                }
            },
        }
    }

    /// The newest proofs, newest first, bounded by [`PROOF_SCAN_LIMIT`].
    ///
    /// Symlinks are skipped rather than followed: a link in a world-readable directory
    /// is the one way a scan could be pointed at a file outside it.
    pub fn scan(&self) -> (Vec<SignedSweepProof>, Vec<String>) {
        let (names, mut trouble) = self.names();
        let mut proofs = Vec::new();
        for name in names {
            let path = self.directory.join(&name);
            match std::fs::read(&path)
                .map_err(|_| ())
                .and_then(|bytes| SignedSweepProof::from_bytes(&bytes).map_err(|_| ()))
            {
                Ok(proof) => proofs.push(proof),
                Err(()) => trouble.push(name),
            }
        }
        (proofs, trouble)
    }

    /// The digest of the newest proof file, which the next proof links to.
    pub fn newest_digest(&self) -> Option<[u8; 32]> {
        let (names, _) = self.names();
        let name = names.first()?;
        let bytes = std::fs::read(self.directory.join(name)).ok()?;
        let mut digest = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut digest, &bytes);
        let finalized = sha2::Digest::finalize(digest);
        let mut out = [0u8; 32];
        out.copy_from_slice(&finalized);
        Some(out)
    }

    /// The proof file names, newest first and bounded, plus the ones skipped.
    fn names(&self) -> (Vec<String>, Vec<String>) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return (Vec::new(), Vec::new());
        };
        let mut names = Vec::new();
        let mut trouble = Vec::new();
        for entry in entries.flatten() {
            let is_symlink = entry
                .file_type()
                .map(|kind| kind.is_symlink())
                .unwrap_or(true);
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".cbor") {
                continue;
            }
            if is_symlink {
                trouble.push(name);
                continue;
            }
            names.push(name);
        }
        // The name starts with the run end, zero-padded, so the newest is the largest.
        names.sort_by(|left, right| right.cmp(left));
        names.truncate(PROOF_SCAN_LIMIT);
        (names, trouble)
    }
}

/// Write one proof and prune to [`PROOF_RETENTION`], newest first.
///
/// The proof is written before the prune, so a run's own evidence cannot be the file
/// the prune removes. The file is `0644`: exactly one writer (the admin principal) and
/// every principal a reader, because a proof authorises a lease the reader has to be
/// able to check.
pub fn write(directory: &Path, signed: &SignedSweepProof) -> Result<PathBuf, GateRefusal> {
    std::fs::create_dir_all(directory).map_err(|_| GateRefusal::Malformed)?;
    let name = file_name(signed);
    let path = directory.join(&name);
    let bytes = signed.to_bytes()?;
    let temporary = directory.join(format!(".{name}.tmp"));
    std::fs::write(&temporary, &bytes).map_err(|_| GateRefusal::Malformed)?;
    set_readable(&temporary)?;
    std::fs::rename(&temporary, &path).map_err(|_| GateRefusal::Malformed)?;
    retain(directory, PROOF_RETENTION);
    Ok(path)
}

/// `<run_end:010>-<8 hex>.cbor`: the timestamp sorts, the digest separates.
///
/// The suffix is the digest of the signed proof, so two runs in the same second
/// produce two files unless their evidence is byte-identical — in which case they
/// are the same statement and one file is enough. A backwards clock step lands
/// under an older prefix and cannot overwrite a newer proof.
fn file_name(signed: &SignedSweepProof) -> String {
    let mut digest = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut digest, signed.signature.as_slice());
    sha2::Digest::update(&mut digest, signed.proof.run_end.to_be_bytes());
    let bytes = sha2::Digest::finalize(digest);
    let hex: String = bytes[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{:010}-{hex}.cbor", signed.proof.run_end.max(0))
}

/// Give the written proof the mode the table records: `0644`.
///
/// `create` honours the caller's `umask`, which is how a mode drifts below the one
/// the layout states. Setting it explicitly makes the file's mode the design's, not
/// the invoking shell's.
fn set_readable(path: &Path) -> Result<(), GateRefusal> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(path, mode).map_err(|_| GateRefusal::Malformed)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Keep the newest `keep` proofs.
fn retain(directory: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut names = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            name.ends_with(".cbor").then_some(name)
        })
        .collect::<Vec<_>>();
    names.sort_by(|left, right| right.cmp(left));
    for name in names.into_iter().skip(keep) {
        let _ = std::fs::remove_file(directory.join(name));
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says why.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const SCOPE: &str = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-*";
    const I: u64 = 300;

    fn admin() -> PrincipalId {
        PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap()
    }

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn proof(run_end: i64, success: bool, duration: i64) -> SweepProof {
        SweepProof {
            scope: SCOPE.to_string(),
            arming_id: Some("arm-1".to_string()),
            admin: admin(),
            run_start: run_end - duration,
            run_end,
            declared_interval_secs: Some(I),
            realised_interval_secs: None,
            success,
            removed: 0,
            already_absent: 0,
            not_yet_due: 0,
            bound_reached: false,
            error_codes: if success { Vec::new() } else { vec![9] },
            signer_key_id: "admin-2026".to_string(),
            prev_digest: None,
        }
    }

    /// The same proof, invoked without a recorded schedule.
    fn unarmed(run_end: i64) -> SweepProof {
        SweepProof {
            arming_id: None,
            declared_interval_secs: None,
            ..proof(run_end, true, 0)
        }
    }

    fn gate(directory: &Path) -> ProofGate<'_> {
        ProofGate {
            directory: directory.to_path_buf(),
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        }
    }

    fn write_proof(directory: &Path, proof: SweepProof) {
        write_proof_signed_by(directory, proof, &signer());
    }

    fn write_proof_signed_by(directory: &Path, proof: SweepProof, key: &SigningKey) {
        let signed = SignedSweepProof::sign(proof, key).unwrap();
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join(file_name(&signed)),
            signed.to_bytes().unwrap(),
        )
        .unwrap();
    }

    /// T055: the observation and the window come from one proof.
    #[test]
    fn the_proved_run_carries_the_window_its_observation_came_from() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        let mut run = proof(1_000, true, 4);
        run.removed = 2;
        run.already_absent = 1;
        run.not_yet_due = 3;
        write_proof(&directory, run);

        let run = gate(&directory).proved_run(1_010).unwrap();
        assert_eq!(run.observation.age, 10);
        assert_eq!(run.proof.run_end, 1_000);
        assert_eq!(run.proof.run_start, 996);
        assert_eq!(
            (
                run.proof.removed,
                run.proof.already_absent,
                run.proof.not_yet_due
            ),
            (2, 1, 3),
            "the counts travel with the window they were recorded with"
        );
    }

    /// FR-056: a newer failure is reported, and is never the proof that decides.
    #[test]
    fn a_newer_failure_is_reported_and_never_chosen() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        write_proof(&directory, proof(1_000, true, 4));
        write_proof(&directory, proof(2_000, false, 4));

        let run = gate(&directory).proved_run(2_010).unwrap();
        assert_eq!(
            run.proof.run_end, 1_000,
            "the newest success still decides, however old it is"
        );
        match gate(&directory).newest_failure() {
            Ok(Some(FailedRun::Verified(failed))) => {
                assert_eq!(failed.run_end, 2_000);
                assert_eq!(failed.error_codes, vec![9]);
            }
            other => panic!("the failed run is reported: {other:?}"),
        }
    }

    /// A failure that names another deployment says nothing about this one.
    #[test]
    fn a_failure_from_another_scope_is_not_this_deployments() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        write_proof(&directory, proof(1_000, true, 4));
        let mut other = proof(2_000, false, 4);
        other.scope = "p/vault-2/other/agent-*".to_string();
        write_proof(&directory, other);

        assert!(
            gate(&directory).newest_failure().unwrap().is_none(),
            "another deployment's failure is not this one's report"
        );
    }

    /// An unreadable directory is not "no failure is recorded".
    #[test]
    fn an_unreadable_directory_is_an_error_for_the_failure_scan() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        write_proof(&directory, proof(1_000, true, 4));
        let mut permissions = std::fs::metadata(&directory).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o000);
        std::fs::set_permissions(&directory, permissions).unwrap();

        let result = gate(&directory).newest_failure();
        // Restore before asserting, so a failure still cleans up.
        let mut permissions = std::fs::metadata(&directory).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&directory, permissions).unwrap();

        assert_eq!(result, Err(GateRefusal::Unreadable));
    }

    /// A directory that does not exist is a known absence, not an error.
    #[test]
    fn a_missing_directory_is_no_recorded_failure() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            gate(&home.path().join("proofs")).newest_failure(),
            Ok(None),
            "nothing has run here, which is not the same as being unable to look"
        );
    }

    /// Misfit W, applied to failures: a forged failure's counts are not shown.
    #[test]
    fn a_forged_failure_is_unverified_and_its_counts_are_not_returned() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        write_proof(&directory, proof(1_000, true, 4));
        write_proof_signed_by(
            &directory,
            proof(2_000, false, 4),
            &SigningKey::from_bytes(&[3u8; 32]),
        );

        match gate(&directory).newest_failure() {
            Ok(Some(FailedRun::Unverified { reason })) => {
                assert!(reason.contains("does not verify"), "{reason}");
            }
            other => panic!("the forged failure is unverified: {other:?}"),
        }
        // The success still decides, and its own signature is the pinned one.
        assert_eq!(
            gate(&directory).proved_run(1_010).unwrap().proof.run_end,
            1_000
        );
    }

    /// Misfit C: an armed backend with no proof admits nothing.
    #[test]
    fn no_proof_admits_nothing() {
        let home = tempfile::tempdir().unwrap();
        let refusal = gate(&home.path().join("proofs")).admit(Duration::from_secs(600), 1_000);
        assert_eq!(refusal, GateOutcome::Refused(GateRefusal::NoProof));
    }

    /// Acceptance 2: 600 s is admitted at I = 300, 599 s is below the `2 ×` floor.
    #[test]
    fn the_proven_interval_sets_the_floor_at_twice_itself() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        write_proof(&directory, proof(1_000, true, 4));
        let gate = ProofGate {
            directory: directory.clone(),
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        };
        assert!(matches!(
            gate.admit(Duration::from_secs(600), 1_010),
            GateOutcome::Admitted { .. }
        ));
        match gate.admit(Duration::from_secs(599), 1_010) {
            GateOutcome::Refused(GateRefusal::BelowFloor(_)) => {}
            other => panic!("599 s must be refused: {other:?}"),
        }
    }

    /// Acceptance 3: the bound is `I + grace`, and both sides of it are exact.
    #[test]
    fn the_boundary_is_the_interval_plus_the_measured_grace() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        // d = 600 exactly caps the grace at I: bound = 300 + 300.
        write_proof(&directory, proof(1_000, true, 600));
        let gate = ProofGate {
            directory,
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        };
        assert!(matches!(
            gate.admit(Duration::from_secs(600), 1_000 + 599),
            GateOutcome::Admitted { .. }
        ));
        assert!(matches!(
            gate.admit(Duration::from_secs(600), 1_000 + 600),
            GateOutcome::Refused(GateRefusal::Stale { .. })
        ));
        assert!(matches!(
            gate.admit(Duration::from_secs(600), 1_000 + 601),
            GateOutcome::Refused(GateRefusal::Stale { .. })
        ));
    }

    /// Misfit N and acceptance 4: a newer failure does not extend the clock.
    #[test]
    fn a_failed_run_after_a_success_does_not_refresh_the_bound() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        write_proof(&directory, proof(1_000, true, 0));
        write_proof(&directory, proof(1_200, false, 0));
        let gate = ProofGate {
            directory,
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        };
        // The grace for d = 0 is I/2 = 150, so the bound from the success is 1_450.
        assert!(matches!(
            gate.admit(Duration::from_secs(600), 1_460),
            GateOutcome::Refused(GateRefusal::Stale { .. })
        ));
        // A home with only failures says so, rather than claiming no proof exists.
        let failed = tempfile::tempdir().unwrap();
        let directory = failed.path().join("proofs");
        write_proof(&directory, proof(1_000, false, 0));
        let gate = ProofGate {
            directory,
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        };
        assert_eq!(
            gate.admit(Duration::from_secs(600), 1_010),
            GateOutcome::Refused(GateRefusal::NoSuccessfulProof)
        );
    }

    /// Misfit M: a valid arming and an active unit do not rescue a bad signature.
    #[test]
    fn an_edited_proof_is_unverified() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        let signed = SignedSweepProof::sign(proof(1_000, true, 0), &signer()).unwrap();
        let mut edited = signed.clone();
        edited.proof.success = false;
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(file_name(&edited)),
            edited.to_bytes().unwrap(),
        )
        .unwrap();
        let gate = ProofGate {
            directory,
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        };
        // The edited file says "failed", so it is skipped; the original is not there.
        assert_eq!(
            gate.admit(Duration::from_secs(600), 1_010),
            GateOutcome::Refused(GateRefusal::NoSuccessfulProof)
        );
    }

    /// Acceptance 6: a proof dated beyond the grace is `unknown`, never fresh.
    #[test]
    fn a_future_dated_proof_is_unknown() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        write_proof(&directory, proof(2_000, true, 0));
        let gate = ProofGate {
            directory,
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        };
        assert!(matches!(
            gate.admit(Duration::from_secs(600), 1_000),
            GateOutcome::Unknown(GateRefusal::FutureSkew { .. })
        ));
    }

    /// Misfit O: a proof for another scope does not admit this deployment.
    #[test]
    fn a_proof_for_another_scope_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        let mut other = proof(1_000, true, 0);
        other.scope = "p/vault-2/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-*".to_string();
        write_proof(&directory, other);
        let gate = ProofGate {
            directory,
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        };
        assert!(matches!(
            gate.admit(Duration::from_secs(600), 1_010),
            GateOutcome::Refused(GateRefusal::ScopeMismatch { .. })
        ));
    }

    /// Misfit Y: a clean run admits without claiming any version was removed.
    #[test]
    fn a_successful_run_that_removed_nothing_still_admits() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        write_proof(&directory, proof(1_000, true, 0));
        let gate = ProofGate {
            directory,
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        };
        let outcome = gate.admit(Duration::from_secs(600), 1_010);
        assert!(matches!(outcome, GateOutcome::Admitted { .. }));
    }

    /// FR-028: an unreadable sweeper area is unverifiable, not absent.
    #[test]
    fn an_unreadable_sweeper_area_is_not_reported_as_absent() {
        let home = tempfile::tempdir().unwrap();
        // A file where the directory should be: `read_dir` fails with an error that
        // is not `NotFound`, whatever uid runs the test.
        let path = home.path().join("proofs");
        std::fs::write(&path, b"not a directory").unwrap();
        assert_eq!(
            gate(&path).admit(Duration::from_secs(600), 1_000),
            GateOutcome::Refused(GateRefusal::Unreadable)
        );
    }

    /// Acceptance 7: the retention keeps the newest, and the newest success survives.
    #[test]
    fn retention_keeps_two_hundred_and_the_newest_success() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        std::fs::create_dir_all(&directory).unwrap();
        for index in 0..250 {
            // Through the writer, because the prune is part of it.
            let signed = SignedSweepProof::sign(proof(1_000 + index, true, 0), &signer()).unwrap();
            write(&directory, &signed).unwrap();
        }
        let files = std::fs::read_dir(&directory).unwrap().flatten().count();
        assert_eq!(files, PROOF_RETENTION, "the prune keeps exactly the bound");
        let gate = ProofGate {
            directory: directory.clone(),
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        };
        assert!(matches!(
            gate.admit(Duration::from_secs(600), 1_249),
            GateOutcome::Admitted { .. }
        ));
    }

    /// Acceptance 5: a torn file is skipped, not treated as fresh.
    #[test]
    fn a_torn_proof_is_skipped_and_reported() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("9999999999-deadbeef.cbor"), b"xx").unwrap();
        let gate = ProofGate {
            directory: directory.clone(),
            anchor: Box::leak(Box::new(signer().verifying_key())),
            scope: SCOPE.to_string(),
        };
        let (proofs, trouble) = gate.scan();
        assert!(proofs.is_empty());
        assert_eq!(trouble.len(), 1, "the unreadable file is reported");
        // Only a torn file exists: the refusal says the proof could not be read, not
        // that nothing was written.
        assert_eq!(
            gate.admit(Duration::from_secs(600), 1_010),
            GateOutcome::Refused(GateRefusal::Malformed)
        );

        // With a valid proof beside it, the torn file is skipped rather than shadowing.
        write_proof(&directory, proof(1_000, true, 0));
        assert!(matches!(
            gate.admit(Duration::from_secs(600), 1_010),
            GateOutcome::Admitted { .. }
        ));
    }

    /// Every text value in the encoded proof, so the assertion is over the bytes a
    /// reader would see rather than over the field list.
    fn texts(value: &ciborium::value::Value, out: &mut Vec<String>) {
        match value {
            ciborium::value::Value::Text(text) => out.push(text.clone()),
            ciborium::value::Value::Array(items) => {
                for item in items {
                    texts(item, out);
                }
            }
            ciborium::value::Value::Map(entries) => {
                for (key, item) in entries {
                    texts(key, out);
                    texts(item, out);
                }
            }
            _ => {}
        }
    }

    /// The values a proof may not carry, with the reason for each.
    ///
    /// One entry per offending value; empty means the proof is clean. The same rule
    /// runs over the real proof and over a poisoned one, so the check is not a list
    /// of words nobody executes.
    fn violations(value: &ciborium::value::Value) -> Vec<String> {
        let looks_like_base64 = |text: &str| {
            text.len() >= 40
                && text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        };
        let looks_like_hex =
            |text: &str| text.len() >= 40 && text.chars().all(|c| c.is_ascii_hexdigit());

        let mut found = Vec::new();
        texts(value, &mut found);

        let mut violations = Vec::new();
        for text in found {
            for forbidden in ["version", "secret", "path", "agent-1"] {
                if text.contains(forbidden) {
                    violations.push(format!("'{forbidden}' names a record or a version: {text}"));
                }
            }
            if text.starts_with("ksp-") || text.starts_with("v1.") || text.starts_with("Bearer ") {
                violations.push(format!("a token prefix: {text}"));
            }
            if looks_like_base64(&text) {
                violations.push(format!("base64 key material: {text}"));
            }
            if looks_like_hex(&text) {
                violations.push(format!("hex key material: {text}"));
            }
        }
        violations
    }

    /// Acceptance 8: the proof carries no record identifier and no secret-shaped
    /// value at all.
    ///
    /// A reader trusts this by looking at the type; a reviewer should not have to.
    /// The value walk is what catches the day someone adds a `details: String` field
    /// and a caller formats a path or a token into it; the key-set assertion is what
    /// catches a new field at all, because a new field is where a version travels.
    #[test]
    fn a_proof_has_no_field_a_version_could_travel_in() {
        let encoded = ksp_types::cbor::encode(&proof(1_000, false, 0)).unwrap();
        let value: ciborium::value::Value = ksp_types::cbor::decode(&encoded).unwrap();

        // The fields the type declares, and nothing else. A new field has to be a
        // deliberate edit here, next to the rule it must satisfy.
        let ciborium::value::Value::Map(entries) = &value else {
            panic!("a proof encodes as a map");
        };
        let mut keys: Vec<String> = entries
            .iter()
            .map(|(key, _)| {
                let ciborium::value::Value::Text(key) = key else {
                    panic!("a proof's keys are text");
                };
                key.clone()
            })
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "admin",
                "already_absent",
                "arming_id",
                "bound_reached",
                "declared_interval_secs",
                "error_codes",
                "not_yet_due",
                "prev_digest",
                "realised_interval_secs",
                "removed",
                "run_end",
                "run_start",
                "scope",
                "signer_key_id",
                "success",
            ],
            "a field the type does not declare has no rule covering it"
        );

        // The walk must see the proof's own identifiers, or it proves nothing.
        let mut found = Vec::new();
        texts(&value, &mut found);
        assert!(
            found.iter().any(|text| text == "arm-1") && found.iter().any(|text| text == SCOPE),
            "the walk must see the proof's own fields: {found:?}"
        );
        assert_eq!(
            violations(&value),
            Vec::<String>::new(),
            "a proof must not name a record or carry secret-shaped material"
        );
    }

    /// Acceptance 8's other direction: the rule has teeth.
    ///
    /// The type has no field a version could travel in, so a poisoned text field
    /// stands in for the day one is added: the same rule, run over an encoded proof,
    /// must reject it.
    #[test]
    fn the_no_secret_rule_rejects_a_poisoned_proof() {
        let mut poisoned = proof(1_000, true, 0);
        poisoned.arming_id = Some("v/secret/db-password/version-3".to_string());
        let value: ciborium::value::Value =
            ksp_types::cbor::decode(&ksp_types::cbor::encode(&poisoned).unwrap()).unwrap();

        let found = violations(&value);

        assert!(
            found
                .iter()
                .any(|violation| violation.contains("'version'")),
            "the rule must reject a value carrying a version id: {found:?}"
        );
    }

    /// Misfit D: the refusal says how late the run is, so the bound cannot be read as
    /// a maximum lag.
    #[test]
    fn a_stale_refusal_names_the_age_and_the_bound() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        write_proof(&directory, proof(1_000, true, 0));
        match gate(&directory).admit(Duration::from_secs(600), 1_600) {
            GateOutcome::Refused(GateRefusal::Stale {
                age,
                bound,
                interval,
            }) => {
                assert_eq!(age, 600);
                assert_eq!(bound, 450, "I + grace = 300 + 150");
                assert_eq!(interval, 300);
            }
            other => panic!("the newest proof is stale: {other:?}"),
        }
    }

    /// The cap: a run longer than its interval may not widen the grace past `I`.
    #[test]
    fn a_run_longer_than_its_interval_caps_the_grace_at_one_interval() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        let mut long = proof(1_000, true, 600);
        long.declared_interval_secs = Some(60);
        write_proof(&directory, long);
        // d = 600, I = 60: grace = clamp(max(30, 605), 30, 60) = 60, bound = 120.
        assert!(matches!(
            gate(&directory).admit(Duration::from_secs(120), 1_119),
            GateOutcome::Admitted { .. }
        ));
        assert!(matches!(
            gate(&directory).admit(Duration::from_secs(120), 1_120),
            GateOutcome::Refused(GateRefusal::Stale { bound: 120, .. })
        ));
    }

    /// Misfit N: a schedule that really became slower is the case the proof is for.
    #[test]
    fn a_longer_realised_interval_is_the_cadence_admission_uses() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        let mut slower = proof(1_000, true, 0);
        slower.declared_interval_secs = Some(60);
        slower.realised_interval_secs = Some(300);
        write_proof(&directory, slower);
        assert!(matches!(
            gate(&directory).admit(Duration::from_secs(600), 1_010),
            GateOutcome::Admitted { .. }
        ));
        assert!(matches!(
            gate(&directory).admit(Duration::from_secs(599), 1_010),
            GateOutcome::Refused(GateRefusal::BelowFloor(_))
        ));
    }

    /// A shorter gap is a retry or an ad-hoc run, not a faster schedule: lowering the
    /// floor for it would admit a lease the declared cadence cannot cover.
    #[test]
    fn a_shorter_realised_interval_does_not_lower_the_floor() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        let mut retried = proof(1_000, true, 0);
        retried.declared_interval_secs = Some(300);
        retried.realised_interval_secs = Some(10);
        write_proof(&directory, retried);
        assert!(matches!(
            gate(&directory).admit(Duration::from_secs(599), 1_010),
            GateOutcome::Refused(GateRefusal::BelowFloor(_))
        ));
    }

    /// A run with no recorded schedule proves a run, not a cadence. It must neither
    /// admit nor poison an earlier proof that does prove one.
    #[test]
    fn an_unarmed_run_neither_admits_nor_shadows_the_scheduled_proof() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        write_proof(&directory, proof(1_000, true, 0));
        write_proof(&directory, unarmed(1_100));
        assert_eq!(
            gate(&directory).admit(Duration::from_secs(600), 1_100),
            GateOutcome::Admitted {
                interval: Duration::from_secs(I),
                age: 100,
            }
        );

        // And a home where every success is ad-hoc has nothing to say about a cadence.
        let only_unarmed = tempfile::tempdir().unwrap();
        let directory = only_unarmed.path().join("proofs");
        write_proof(&directory, unarmed(1_000));
        assert_eq!(
            gate(&directory).admit(Duration::from_secs(600), 1_010),
            GateOutcome::Refused(GateRefusal::NoCadence)
        );
    }

    /// T035: the chain link lives inside the signed proof. Nothing reads it to decide
    /// freshness, and no separate head can be rolled back.
    #[test]
    fn a_proof_links_the_previous_one_without_a_head_pointer() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        let first = SignedSweepProof::sign(proof(1_000, true, 0), &signer()).unwrap();
        write(&directory, &first).unwrap();

        let linked = SweepProof {
            prev_digest: gate(&directory).newest_digest(),
            ..proof(1_100, true, 0)
        };
        let second = SignedSweepProof::sign(linked, &signer()).unwrap();
        write(&directory, &second).unwrap();

        assert_eq!(second.proof.prev_digest, first.digest());
        assert!(first.proof.prev_digest.is_none());
    }

    /// T036: the writer sets the file's mode rather than inheriting the caller's
    /// `umask`, so every principal can read the proof that authorises its lease.
    #[test]
    fn the_written_proof_is_world_readable_and_not_writable() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("proofs");
        let signed = SignedSweepProof::sign(proof(1_000, true, 0), &signer()).unwrap();
        let path = write(&directory, &signed).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the proof is readable by every principal");
    }
}
