//! `ksp audit verify`: every record checked against public pins, and no claim
//! beyond what the log can prove.
//!
//! # Where the keys come from
//!
//! From the pins, never from the log: the admin anchor, the user policy the admin
//! signed, and the enrolment records this host pinned (FR-048). The record's own
//! `signer_key_id` is matched *against* those pins and is never used to fetch a key
//! — a verifier that reads the key out of the artifact it checks answers its own
//! question (Misfit W).
//!
//! # What it will not say
//!
//! A chain that verifies proves authorship, not coverage: deleting the tail leaves
//! a shorter valid chain. Without a head digest kept outside the log the only
//! honest word is `unknown`, and this module never prints "valid" or "complete"
//! (FR-051). Verification is read-only: nothing here writes, repairs or re-signs
//! (FR-054).

use std::io::Write;
use std::path::Path;

use ksp_deletion::{AuditChain, PinRole, PinStatus, PinnedKey, Pins, VerifyReport, verify_segment};
use ksp_types::PrincipalId;

use crate::config::Layout;
use crate::exit::{self, Outcome};
use crate::output::{Emitter, FirstView, HeadView, Report, VerifyView};

/// The sentence a run without an external head must print.
const NO_HEAD: &str = "completeness unknown: no head digest was supplied from outside the log, so a \
                       deleted tail verifies exactly like a whole one";

/// What the caller supplied on the command line.
pub struct Verify<'a> {
    /// Head digests recorded outside the log, in lowercase hex.
    pub heads: &'a [String],
}

/// Why verification could not run at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// This host has no deployment, so there is nothing to verify against.
    #[error("this host has no deployment to verify against")]
    NotProvisioned,
    /// Pinned public material could not be read.
    #[error("pinned public material could not be read: {0}")]
    Pins(String),
    /// The log could not be read, so the verification is incomplete.
    #[error("the audit log could not be read: {0}")]
    Log(String),
}

impl VerifyError {
    /// The exit class this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            // Nothing to verify against is a missing key-material class, not a
            // verdict about the log.
            Self::NotProvisioned | Self::Pins(_) => exit::MISSING_KEY,
            // A log that could not be read is unverified, never valid.
            Self::Log(_) => exit::AUDIT_UNVERIFIED,
        }
    }
}

/// Verify the log against the pins and report it.
pub fn run<W: Write>(layout: &Layout, verify: Verify<'_>, emitter: &mut Emitter<W>) -> Outcome {
    let (pins, policy_pinned) = match pins(layout) {
        Ok(pins) => pins,
        Err(error) => {
            let _ = emitter.refusal(&error.to_string());
            return Outcome::Failed(error.exit_code());
        }
    };

    let read = match walk(layout, &pins) {
        Ok(read) => read,
        Err(error) => {
            let _ = emitter.refusal(&error.to_string());
            return Outcome::Failed(error.exit_code());
        }
    };

    // The revisions that withdrew a grant, for the note that explains the count.
    let revoked = pins
        .keys()
        .iter()
        .filter_map(|key| match key.status {
            PinStatus::Revoked {
                policy_revision,
                at,
            } => Some((policy_revision, at)),
            PinStatus::Current => None,
        })
        .collect::<Vec<_>>();
    let view = read.view(verify.heads, &revoked, policy_pinned);
    // A revoked signer still verifies: the authority is gone, the signature is not
    // a forgery. It is reported and does not fail the run.
    let sound = view.valid + view.revoked == view.records
        && view.broken.is_none()
        && view.torn_tail.is_none()
        && view.unreadable == 0
        && view.matched_heads.len() == view.heads_supplied;

    match emitter.report(&Report::Verify(view)) {
        Ok(()) if sound => Outcome::Success,
        Ok(()) => Outcome::Failed(exit::AUDIT_UNVERIFIED),
        Err(_) => Outcome::Failed(exit::INTERNAL),
    }
}

/// The heads of every chain, for `ksp status`.
///
/// The same walk `audit verify` runs, reduced to what a disclosure needs: a head is
/// only named for a chain this host could verify, and a walk that could not run says
/// why rather than printing a digest nobody checked.
pub struct ChainHeads {
    /// One head per chain that reached a record.
    pub chains: Vec<HeadView>,
    /// Records the walk verified.
    pub records: usize,
    /// Segments it walked.
    pub segments: usize,
    /// Entries it could not read.
    pub unreadable: usize,
    /// Records that verified against no pinned key, or against one that may not sign
    /// them, so the chain's head ends a chain this host cannot fully attribute.
    pub unattributed: usize,
    /// The first chain that does not reach a head, when one does not.
    pub broken: Option<String>,
    /// Why no head could be read at all.
    pub reason: Option<String>,
}

/// Read the audit heads, or the reason there are none.
pub fn heads(layout: &Layout) -> ChainHeads {
    let unknown = |reason: String| ChainHeads {
        chains: Vec::new(),
        records: 0,
        segments: 0,
        unreadable: 0,
        unattributed: 0,
        broken: None,
        reason: Some(reason),
    };
    // `pins` reports every deployment problem as "not provisioned"; a corrupt record
    // is not an absent one, and status has to say which it is.
    if let Err(error) = crate::deployment::require(layout) {
        return unknown(match error {
            crate::keys::PinError::Absent => {
                "this host has no deployment to verify against".to_string()
            }
            _ => "the deployment record could not be read as this host's, so no pin is trusted"
                .to_string(),
        });
    }
    let resolved = match pins(layout) {
        Ok((resolved, _)) => resolved,
        Err(error) => return unknown(error.to_string()),
    };
    match walk(layout, &resolved) {
        Ok(read) => {
            // A walk that verified nothing because it could read nothing is not an
            // empty log. `unreadable` alone cannot say that: a healthy two-account
            // walk reports a sibling's chain as out of scope, and that is not a
            // reason to withhold the head this caller did verify. What is a reason
            // is no records *and* something unreadable.
            let reason = (read.records == 0 && read.heads.is_empty() && read.unreadable > 0)
                .then(|| "the audit log could not be read, so no head was verified".to_string());
            ChainHeads {
                chains: read.heads,
                records: read.records,
                segments: read.segments,
                unreadable: read.unreadable,
                unattributed: read.counts.unpinned + read.counts.mismatch + read.counts.invalid,
                broken: read.broken,
                reason,
            }
        }
        Err(error) => unknown(error.to_string()),
    }
}

/// The public material verification resolves against.
///
/// The admin anchor is the root. The user's key comes from the policy, which is
/// only used once the admin's signature over it verifies — otherwise a policy file
/// an attacker could write would pin the attacker's key. Enrolment records are
/// pins in their own right: the operator read their fingerprints out of band, and
/// the file mode is what protects them.
fn pins(layout: &Layout) -> Result<(Pins, bool), VerifyError> {
    let (deployment, anchor) =
        crate::deployment::require(layout).map_err(|_| VerifyError::NotProvisioned)?;
    let admin_key = ed25519_dalek::VerifyingKey::from_bytes(&anchor.key.to_bytes())
        .map_err(|_| VerifyError::Pins("the pinned admin key is not a valid key".to_string()))?;
    let mut keys = vec![PinnedKey {
        key_id: anchor.key_id.as_str().to_string(),
        key: admin_key,
        principal: Some(deployment.admin),
        role: PinRole::Admin,
        status: PinStatus::Current,
    }];

    // A policy is this deployment's only when the admin signed it *and* it names
    // this vault and this tenant: an authentic policy for another deployment would
    // otherwise pin a stranger's key under the tenant's principal.
    let policy = crate::admin::read_policy(layout).ok().filter(|policy| {
        policy.verify_issuer(&anchor.key)
            && policy.vault() == &deployment.vault
            && policy.user() == &deployment.user
    });
    if let Some(policy) = &policy {
        let trusted = policy.trusted();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&trusted.signing_key.to_bytes())
            .map_err(|_| VerifyError::Pins("the pinned user key is not a valid key".to_string()))?;
        keys.push(PinnedKey {
            key_id: trusted.signing_key_id.as_str().to_string(),
            key,
            principal: Some(*policy.user()),
            role: PinRole::User,
            status: PinStatus::Current,
        });
    }

    // A withdrawal is the only evidence that a grant is gone: an agent that was
    // never shared with looks identical to one whose grant was withdrawn, so
    // absence from the policy is not used.
    // A ledger that cannot be read cannot rule a withdrawal out. Reporting every
    // agent as current on the strength of a file this run could not parse would be
    // the one claim verification must never make, so the run refuses instead.
    // From the deployment record, which this run already holds: the record names both
    // principals, so there is nothing to discover and nothing to fail on before the
    // ledger read itself. A missing policy is then reported as a missing policy rather
    // than as a registry this command never needed.
    let withdrawals = crate::ledgers::LedgerPaths::for_deployment(layout, &deployment)
        .as_ledger()
        .withdrawals()
        .map_err(|error| {
            VerifyError::Pins(format!(
                "the issuance ledger could not be read, so a withdrawn grant cannot be ruled \
                 out: {error}"
            ))
        })?;

    let entries = match std::fs::read_dir(layout.enrolments_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Pins::new(keys), policy.is_some()));
        }
        Err(_) => {
            return Err(VerifyError::Pins(
                "the enrolment pins could not be read".to_string(),
            ));
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(stored) = crate::keys::StoredEnrolment::load(&path) else {
            // A pin this host cannot read is not silently skipped: verification
            // would then call its records unpinned for the wrong reason.
            return Err(VerifyError::Pins(format!(
                "{} is not a readable enrolment pin",
                path.display()
            )));
        };
        let key = ed25519_dalek::VerifyingKey::from_bytes(&stored.signing_key.to_bytes())
            .map_err(|_| VerifyError::Pins("an enrolment pin is not a valid key".to_string()))?;
        let identity = stored.identity.principal();
        let status = withdrawals
            .iter()
            .find(|withdrawal| {
                withdrawal.withdrawal == ksp_identity::Withdrawal::Agent(stored.identity)
            })
            .map_or(PinStatus::Current, |withdrawal| PinStatus::Revoked {
                policy_revision: withdrawal.policy_revision,
                at: u64::try_from(withdrawal.at).ok(),
            });
        keys.push(PinnedKey {
            key_id: stored.signing_key_id.as_str().to_string(),
            key,
            principal: Some(identity),
            role: PinRole::Agent,
            status,
        });
    }

    let policy_pinned = policy.is_some();
    Ok((Pins::new(keys), policy_pinned))
}

/// What the walk over every segment found.
struct Read {
    segments: usize,
    records: usize,
    counts: ksp_deletion::VerifyCounts,
    broken: Option<String>,
    torn_tail: Option<usize>,
    unreadable: usize,
    trouble: Vec<String>,
    heads: Vec<HeadView>,
    first: Vec<FirstView>,
}

impl Read {
    /// Turn the walk into the reported view, comparing any supplied heads.
    fn view(
        self,
        supplied: &[String],
        revoked: &[(u64, Option<u64>)],
        policy_pinned: bool,
    ) -> VerifyView {
        let mut matched = Vec::new();
        let mut unmatched = Vec::new();
        for expected in supplied {
            let expected = expected.trim().to_ascii_lowercase();
            match self
                .heads
                .iter()
                .find(|head| head.digest.eq_ignore_ascii_case(&expected))
            {
                Some(head) => matched.push(head.clone()),
                None => unmatched.push(expected),
            }
        }

        let completeness = if supplied.is_empty() {
            NO_HEAD.to_string()
        } else if unmatched.is_empty() && (self.broken.is_some() || self.torn_tail.is_some()) {
            // The head matched the last record the walk reached, which is not the
            // last record the log holds: a broken or torn chain cannot establish
            // coverage even against a supplied head.
            "a supplied head matches the last record this run could reach, but the chain is broken \
             or torn, so completeness cannot be established"
                .to_string()
        } else if unmatched.is_empty() {
            format!(
                "the log ends at the supplied head for {} chain(s); a tail removed before that head \
                 was recorded would still match, and a copy that never reached this host is not \
                 covered",
                matched.len()
            )
        } else {
            format!(
                "head mismatch: no chain ends at {}; completeness cannot be established",
                unmatched.join(", ")
            )
        };

        let mut notes = vec![completeness.clone()];
        if self.counts.revoked > 0 {
            let revisions = revoked
                .iter()
                .map(|(revision, at)| match at {
                    Some(at) => format!("revision {revision} at {at}"),
                    None => format!("revision {revision}"),
                })
                .collect::<Vec<_>>()
                .join(", ");
            notes.push(format!(
                "{} record(s) were signed by a key whose grant was withdrawn ({revisions}); a \
                 signature that verifies is not a current authority, and these are not equivalent \
                 to current ones",
                self.counts.revoked
            ));
        }
        if self.counts.unpinned > 0 {
            if !policy_pinned {
                notes.push(
                    "no policy signed by the admin is present, so the user's signing key is not \
                     pinned here; its records are reported unpinned"
                        .to_string(),
                );
            }
            notes.push(
                "a key retired by rotation is not kept as public material on this host, so its \
                 signatures are reported unpinned here rather than archived"
                    .to_string(),
            );
        }
        if self.unreadable > 0 {
            notes.push(format!(
                "{} entr(ies) could not be read, so this run did not check every record",
                self.unreadable
            ));
        }
        notes.push(
            "a record that verifies is the writer's claim at the time it wrote; an absent record is \
             not evidence that an operation did not happen"
                .to_string(),
        );

        VerifyView {
            segments: self.segments,
            records: self.records,
            valid: self.counts.verified.saturating_sub(self.counts.revoked),
            revoked: self.counts.revoked,
            unpinned: self.counts.unpinned,
            mismatch: self.counts.mismatch,
            invalid: self.counts.invalid,
            broken: self.broken,
            torn_tail: self.torn_tail,
            unreadable: self.unreadable,
            trouble: self.trouble,
            heads: self.heads,
            heads_supplied: supplied.len(),
            matched_heads: matched,
            first: self.first,
            completeness,
            notes,
        }
    }
}

/// Walk every actor directory and every segment in it.
fn walk(layout: &Layout, pins: &Pins) -> Result<Read, VerifyError> {
    let chain = AuditChain::new(layout.audit_root());
    let mut read = Read {
        segments: 0,
        records: 0,
        counts: ksp_deletion::VerifyCounts::default(),
        broken: None,
        torn_tail: None,
        unreadable: 0,
        trouble: Vec::new(),
        heads: Vec::new(),
        first: Vec::new(),
    };

    // The audit root is `0711`: every principal traverses it, and none may list
    // it. So the walk has two sources, and neither may be silent — the listing
    // where this caller can list, and the writers the deployment names, whose
    // directories it may or may not be able to open.
    let mut directories = match std::fs::read_dir(layout.audit_root()) {
        Ok(actors) => actors
            .flatten()
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        // A host that never wrote a record has no log, which is an empty
        // verification rather than a failure.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(read),
        Err(error) => {
            let known = crate::audit_view::known_principals(layout);
            if known.is_empty() {
                // No listing and no deployment: there is nothing to walk and no
                // way to name what was missed, so this is a failure rather than a
                // clean empty report.
                return Err(VerifyError::Log(error.to_string()));
            }
            Vec::new()
        }
    };
    for principal in crate::audit_view::known_principals(layout) {
        let directory = chain.writer_root(principal);
        if !directories.contains(&directory) {
            directories.push(directory);
        }
    }
    directories.sort();

    for directory in directories {
        let Some(actor) = directory
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| PrincipalId::parse(name).ok())
        else {
            unreadable(layout, &mut read, &directory);
            continue;
        };
        let labels = match chain.labels(actor) {
            Ok(labels) => labels,
            Err(error) => {
                // One directory this run cannot list must not hide the segments it
                // can: count it, name it, and keep walking.
                unreadable_chain(layout, &mut read, &directory, &error);
                continue;
            }
        };
        for label in labels {
            read.segments += 1;
            let reader = match chain.reader(actor, &label) {
                Ok(Some(reader)) => reader,
                Ok(None) => {
                    // A segment that vanished between listing and opening: the
                    // verification did not see it, and saying so is the honest
                    // answer rather than a shorter clean run.
                    unreadable(layout, &mut read, &chain.segment(actor, &label));
                    continue;
                }
                Err(error) => {
                    read.unreadable += 1;
                    read.trouble.push(format!(
                        "{}: {error}",
                        relative(layout, &chain.segment(actor, &label))
                    ));
                    continue;
                }
            };
            let report = match verify_segment(reader, pins) {
                Ok(report) => report,
                Err(error) => {
                    // A segment this run cannot read is counted, not fatal: the
                    // segments it can read still answer for themselves.
                    read.unreadable += 1;
                    read.trouble.push(format!(
                        "{}: {error}",
                        relative(layout, &chain.segment(actor, &label))
                    ));
                    continue;
                }
            };
            merge(&mut read, actor, &label, report);
        }
    }
    Ok(read)
}

/// Fold one segment's report into the run's totals.
fn merge(read: &mut Read, actor: PrincipalId, label: &str, report: VerifyReport) {
    // The verified signer names the chain; the file name is only a path.
    let chain = format!(
        "{actor}/{}",
        report.chain_signer.as_deref().unwrap_or(label)
    );
    read.records += report.records;
    read.counts.verified += report.counts.verified;
    read.counts.revoked += report.counts.revoked;
    read.counts.unpinned += report.counts.unpinned;
    read.counts.mismatch += report.counts.mismatch;
    read.counts.invalid += report.counts.invalid;
    if read.broken.is_none()
        && let Some(broken) = report.broken
    {
        read.broken = Some(format!("{chain}: {}", broken.describe()));
    }
    if read.torn_tail.is_none()
        && let Some(index) = report.torn_tail_at
    {
        read.torn_tail = Some(index);
        read.trouble
            .push(format!("{chain}: a torn frame at index {index}"));
    }
    for (class, index) in [
        ("invalid", report.first_invalid),
        ("unpinned", report.first_unpinned),
        ("mismatch", report.first_mismatch),
        ("revoked", report.first_revoked),
    ] {
        if let Some(index) = index {
            read.first.push(FirstView {
                class: class.to_string(),
                chain: chain.clone(),
                index,
            });
        }
    }
    if let Some(head) = report.head {
        read.heads.push(HeadView {
            chain,
            digest: hex(&head),
        });
    }
}

/// Count one chain a caller could not open, or name it as another account's.
///
/// The audit root is `0711` and every writer directory is `0700` and its owner's,
/// so a walk from a principal's account is *supposed* to fail on a sibling's chain.
/// Counting that as an incomplete verification would give every principal a red log
/// on a healthy host. The distinction is ownership, not reachability: a chain whose
/// directory belongs to another account, walked by a caller that does not own the
/// audit root, is out of this caller's scope — named, not counted. The deployment's
/// own owner walks the whole log, and *their* unreadable chain is the finding
/// (exit 12) the admin report exists to make.
fn unreadable_chain(
    layout: &Layout,
    read: &mut Read,
    directory: &Path,
    error: &dyn std::fmt::Display,
) {
    use std::os::unix::fs::MetadataExt;

    let caller = ksp_posture::permissions::effective_uid();
    let owner = std::fs::symlink_metadata(directory)
        .map(|metadata| metadata.uid())
        .ok();
    let root_is_mine = std::fs::symlink_metadata(layout.audit_root())
        .map(|metadata| metadata.uid() == caller)
        .unwrap_or(false);
    if let Some(owner) = owner
        && owner != caller
        && !root_is_mine
    {
        read.trouble.push(format!(
            "{}: not this account's chain",
            relative(layout, directory)
        ));
        return;
    }
    read.unreadable += 1;
    read.trouble
        .push(format!("{}: {error}", relative(layout, directory)));
}

/// Count one entry that could not be read, and name it.
fn unreadable(layout: &Layout, read: &mut Read, path: &Path) {
    read.unreadable += 1;
    read.trouble.push(relative(layout, path));
}

/// A path relative to the home, so two hosts' output is comparable.
fn relative(layout: &Layout, path: &Path) -> String {
    path.strip_prefix(layout.root())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Lowercase hex, which is what an operator writes down and supplies back.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}
