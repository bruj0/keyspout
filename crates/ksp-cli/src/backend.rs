//! `ksp backend`: what the selected store can do, and whether one lease fits.
//!
//! # Why `test` is a probe and not a promise
//!
//! `test` asks the admission gate the same question a mint asks, with the same
//! classification the mint would read: a lease of this length against this
//! backend. A refusal names the capability and the minimum the backend could
//! honour, because that is the number the operator has to change. It never says
//! anything about how long a copy survives after a delete — the system cannot
//! measure that, and a probe that claimed it would be inventing evidence.

use std::time::Duration;

use ksp_backend::admission::admit_at_gate;

use crate::commands::BackendCommand;
use crate::config::{self, Layout};
use crate::exit::{self, Outcome};
use crate::output::{BackendReport, Emitter, Report};

/// The backends this build can select, in the order they are described.
///
/// `file` and `valkey` are what the MVP admits; the rest of the storage research
/// refuses the others with evidence, so they are not offered as choices here.
const SELECTABLE: [&str; 2] = ["file", "valkey"];

/// Build the report for the selected backend.
fn describe(layout: &Layout, requested: Option<u64>) -> Result<(BackendReport, bool), ()> {
    let selection = config::read_backend(layout).map_err(|_| ())?;
    // The classification admission reads, not the configuration-only one: `file`
    // carries `None` by configuration and becomes `Scheduled` only once a signed
    // proof exists. Reading the other source here made `test` refuse a lease of a
    // length that `token mint` then admitted on the same host.
    let now = i64::try_from(crate::run::now_seconds()).unwrap_or(i64::MAX);
    let admission = crate::admission::classify(layout, &selection, now).map_err(|_| ())?;
    let classification = admission.classification;

    let mut report = BackendReport {
        backend: selection.name().to_string(),
        capability: format!("{:?}", classification.capability),
        mechanism: classification.mechanism.to_string(),
        declared_cadence_secs: classification.declared_cadence.map(|value| value.as_secs()),
        retention_secs: classification.retention.map(|value| value.as_secs()),
        requested_ttl_secs: requested,
        admitted: None,
        detail: format!(
            "selectable: {} (selected: {})",
            SELECTABLE.join(", "),
            selection.name()
        ),
    };

    let Some(ttl) = requested else {
        return Ok((report, true));
    };

    // The same gate a mint uses, so `test` cannot pass a lease that a mint then
    // refuses — and the refusal carries the backend's own reason.
    match admit_at_gate(&classification, Duration::from_secs(ttl)) {
        Ok(_) => {
            report.admitted = Some(true);
            report.detail =
                "the requested lease is admissible against this backend's classification"
                    .to_string();
            Ok((report, true))
        }
        Err(error) => {
            report.admitted = Some(false);
            report.detail = error.to_string();
            Ok((report, false))
        }
    }
}

/// Run one `ksp backend` subcommand.
pub fn run<W: std::io::Write>(
    command: &BackendCommand,
    layout: &Layout,
    emitter: &mut Emitter<W>,
) -> Outcome {
    if let BackendCommand::ArmSweep {
        kind,
        interval,
        scope,
        credential,
        grants,
        identifier,
        replace,
        query,
        user_arming,
        passphrase_file,
        install,
    } = command
    {
        return crate::arm::run(
            crate::arm::ArmRequest {
                user_signed: *user_arming,
                passphrase_file: passphrase_file.as_deref(),
                kind: kind.as_deref(),
                interval,
                scope,
                credential,
                grants,
                identifier: identifier.as_deref(),
                replace: *replace,
                query: *query,
                install: *install,
            },
            layout,
            emitter,
        );
    }

    let requested = match command {
        BackendCommand::List => None,
        // The default is the lease a mint would request with no `--ttl`: a
        // fifteen-minute delivery, which is short enough that a `file` backend's
        // refusal is about the mechanism rather than about the number.
        BackendCommand::Test { ttl } => Some(ttl.unwrap_or(900)),
        // Handled above: it records a schedule rather than describing a capability.
        BackendCommand::ArmSweep { .. } => None,
    };

    let (report, admitted) = match describe(layout, requested) {
        Ok(value) => value,
        Err(()) => return Outcome::Failed(exit::INTERNAL),
    };

    match emitter.report(&Report::Backend(report)) {
        // A refused lease is the capability refusal the caller has to see, and
        // printing the reason is the only way they can act on it.
        Ok(()) if admitted => Outcome::Success,
        Ok(()) => Outcome::Failed(exit::CAPABILITY_REFUSAL),
        Err(_) => Outcome::Failed(exit::INTERNAL),
    }
}
