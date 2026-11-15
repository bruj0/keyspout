//! The delivery half of `ksp run --consume`: confine, then launch.
//!
//! # Why this is a separate process
//!
//! `ksp run --consume` has to delete, journal and report *after* the child ran,
//! and a Landlock ruleset restricts the process that installs it — irreversibly,
//! and inherited by everything it forks. Delivering in that process would leave
//! the delete with no right to run. So the delivery happens here, in a process
//! whose only job is this, and the parent keeps its own filesystem rights.
//!
//! # The value arrives on stdin
//!
//! Not in argv, not in this process's environment, and not in a file. It is read,
//! handed to the child through the declared `--env` exception, and the buffer is
//! overwritten before this process exits.

use std::io::Read;

use zeroize::Zeroize;

use crate::commands::DeliverArgs;
use crate::exit::{self, Outcome};
use crate::process::ConfinedProcess;
use crate::run_gate::{ChildLauncher, Confiner};

/// Run one `ksp __deliver` invocation.
pub fn run(args: &DeliverArgs) -> Outcome {
    // Read before confining: after the ruleset is in force this process cannot
    // open anything it was not granted, and stdin is an inherited descriptor
    // either way — but reading first keeps the order clear.
    let mut value = Vec::new();
    if std::io::stdin().read_to_end(&mut value).is_err() {
        return Outcome::Failed(exit::MISSING_KEY);
    }

    let mut text = match String::from_utf8(std::mem::take(&mut value)) {
        Ok(text) => text,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Outcome::Failed(exit::MISSING_KEY);
        }
    };

    // The configuration is read here rather than passed in argv. `KSP_HOME` is
    // inherited from the parent, so this process resolves the same file with the
    // same function the parent used: the two cannot disagree about which adapter
    // confines, and a name in argv could not become a second source of truth for
    // a decision this process has to make itself anyway (it must still confirm
    // the host provides the mechanism before it relies on it).
    //
    // A child with no home cannot name the store, and delivering a value from a
    // store this process cannot locate is not a thing to guess at.
    let Some(home) = crate::app::home_from_env() else {
        text.zeroize();
        let _ = crate::output::Emitter::new(false, std::io::stderr()).refusal(
            "no store location: neither KSP_HOME nor HOME is set, so the child cannot be given \
             the store's path. Set KSP_HOME to an absolute path",
        );
        return Outcome::Failed(exit::MISSING_KEY);
    };
    let layout = crate::config::Layout::new(home);
    let configuration = match crate::establish::load(&layout) {
        Ok(configuration) => configuration,
        Err(refusal) => {
            text.zeroize();
            let _ =
                crate::output::Emitter::new(false, std::io::stderr()).refusal(&refusal.to_string());
            return Outcome::Failed(refusal.exit_code());
        }
    };
    let grant = match crate::establish::granted(
        configuration.as_ref(),
        ksp_types::HostCapability::PathConfinement,
    ) {
        Ok(grant) => grant,
        Err(refusal) => {
            text.zeroize();
            let _ =
                crate::output::Emitter::new(false, std::io::stderr()).refusal(&refusal.to_string());
            return Outcome::Failed(refusal.exit_code());
        }
    };

    // Confinement is required here for the same reason it is required in a
    // non-consume run: a delivery that cannot be confined must refuse rather
    // than produce an unconfined child that looks like a successful one. The
    // ruleset reaches the named level and nothing above it, which is why the
    // parent passes the directory instead of this process deriving one.
    //
    // An `optional` capability the host established nothing for runs unconfined;
    // the parent has already said so in its own output.
    let process = if grant.established() {
        match crate::establish::confinement(&grant) {
            Some(adapter) => ConfinedProcess::new(adapter),
            None => ConfinedProcess::unconfined(),
        }
    } else {
        // Selected, and it establishes nothing: the child runs unconfined, and
        // the parent has already said so (FR-036).
        ConfinedProcess::unconfined()
    };
    if let Err(refusal) = process.apply(&crate::run::confinement_for(
        &args.level,
        grant.requirement(),
    )) {
        // The refusal is the one exit that never hands the value over, so the
        // buffer is wiped here as well: this module promises the plaintext is
        // overwritten before the process ends, and a refusal is still an end.
        text.zeroize();
        let _ = crate::output::Emitter::new(false, std::io::stderr()).refusal(&refusal.to_string());
        return Outcome::Failed(exit::CAPABILITY_REFUSAL);
    }

    let environment = vec![(args.env.clone(), text)];
    match process.launch(&args.child, &environment) {
        // `launch` yields `Ok` only for a child that exited zero, and reports a
        // non-zero child as an error carrying its code.
        Ok(_) => Outcome::Success,
        Err(crate::run_gate::LaunchError::NonZero { code }) => Outcome::Failed(code),
        Err(_) => Outcome::Failed(exit::INTERNAL),
    }
}
