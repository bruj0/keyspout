//! The `ksp` binary.
//!
//! One foreground invocation per operation. Nothing here listens, nothing here
//! persists state between runs, and every exit integer comes from
//! [`ksp::exit`].

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = ksp::commands::Cli::parse();

    // There is no default store when neither `KSP_HOME` nor `HOME` is set. The
    // refusal is emitted here rather than inside `dispatch`, because every
    // command needs a home before it can do anything and a store invented at the
    // working directory is the hazard `home_from_env` documents.
    let Some(home) = ksp::app::home_from_env() else {
        let mut stderr = ksp::output::Emitter::new(false, std::io::stderr());
        let _ = stderr.refusal(
            "no store location: neither KSP_HOME nor HOME is set, so ksp cannot name a \
             directory to read. Set KSP_HOME to an absolute path",
        );
        return ExitCode::from(u8::try_from(ksp::exit::MISSING_KEY).unwrap_or(1));
    };

    let outcome = ksp::app::dispatch(&cli, &home);

    // A refusal is never silent. The message names the exit code and nothing
    // else: the subsystem messages that could carry a value are deliberately not
    // printed here, and an unexplained non-zero exit is the one failure a caller
    // cannot act on.
    if let ksp::exit::Outcome::Failed(code) = outcome {
        // Through the emitter rather than a direct `eprintln!`: that is the one
        // place this binary writes, and it is where the rule about what may
        // appear in output is enforced.
        let mut stderr = ksp::output::Emitter::new(false, std::io::stderr());
        let _ = stderr.refusal(&format!(
            "refused (exit {code}: {})",
            ksp::exit::describe(code)
        ));
    }

    ExitCode::from(u8::try_from(outcome.code()).unwrap_or(1))
}
