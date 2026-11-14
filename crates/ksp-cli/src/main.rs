//! The `ksp` binary.
//!
//! One foreground invocation per operation. Nothing here listens, nothing here
//! persists state between runs, and every exit integer comes from
//! [`ksp_cli::exit`].

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = ksp_cli::commands::Cli::parse();
    let outcome = ksp_cli::app::dispatch(&cli, &ksp_cli::app::home_from_env());

    // A refusal is never silent. The message names the exit code and nothing
    // else: the subsystem messages that could carry a value are deliberately not
    // printed here, and an unexplained non-zero exit is the one failure a caller
    // cannot act on.
    if let ksp_cli::exit::Outcome::Failed(code) = outcome {
        // Through the emitter rather than a direct `eprintln!`: that is the one
        // place this binary writes, and it is where the rule about what may
        // appear in output is enforced.
        let mut stderr = ksp_cli::output::Emitter::new(false, std::io::stderr());
        let _ = stderr.refusal(&format!(
            "refused (exit {code}: {})",
            ksp_cli::exit::describe(code)
        ));
    }

    ExitCode::from(u8::try_from(outcome.code()).unwrap_or(1))
}
