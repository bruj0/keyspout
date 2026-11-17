//! A deployment with an admin and N user principals, built once for the suites
//! that need one.
//!
//! # Why a shared fixture
//!
//! Every later work package needs "an admin, two users, an agent and a shared
//! store". Built by hand, that shape is thirty lines of setup repeated per file,
//! and a change to the topology becomes thirty edits. One helper means the
//! topology has one statement in the tests, the way `Layout` is one statement of
//! it in the product.
//!
//! # What it does not do
//!
//! It does not create UNIX accounts, chown anything, or need root. The homes are
//! temporary directories owned by the invoking account, so the `file` boundary is
//! the same account in every home; the *topology* — one store, N homes, one
//! registry — is what this fixture exercises. Cross-account ownership stays the
//! business of `crates/ksp/tests/principals.rs`, which runs under `sudo`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The binary under test.
pub fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// One deployment: an admin home, two user homes and one shared store.
pub struct Deployment {
    /// Holds everything, so the caller keeps it alive.
    pub root: tempfile::TempDir,
    /// The admin principal's home.
    pub admin_home: PathBuf,
    /// The first user principal's home.
    pub alice_home: PathBuf,
    /// The second user principal's home.
    pub bob_home: PathBuf,
    /// The store every home shares.
    pub store: PathBuf,
    /// The agent alice enrolled, as its principal UUID: `agent pubkey` and the
    /// record path take the identity, while `agent enroll` takes a display name.
    pub agent: String,
}

impl Deployment {
    /// Run `ksp` in `home` against the shared store.
    pub fn run(&self, home: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String) {
        let mut command = Command::new(ksp());
        command
            .env("KSP_HOME", home)
            .env("KSP_STORE", &self.store)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        let mut child = command.spawn().expect("the binary runs");
        if let Some(text) = stdin {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(text.as_bytes())
                .expect("the child reads its password");
        }
        let output = child.wait_with_output().expect("the child finishes");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr),
        )
    }

    /// The layout for one home over the shared store.
    pub fn layout(&self, home: &Path) -> ksp::config::Layout {
        ksp::config::Layout::with_store(home, Some(self.store.clone()))
    }

    /// The registry path this deployment writes.
    pub fn registry(&self) -> PathBuf {
        let layout = self.layout(&self.admin_home);
        let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
        ksp::registry::PrincipalRegistry::path_of(&layout, &deployment.vault, deployment.admin)
    }
}

/// The password every enrolment in these suites uses.
pub const PASSWORD: &str = "a long enough password";

/// Build an admin and two user principals in separate homes over one store.
///
/// Panics with the child's own output when a step refuses: a fixture that failed
/// silently would turn every assertion after it into a report about the wrong
/// thing.
pub fn admin_and_two_users() -> Deployment {
    let root = tempfile::tempdir().expect("a temporary directory");
    let admin_home = root.path().join("admin-home");
    let alice_home = root.path().join("alice-home");
    let bob_home = root.path().join("bob-home");
    let store = root.path().join("store");
    std::fs::create_dir_all(&store).expect("the shared store is created by its operator");

    let mut fixture = Deployment {
        root,
        admin_home,
        alice_home,
        bob_home,
        store,
        agent: String::new(),
    };

    let (code, output) = fixture.run(
        &fixture.admin_home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, 0, "admin init failed: {output}");

    for home in [&fixture.alice_home, &fixture.bob_home] {
        let (code, output) = fixture.run(
            &fixture.admin_home,
            &[
                "admin",
                "user",
                "add",
                "--home",
                home.to_str().expect("a UTF-8 temporary path"),
            ],
            Some(PASSWORD),
        );
        assert_eq!(
            code,
            0,
            "admin user add into {} failed: {output}",
            home.display()
        );
    }
    // The agent enrols in the user's home, because that is the account whose
    // records it will read. A deployment fixture without one would leave every
    // later grant test building its own.
    let name = "alice-agent";
    let (code, output) = fixture.run(
        &fixture.alice_home,
        &["agent", "enroll", "--agent", name],
        None,
    );
    assert_eq!(code, 0, "agent enroll failed: {output}");
    let start = output
        .find("agent:")
        .unwrap_or_else(|| panic!("no agent identity in {output}"));
    fixture.agent = output[start + "agent:".len()..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
        .collect();
    assert!(!fixture.agent.is_empty(), "the enrol printed an identity");
    fixture
}
