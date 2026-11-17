//! The public half of an agent's enrolment, where the admin can read it.
//!
//! # Why the home-local pin is not enough
//!
//! `agent enroll` writes the pin in the owner's home, and only her account can
//! read it. An edge that names an agent is signed by the **admin**, in the admin's
//! home, and the admin has no path into the user's `0700` home — that boundary is
//! the reason the deployment has per-account homes at all. Without a shared,
//! readable record, `admin policy create --agent` cannot tell an enrolled agent
//! from a typo, which is misfit G, and no read surface can compute the `dangling`
//! state (CF-011).
//!
//! # What this is, and is not
//!
//! It is the same public material the pin already holds: the agent's principal,
//! its two public keys, the key IDs and the fingerprint. There is no private half,
//! no password and no secret. That is why `0644` is not a weakening: the file a
//! sibling can read protects nothing by being unreadable.
//!
//! It is **not** a second trust anchor. A reload still verifies against the
//! home-local pin; this index answers "does this agent exist, and which key does the
//! operator say it has", which is a question about enrolment rather than about
//! authorisation.
//!
//! # Rotation replaces it
//!
//! A rotated key that left the old public half in the index would make the admin
//! check a key the agent no longer has, and a publication sealed to it would be
//! unopenable with a perfectly valid grant. So `agent rotate` rewrites the index in
//! the same step that rewrites the pin.

use std::path::PathBuf;

use ksp_types::{AgentId, PrincipalId, VaultId};

use crate::config::Layout;
use crate::keys::{PinError, StoredEnrolment};

/// The directory mode: readable and traversable, so an admin can list a user's
/// agents without reading anything else of hers.
pub const AGENTS_DIR_MODE: u32 = 0o755;

/// `p/<vault>/<owner>/agents/`.
pub fn dir(layout: &Layout, vault: &VaultId, owner: PrincipalId) -> PathBuf {
    layout
        .store_root()
        .join("p")
        .join(vault.as_str())
        .join(owner.to_string())
        .join("agents")
}

/// `p/<vault>/<owner>/agents/<agent>.cbor`.
pub fn path(layout: &Layout, vault: &VaultId, owner: PrincipalId, agent: &AgentId) -> PathBuf {
    dir(layout, vault, owner).join(format!("{agent}.cbor"))
}

/// Publish one agent's public identity where every principal can read it.
pub fn publish(
    layout: &Layout,
    vault: &VaultId,
    owner: PrincipalId,
    enrolment: &StoredEnrolment,
) -> Result<PathBuf, PinError> {
    use std::os::unix::fs::PermissionsExt;

    // The principal root is the layout's (`0711`); `agents/` is created here with an
    // explicit mode, because `create_dir_all` takes the caller's `umask`.
    crate::layout::ensure_principal_root(layout, vault, owner).map_err(|_| PinError::Unreadable)?;
    let directory = dir(layout, vault, owner);
    std::fs::create_dir_all(&directory).map_err(|_| PinError::Unreadable)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(AGENTS_DIR_MODE))
        .map_err(|_| PinError::Unreadable)?;

    let target = path(layout, vault, owner, &enrolment.identity);
    enrolment.save(&target)?;
    Ok(target)
}

/// Read one agent's published identity.
pub fn load(
    layout: &Layout,
    vault: &VaultId,
    owner: PrincipalId,
    agent: &AgentId,
) -> Result<StoredEnrolment, PinError> {
    StoredEnrolment::load(&path(layout, vault, owner, agent))
}

/// Whether this user's agent is published, and therefore resolvable by the admin.
pub fn exists(layout: &Layout, vault: &VaultId, owner: PrincipalId, agent: &AgentId) -> bool {
    path(layout, vault, owner, agent).is_file()
}

/// Every agent a user has published, ordered by identity.
///
/// A user who has enrolled nothing has no directory, which is an empty set rather
/// than an error: the first enrolment in a fresh deployment is not a failure.
pub fn list(
    layout: &Layout,
    vault: &VaultId,
    owner: PrincipalId,
) -> Result<Vec<StoredEnrolment>, PinError> {
    let Ok(entries) = std::fs::read_dir(dir(layout, vault, owner)) else {
        return Ok(Vec::new());
    };
    let mut agents = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("cbor") {
            continue;
        }
        agents.push(StoredEnrolment::load(&path)?);
    }
    agents.sort_by_key(|agent| agent.identity.to_string());
    Ok(agents)
}
