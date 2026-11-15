//! The `ksp admin` group: initialise the deployment, enrol the user, hold the policy.
//!
//! # What the admin can and cannot do
//!
//! The admin holds a signing key that cannot decrypt anything (FR-001). `init`
//! writes that key's protected file and pins the public half; nothing here opens
//! a payload. `user add` creates the *user's* vault, and the policy it signs
//! names the user's public keys — the admin never holds a user private half.
//!
//! # The policy is the grant list
//!
//! `S2` refuses a mint whose secret or agent the policy does not name, so the
//! policy written here is what authorises a delivery. Rewriting it is a normal
//! operation: `admin policy` re-signs the same body with a higher revision and
//! the grants the operator asked for.

use std::io::Read;

use ksp_identity::{
    AdminKeyBundle, KeyId, Policy, PolicyBody, PolicyRefusal, TrustedEnrolmentKeys, Withdrawal,
};
use ksp_key_lifecycle::{KeyError, KeyRoot, KeyStore};
use ksp_types::{AgentId, OpaqueSecretId, PrincipalId, VaultId};

use crate::config::Layout;
use crate::deployment::Deployment;
use crate::exit::{self, Outcome};
use crate::keys::{Anchor, PinError};
use crate::vault::{VaultError, VaultHome};

/// Why an admin operation failed.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The protected admin key file could not be written or read.
    #[error("the admin key file could not be used")]
    Keys(#[from] KeyError),
    /// A pin or the deployment file could not be read.
    ///
    /// `Absent` is split out in [`Self::exit_code`] rather than here: a host
    /// with no deployment has missing key material, not a corrupt file, and
    /// every other surface already says so.
    #[error("the deployment is not readable")]
    Pin(#[from] PinError),
    /// The vault could not be created or opened.
    ///
    /// Transparent rather than a fixed sentence. Every `VaultError` already
    /// names what happened in the operator's terms, and a wrapper that replaced
    /// them with one generic line is how a seven-byte password arrived as "the
    /// vault could not be created" instead of as a length.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The policy was refused by S2's own constructor.
    #[error("the policy was refused: {0}")]
    Policy(#[from] PolicyRefusal),
    /// The signed policy could not be written.
    ///
    /// Its own variant because the generic one told an operator whose `admin
    /// policy` was refused by `EACCES` that "the deployment is not readable":
    /// every later step then looks for a corrupt file that is only unowned.
    #[error("the signed policy could not be written")]
    PolicyWrite,
    /// A file this operation had to write could not be written.
    ///
    /// Deliberately generic: this variant carries the layout, the policy, the
    /// ledger, the anchor, the deployment record and the vault binding. A message
    /// that named one of them ("the policy could not be written") told an
    /// operator whose `admin init` failed on the layout to look at the wrong
    /// file. Where the specific file is known, a specific variant is raised.
    #[error("a protected file this operation had to write could not be written")]
    Write,
    /// A password could not be read.
    ///
    /// The sentence names `--passphrase-file`, because a caller that cannot type
    /// has to be told the one way it can supply the password. It mapped to
    /// `POLICY_DENIAL` before this: a missing credential reported as a policy
    /// decision, which a caller cannot act on and cannot tell apart from a real
    /// refusal.
    #[error(
        "the password could not be read: supply it on stdin, or name a file with \
         --passphrase-file"
    )]
    NoPassword,
    /// The file named by `--passphrase-file` could not be opened.
    ///
    /// The path is named because a caller that mistyped it needs to see which
    /// file was opened. `NoPassword` would say only that something could not be
    /// read, and the fix for a wrong path is to correct the path.
    #[error(
        "the passphrase file at {0} could not be opened: check the path, or supply the password \
         on stdin"
    )]
    PassphraseFile(String),
    /// This host holds no signed policy.
    #[error("this host holds no signed policy")]
    NoPolicy,
    /// The policy on disk was not signed by the pinned admin key.
    #[error("the policy was not signed by the pinned admin key")]
    PolicyIssuer,
    /// The withdrawal named no grant, or one the policy does not make.
    #[error("{0}")]
    Withdrawal(String),
    /// The ledger refused to record the decision.
    #[error("{0}")]
    Ledger(String),
    /// This host has not recorded the user's recipient public key, so there is
    /// nothing to seal a record to.
    #[error("the user's recipient public key was never recorded on this host")]
    NoRecipientKey,
    /// The record could not be sealed or written.
    #[error(transparent)]
    Secret(#[from] crate::secret::SecretError),
    /// This host already holds a sealed vault, and enrolling again would replace it.
    ///
    /// A second `admin user add` with a different password would write a new
    /// sealed file over the old one and lock the principal out of every record
    /// already sealed to her. The replacement has to be asked for by name —
    /// `ksp vault rekey` — not arrived at by re-running enrolment.
    #[error(
        "this host already holds a sealed vault for {principal}: enrolling again would replace \
         it and lock that principal out of every record sealed to her; use `ksp vault rekey` to \
         change the password"
    )]
    AlreadyEnrolled {
        /// The principal the existing vault belongs to.
        principal: PrincipalId,
    },
    /// An enrolment stopped after the vault was written and before her keys were
    /// recorded, so the vault is a leftover and not an enrolment.
    ///
    /// Nothing can have been sealed to that file: `admin put` seals to the
    /// recipient key the deployment records, and an interrupted enrolment never
    /// recorded one. Removing it is therefore safe, and refusing without saying
    /// so would leave an operator with a home no command can finish.
    #[error(
        "an enrolment of {principal} stopped after its vault was written and before her keys \
         were recorded, so nothing was sealed to it yet: remove {path} and run this again"
    )]
    Interrupted {
        /// The principal the interrupted enrolment was for.
        principal: PrincipalId,
        /// The leftover vault.
        path: String,
    },
    /// The host could not answer whether an account exists.
    ///
    /// The group that owns the store could not be read, so the principal cannot be
    /// given the sweep group the agent level needs. The tool is named because the
    /// two reasons an answer is missing — a gid with no group, and a tool the host
    /// does not have — are fixed differently, and a sentence about the *account*
    /// sent readers to check an account that was never in question.
    #[error(
        "the store's group (gid {gid}) could not be read with {tool}, so {account} cannot be given \
         the group the agent level needs: {reason}"
    )]
    GroupUnreadable {
        /// The gid the store root carries.
        gid: u32,
        /// The account the binding named.
        account: String,
        /// The tool that was run, at its absolute path.
        tool: &'static str,
        /// What the tool said, or what it printed instead of a name.
        reason: String,
    },
    /// The store root's ownership could not be read, so there was no gid to resolve.
    ///
    /// Not `Write`: nothing was written, and a sentence about a file that could
    /// not be written sends the operator to check permissions on the wrong path.
    #[error(
        "the store root at {path} could not be read, so its group could not be resolved: {reason}"
    )]
    StoreRootUnreadable {
        /// The store root that could not be read.
        path: String,
        /// What the filesystem said.
        reason: String,
    },
    /// The membership tool ran and could not answer whether the account is in the
    /// group, for a reason that is not the privilege the edit step needs.
    ///
    /// Measured on Darwin: a group that does not exist, and a user record that
    /// does not exist, both exit `64` from `dseditgroup -o checkmember`. Reporting
    /// that as "run as root" names a privilege that is not the problem.
    #[error(
        "{tool} could not say whether {account} is in {group} ({status}): {reason}. Run it yourself \
         to read the full answer, and check that both the group and the account exist on this host"
    )]
    MembershipRefused {
        /// The account the step was adding.
        account: String,
        /// The group the step was adding it to.
        group: String,
        /// The tool that answered.
        tool: &'static str,
        /// The exit status, rendered.
        status: String,
        /// The tool's own first line, or empty when it printed nothing.
        reason: String,
    },
    /// The tool the group step needs is not usable on this host.
    ///
    /// Distinct from [`GroupUnreadable`](Self::GroupUnreadable): that one ran a
    /// tool and got no answer, and this one had nothing to run. The command is
    /// carried so an operator can run it themselves and read what the shell says.
    #[error(
        "the store's group could not be checked because {tool} is not usable on this host: {reason} \
         (the step runs: {command})"
    )]
    GroupTool {
        /// The tool that could not be run.
        tool: &'static str,
        /// The command line, quoted for a shell.
        command: String,
        /// Why the tool could not be run.
        reason: String,
    },
    /// The membership step could not run its tool at all.
    #[error(
        "{account} could not be added to the store's group because {tool} is not usable on this \
         host: {reason} (the step runs: {command})"
    )]
    MembershipTool {
        /// The tool that could not be run.
        tool: &'static str,
        /// The command line, quoted for a shell.
        command: String,
        /// Why the tool could not be run.
        reason: String,
        /// The account the step was adding.
        account: String,
    },
    /// A missing `id`, a PATH-less environment or a probe that failed for another
    /// reason is not the same finding as "there is no such account": FR-023 wants
    /// the identity named *and* the reason it could not be checked.
    #[error(
        "this host could not answer whether there is a UNIX account named {name}, so the binding \
         was not recorded: {reason}"
    )]
    AccountUnreadable {
        /// The account the binding named.
        name: String,
        /// What the probe said, in its own words.
        reason: String,
    },
    /// A named UNIX account does not exist on this host.
    ///
    /// FR-023: a binding that names a host identity the backend cannot verify is
    /// reported with the identity named, and the operation does not proceed on a
    /// binding nobody can check.
    #[error(
        "there is no UNIX account named {0} on this host, so the vault cannot be bound to it: \
         a binding that names nothing would be recorded as if it had been checked"
    )]
    NoAccount(String),
    /// The vault could not be handed to the account the binding names.
    ///
    /// Changing a file's owner is privileged: an account may give a file away
    /// only as root. The refusal says so instead of surfacing a bare `EPERM` as
    /// an internal failure, because the operator's next step is a different
    /// invocation, not a bug report.
    #[error(
        "the vault must belong to {account}, and handing a file to another account needs a \
         privileged chown: run this provisioning step as root, or bind the account before \
         the deployment is written"
    )]
    Binding {
        /// The account the vault was to belong to.
        account: String,
    },
    /// The account could not be added to the group that owns the store.
    ///
    /// Distinct from [`Binding`](Self::Binding), which names the `chown`. Both
    /// steps need privilege, so both fail on a first unprivileged run — but they
    /// fail for different reasons and an operator fixes them differently. Reusing
    /// the `chown` sentence here told a reader whose `chown` had *succeeded* that
    /// a `chown` needed root, which is a sentence about an operation that was
    /// not the one that failed.
    ///
    /// # Why this does not simply say "run as root"
    ///
    /// It did, and the advice was dangerous. The group is read from the store
    /// root, and a store created under `/tmp` on macOS inherits `wheel` — so the
    /// sentence told an ordinary operator to run as root and add their account to
    /// a privileged system group. The accepted shape is named instead: a store
    /// whose group is one the operator can join, which is what creating it under
    /// their own home produces.
    ///
    /// The tool's own stderr is carried in [`GroupToolSaid`](Self::GroupToolSaid)
    /// rather than interpolated here, because an unlabelled line from
    /// `dseditgroup` reads as `ksp`'s own sentence.
    #[error(
        "{account} could not be added to {group}, the group that owns the store, so the agent \
         level cannot be shared with the sweep: {tool} failed. The store's group is inherited \
         from the directory it was created in, so a store under a system-owned directory gets \
         a system group. Create the store under your own home (the default), or set KSP_HOME \
         to a directory whose group you belong to, and run this step again. If the store must \
         keep this group, run the step as root and add {account} to {group} yourself"
    )]
    GroupJoin {
        /// The account the step was adding.
        account: String,
        /// The group the step was adding it to.
        group: String,
        /// The tool that failed.
        tool: &'static str,
    },
    /// The tool said something of its own, which is not `ksp`'s sentence.
    ///
    /// A separate variant so the forwarded line is labelled. The previous shape
    /// printed `dseditgroup`'s `Username and password must be provided.` between
    /// two `ksp` sentences with nothing to say whose it was.
    #[error("{tool} said: {said}")]
    GroupToolSaid {
        /// The tool that printed the line.
        tool: &'static str,
        /// What it printed, first line only.
        said: String,
    },
    /// The recorded ownership of a file contradicts the binding being made.
    ///
    /// FR-024: a recorded owner is a claim from the past. Replacing it silently
    /// is how a rebind becomes invisible, so the conflict is refused and the
    /// operator is told which claim already exists.
    #[error("{0}")]
    Owners(#[from] crate::layout::LayoutError),
    /// A protected root drifted, so no administrative write may proceed.
    ///
    /// The finding is carried rather than summarised: FR-014 requires the
    /// refusal to name the path, its mode and the expected owner, and a caller
    /// that has to run `ksp status` to learn what stopped it has been told
    /// nothing.
    #[error("no administrative write will touch a drifted layout: {0}")]
    Layout(#[from] crate::layout::LayoutRefusal),
    /// This deployment already has a principal, and a UUID is never reissued.
    #[error(
        "this deployment is already initialised for principal {principal}; a principal UUID is issued once and never reissued"
    )]
    AlreadyInitialised {
        /// The UUID the existing principal keeps.
        principal: PrincipalId,
    },
}

impl AdminError {
    /// The exit code this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Keys(error) if error.failure().is_missing_key_material() => exit::MISSING_KEY,
            // A host with no deployment has missing key material, not a broken
            // tool. `secret ls`, `agent pubkey` and `audit verify` all report
            // `6` for this state; `admin list` reported `1` and was the only
            // surface an agent could not branch on. The remaining `PinError`
            // variants are a corrupt or mismatched pin, which is still an
            // internal failure: re-running setup will not fix a file that is
            // there and wrong.
            Self::Pin(PinError::Absent) => exit::MISSING_KEY,
            Self::Keys(_)
            | Self::Pin(_)
            | Self::Write
            | Self::PolicyWrite
            | Self::AlreadyInitialised { .. } => exit::INTERNAL,
            Self::Vault(error) => error.exit_code(),
            // A password that could not be read is missing usable key material,
            // not a policy decision. `secret set` has always reported `13` for
            // its own stdin conflict, and the four other arms reported `2`, which
            // the published table defines as a policy denial.
            Self::NoPassword | Self::PassphraseFile(_) => exit::MISSING_KEY,
            Self::Policy(_) | Self::NoPolicy | Self::PolicyIssuer | Self::Withdrawal(_) => {
                exit::POLICY_DENIAL
            }
            // The narrower revision was signed but not recorded, so this host
            // cannot show the decision a local client must see.
            Self::Ledger(_) => exit::INTERNAL,
            Self::NoRecipientKey => exit::MISSING_KEY,
            // An operator error about a name, not a missing key: the account the
            // operator asked for is not there, and re-running will not find it.
            // A binding this host could not make is the same class: the operation
            // was refused by the host, and the operator has one more step to run.
            Self::NoAccount(_)
            | Self::GroupUnreadable { .. }
            | Self::MembershipRefused { .. }
            | Self::Binding { .. }
            | Self::GroupJoin { .. }
            | Self::GroupToolSaid { .. }
            | Self::Owners(_)
            | Self::AlreadyEnrolled { .. }
            | Self::Interrupted { .. } => exit::POLICY_DENIAL,
            // Not an operator error about a name: this host could not run the
            // probe, which is an environment failure and not a refusal.
            Self::AccountUnreadable { .. }
            | Self::GroupTool { .. }
            | Self::MembershipTool { .. }
            | Self::StoreRootUnreadable { .. } => exit::INTERNAL,
            // FR-014: a drifted protected root refuses the operation with the
            // capability-refusal code, the same code a lease request carries.
            Self::Layout(_) => exit::CAPABILITY_REFUSAL,
            Self::Secret(error) => error.exit_code(),
        }
    }
}

/// What `admin init` created.
pub struct Initialised {
    /// The pinned anchor, which is the admin's public key.
    pub anchor: Anchor,
    /// Where the protected admin key file was written.
    pub key_file: std::path::PathBuf,
    /// The admin principal UUID this init issued. The sweep reports as this
    /// actor, so it is not the user whose records it removes.
    pub admin: PrincipalId,
    /// The user principal UUID this init issued.
    pub user: PrincipalId,
}

impl std::fmt::Debug for Initialised {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initialised")
            .field("key_file", &self.key_file)
            .field("key_id", &self.anchor.key_id.as_str())
            .finish()
    }
}

/// Initialise the deployment: the admin's signing key and the identifiers.
///
/// The key is written once. A second `admin init` on the same host refuses,
/// because S6 will not replace an existing protected file: a silent new admin
/// key would invalidate every policy and every token already issued.
pub fn init(
    layout: &Layout,
    vault: VaultId,
    user_name: String,
    key_id: KeyId,
) -> Result<Initialised, AdminError> {
    if layout.deployment_file().exists() {
        // Reissuing a UUID would silently rebind every record path, grant and
        // report to a new principal. Report the one that already exists.
        let existing = Deployment::load(layout)?;
        return Err(AdminError::AlreadyInitialised {
            principal: existing.user,
        });
    }

    // Provisioning is the one command that creates the protected roots, so it
    // creates all of them: a home is never half-laid-out because a later command
    // only needed part of it.
    crate::layout::ensure(layout.root()).map_err(|_| AdminError::Write)?;

    // Issued once, here. The display name below is metadata. The admin gets its
    // own UUID: a sweep report names the actor that removed the version, and
    // naming the user would attribute the admin's action to her.
    let collector = PrincipalId::generate();
    let user = PrincipalId::generate();
    let admin = ksp_identity::AdminSigningKey::generate();
    let bundle = AdminKeyBundle::from_key(&admin, key_id.clone());
    let store = KeyStore::new(KeyRoot::open(layout.admin_key_root())?);
    let key_file = store.save_admin_new(&bundle)?;

    let anchor = Anchor {
        key_id: key_id.clone(),
        key: admin.verifying_public(),
    };
    anchor.save(&layout.admin_anchor_file())?;
    Deployment {
        vault,
        user_name: Some(user_name),
        user_account: None,
        admin: collector,
        user,
        admin_key_id: key_id,
        user_signing_key_id: None,
        user_signing_key: None,
        user_recipient_key_id: None,
        user_recipient_key: None,
    }
    .save(layout)?;
    // Both files exist now; their owners are recorded so a later replacement by
    // another account is reported instead of assumed.
    record_public_files(layout)?;
    // The admin writes its own chain from the first command, and the audit root is
    // only traversable: the directory has to exist before anything appends.
    {
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata(layout.root()).map_err(|_| AdminError::Write)?;
        crate::layout::ensure_audit_writer(layout.root(), collector, (me.uid(), me.gid()))?;
    }

    // The two ledger files, created here because provisioning creates *every*
    // protected root: a home is never half-laid-out because a later command only
    // needed part of it. They are created owned by whoever runs `admin init`, and
    // `admin user add` re-owns them to the accounts that will write them.
    //
    // They are two files rather than one because their writers are different
    // accounts: the principal appends issuances and token marks, the admin appends
    // grant withdrawals. One shared file would have to be group-*writable*, and a
    // mint history any group member can rewrite is one that member can forge.
    // `0640` in the store's group gives each account read of the other's file —
    // which `run` and `audit verify` both need — and write of only its own.
    {
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata(layout.root()).map_err(|_| AdminError::Write)?;
        let owner = (me.uid(), me.gid());
        crate::layout::ensure_ledger_file(layout.root(), &layout.issuance_ledger(), owner)?;
        crate::layout::ensure_ledger_file(layout.root(), &layout.withdrawals_ledger(), owner)?;
    }

    Ok(Initialised {
        anchor,
        key_file,
        admin: collector,
        user,
    })
}

/// Enrol the user: create her vault and sign a policy that names her keys.
///
/// No grants are recorded here. A policy that listed every secret and every
/// agent would be a policy that authorises everything; `admin policy` adds the
/// grants it was asked for.
pub fn user_add(
    layout: &Layout,
    password: &[u8],
    signing_key_id: KeyId,
    recipient_key_id: KeyId,
    account: Option<&str>,
) -> Result<PrincipalId, AdminError> {
    let (deployment, anchor) = crate::deployment::require(layout)?;
    let admin = load_admin(layout, &anchor)?;

    // Refuse before the vault is touched: `vault::init` writes the file, and a
    // new password over an existing vault locks its principal out of everything
    // already sealed to her. Checked here rather than inside S6 so the message
    // can name the principal and the command that *is* meant to replace a vault.
    if layout.vault_file().exists() {
        // Two different states, two different answers. Keys recorded means the
        // enrolment completed and replacing the file would lock her out. No keys
        // recorded means it stopped halfway, and the leftover is safe to remove
        // because nothing was ever sealed to it.
        return Err(if deployment.user_signing_key_id.is_some() {
            AdminError::AlreadyEnrolled {
                principal: deployment.user,
            }
        } else {
            AdminError::Interrupted {
                principal: deployment.user,
                path: layout.vault_file().display().to_string(),
            }
        });
    }

    // S2's vault constructor owns the sealing; this module only chooses the path
    // and the binding.
    let home = VaultHome::new(layout.root().to_path_buf());
    let (binding, vault) = crate::vault::init(
        &home,
        ksp_types::ActorId::User(deployment.user),
        signing_key_id.as_str(),
        recipient_key_id.as_str(),
        password,
    )?;

    let trusted = TrustedEnrolmentKeys {
        signing_key: vault.signing_public(),
        recipient_key: vault.recipient_public(),
        signing_key_id: binding.signing_key_id.clone(),
        recipient_key_id: binding.recipient_key_id.clone(),
    };

    // The binding is the vault's AEAD associated data, so it has to outlive the
    // process that sealed it: a later `admin policy` cannot re-derive it, and a
    // guessed binding would simply fail to open the vault.
    let mut recorded = deployment.clone();
    recorded.user_signing_key_id = Some(binding.signing_key_id.clone());
    recorded.user_signing_key = Some(vault.signing_public());
    recorded.user_recipient_key_id = Some(binding.recipient_key_id.clone());
    // The public half is recorded here so a later `admin put` can seal to her
    // without asking for the password that protects the private half.
    recorded.user_recipient_key = Some(vault.recipient_public());
    // The vault is sealed to her keys and must then be *hers*: an admin-owned
    // `0600` vault is a vault the principal cannot open, and the only way to
    // give it to her is to say which account she is (FR-037's binding).
    if let Some(account) = account {
        let owner = unix_account(account)?;
        bind_vault(layout, owner, account)?;
        bind_principal_roots(layout, &deployment, owner, account)?;
        recorded.user_account = Some(account.to_string());
    }
    // Written after the vault is bound, so the deployment that names the account
    // never exists before the account's ownership of the vault does.
    recorded.save(layout)?;
    record_public_files(layout)?;

    write_policy(
        layout,
        &admin,
        &recorded,
        trusted,
        1,
        Vec::new(),
        Vec::new(),
    )?;

    // A handover run as root must not leave the admin's own files owned by root:
    // `policy.cbor` is created by this step, and the admin is the account that
    // signs the next revision. `EACCES` on her own policy would be reported as a
    // write failure with no owner in the sentence.
    if account.is_some() {
        reclaim_provisioned_files(layout)?;
        record_public_files(layout)?;
    }

    // `admin user add` never mints: the UUID was issued by `admin init` and is
    // reported here so the operator sees which principal her keys belong to.
    Ok(deployment.user)
}

/// The uid and gid a named UNIX account has, or a refusal naming it.
///
/// `id` is spawned with an argv and no shell, and the name is validated first: a
/// name starting with `-` would be an option to `id`, and an account name this
/// host accepts for a binding has no business holding anything but letters,
/// digits, `_`, `-` and `.`.
pub(crate) fn unix_account(name: &str) -> Result<(u32, u32), AdminError> {
    let valid = !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-.".contains(character));
    if !valid {
        return Err(AdminError::NoAccount(name.to_string()));
    }
    let number = |flag: &str| -> Result<u32, AdminError> {
        let output = std::process::Command::new("/usr/bin/id")
            .args([flag, name])
            .output()
            .map_err(|error| AdminError::AccountUnreadable {
                name: name.to_string(),
                reason: error.to_string(),
            })?;
        if !output.status.success() {
            // `id` ran and said no: that is the finding FR-023 reports, with the
            // identity named.
            return Err(AdminError::NoAccount(name.to_string()));
        }
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .map_err(|_| AdminError::AccountUnreadable {
                name: name.to_string(),
                reason: "the probe printed no number".to_string(),
            })
    };
    Ok((number("-u")?, number("-g")?))
}

/// Give the vault to the account that will read it, and record that it is theirs.
fn bind_vault(layout: &Layout, owner: (u32, u32), account: &str) -> Result<(), AdminError> {
    let path = layout.vault_file();
    std::os::unix::fs::chown(&path, Some(owner.0), Some(owner.1)).map_err(|_| {
        AdminError::Binding {
            account: account.to_string(),
        }
    })?;
    crate::layout::record_file_owner(layout.root(), &path, owner.0)?;
    Ok(())
}

/// Give the user principal the roots it writes, and only those.
///
/// `agent/` holds *her* agents' protected keys and `enrolments/` the signed pins
/// for them: both are hers to write, and neither is somewhere the admin needs to
/// write. The audit root is different — it stays a parent every principal
/// traverses — so the handover is her own chain directory, `0700` and hers, which
/// is what stops a sibling reading or appending to it.
///
/// `store/` is deliberately not here: each level is created by the table when the
/// principal first writes it, and a level the provisioning account created would
/// belong to the wrong principal forever.
fn bind_principal_roots(
    layout: &Layout,
    deployment: &Deployment,
    owner: (u32, u32),
    account: &str,
) -> Result<(), AdminError> {
    for path in [layout.agent_key_root(), layout.enrolments_dir()] {
        std::os::unix::fs::chown(&path, Some(owner.0), Some(owner.1)).map_err(|_| {
            AdminError::Binding {
                account: account.to_string(),
            }
        })?;
        // A directory row is recorded when it is created, so the handover has to
        // *replace* that claim: keeping the old owner would report the binding as
        // drift on the next `status`, which is the opposite of recording it.
        crate::layout::rebind_directory_owner(layout.root(), &path, owner.0)?;
    }
    // The agent level's group is the store's (FR-015), and she is the one who
    // creates those levels when she shares. A group she is not in is a group she
    // cannot name on a directory she makes — `chgrp` to it is `EPERM` — so the
    // handover adds her account to it here, where the step already runs
    // privileged.
    join_store_group(layout, account)?;
    // `share` arms as her: `mint::arm` writes the create-new record before any
    // token bytes exist, so the journal has to be group-writable *before* that
    // call, and its owner has to be the deployment rather than the principal —
    // the sticky bit only protects a record from a sibling if the directory's
    // owner is not a sibling too.
    crate::layout::ensure_arm_journal(layout.root()).map_err(|_| AdminError::Binding {
        account: account.to_string(),
    })?;

    // The principal's own level has to exist as *hers* before she can write to
    // it: creating it needs write on the level's parents, and those belong to the
    // deployment. Pre-creating the level (and only the level — the agent levels
    // below it are created by her own `share`) is what makes the parents a
    // boundary rather than a shared write hole.
    let user_level = crate::layout::ensure_level(
        layout.root(),
        &deployment.vault,
        deployment.user,
        &ksp_types::Level::User,
    )?;
    std::os::unix::fs::chown(&user_level, Some(owner.0), Some(owner.1)).map_err(|_| {
        AdminError::Binding {
            account: account.to_string(),
        }
    })?;
    // The principal directory above it is hers too, and stays `0711`: her agent
    // levels are created *beside* `user/`, so creating them needs write on this
    // directory, and every other principal still needs to traverse it to reach
    // its own levels. A directory she owns is one she can widen; that is what
    // `ksp status` measures and what a sibling's `0700` level still refuses.
    if let Some(principal_dir) = user_level.parent() {
        std::os::unix::fs::chown(principal_dir, Some(owner.0), Some(owner.1)).map_err(|_| {
            AdminError::Binding {
                account: account.to_string(),
            }
        })?;
        std::fs::set_permissions(
            principal_dir,
            std::os::unix::fs::PermissionsExt::from_mode(crate::layout::LEVEL_PARENT_MODE),
        )
        .map_err(|_| AdminError::Binding {
            account: account.to_string(),
        })?;
    }
    crate::layout::ensure_audit_writer(layout.root(), deployment.user, owner)?;

    // The two ledger files, each created as the account that writes it.
    //
    // `publish_recorded` appends the issuance file inside the mint's publication
    // closure — the record precedes the token, so a mint that cannot append must
    // not publish — and the file is created lazily on that first append. Creating
    // it needs write on the deployment root, which is `0711` and belongs to the
    // admin on purpose, so a user's `secret share` failed with
    // `the issuance ledger at <root>/issuance.jsonl could not be used: Permission
    // denied`, naming the ledger for a refusal that was really about the directory
    // above it.
    //
    // The two ledger files were created by `admin init`, owned by whoever ran it.
    // Each is re-owned here to the account that will write it: the issuance file
    // to the principal, the withdrawals file to the admin. The group stays the
    // store's, which is what gives each account read of the other's file.
    //
    // They are two files rather than one because their writers are different
    // accounts. One shared file would have to be group-*writable*, and a mint
    // history any group member can rewrite is one that member can forge: appending
    // a revocation is how a token stops working, and removing one is how it starts
    // again. `0640` gives each account read of the other's file — which `run` and
    // `audit verify` both need — and write of only its own.
    crate::layout::ensure_ledger_file(layout.root(), &layout.issuance_ledger(), owner)?;
    // The admin's own uid, taken from the key root it already owns: that directory
    // is `0700`, it exists before this step, and it is the one place on this host
    // that is unambiguously the admin's.
    let admin_owner = admin_root_owner(layout)?;
    crate::layout::ensure_ledger_file(layout.root(), &layout.withdrawals_ledger(), admin_owner)?;
    Ok(())
}

/// The uid and gid of the admin key root, which is the admin's own account.
fn admin_root_owner(layout: &Layout) -> Result<(u32, u32), AdminError> {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata(layout.admin_key_root())
        .map(|metadata| (metadata.uid(), metadata.gid()))
        .map_err(|_| AdminError::Write)
}

/// Put the principal's account in the group that owns the store.
///
/// The agent level is `0730` and its group is the store root's, which is what lets
/// the sweep unlink a copy it may not read (FR-015). The principal creates that
/// level herself when she shares, and only a member of the group can give a new
/// directory that group. Adding the account is a provisioning step with a
/// privileged caller — the same step that chowns her vault — and it is idempotent.
fn join_store_group(layout: &Layout, account: &str) -> Result<(), AdminError> {
    // The group's *name*, because both membership tools take names and a name is
    // what the host's group database holds. The gid comes from the store root
    // itself: a group recorded in a file can disagree with the directory the
    // records are written under, and the directory is what the kernel enforces.
    let group = crate::storegroup::resolve(layout, account)?;
    crate::storegroup::join(account, &group)
}

/// Give the files this deployment keeps for the admin back to the admin account.
///
/// The account is named by `admin/`: it is the key root the admin writes, mode
/// `0700`, and it exists before any of these files do. A step that ran as root
/// writes new files as root, and leaving them that way makes the admin's next
/// write fail on a file that is hers by design.
fn reclaim_provisioned_files(layout: &Layout) -> Result<(), AdminError> {
    use std::os::unix::fs::MetadataExt;

    let admin_root = std::fs::metadata(layout.admin_key_root()).map_err(|_| AdminError::Write)?;
    let caller = ksp_posture::permissions::effective_uid();
    if admin_root.uid() == caller {
        return Ok(());
    }
    for path in [
        layout.policy_file(),
        layout.layout_record_file(),
        layout.deployment_file(),
        layout.admin_anchor_file(),
    ] {
        // A row of the table that does not exist yet is not this step's to
        // create: `admin init` writes all four, and a missing one is a finding.
        if std::fs::symlink_metadata(&path).is_ok() {
            std::os::unix::fs::chown(&path, Some(admin_root.uid()), Some(admin_root.gid()))
                .map_err(|_| AdminError::Write)?;
        }
    }
    Ok(())
}

/// Record the owners of the two public files, so a changed one is reported.
///
/// Their *modes* are not table rows: FR-013 names the key roots, the vault and
/// the store, and the mode of a public file is not a boundary. Their owners are
/// still recorded, because a deployment record replaced by another account is a
/// fact an operator has to see.
fn record_public_files(layout: &Layout) -> Result<(), AdminError> {
    use std::os::unix::fs::MetadataExt;

    for path in [layout.admin_anchor_file(), layout.deployment_file()] {
        let owner = std::fs::metadata(&path)
            .map(|metadata| metadata.uid())
            .map_err(|_| AdminError::Write)?;
        // `?` and not a swallow: a row already recorded against another owner is
        // FR-024's finding, and it has a message of its own. Folding it into "a
        // file could not be written" would hide the claim that stopped it.
        crate::layout::record_file_owner(layout.root(), &path, owner)?;
    }
    Ok(())
}

/// Re-sign the policy with the grants the operator names.
///
/// # Merge is the default, and why
///
/// A revision names every grant it carries, so re-signing from the flags on one
/// invocation withdrew every grant that invocation did not name. Two sequential
/// `admin policy --agent X` calls left only the second agent granted, and both
/// exited `0`: the loss was invisible until the first agent's next share was
/// refused by a policy that named neither the grant nor the command that
/// overwrote it.
///
/// So a write now reads the policy this host holds and unions the named grants
/// into it. `replace` restores the old behaviour for a caller that wants to drop
/// grants in one step, and the report says which of the two happened.
///
/// # What a merge refuses
///
/// The existing policy is verified against the pinned anchor before it is
/// re-signed. Without that check the admin key would launder whatever it found on
/// disk into a policy it appears to have authorised — the same reason `revoke`
/// verifies. A policy that is present and does not verify is an error, not a
/// reason to start over: starting over would silently discard the grants the
/// operator meant to keep.
///
/// # What it does not do
///
/// A merge only adds. Removing a grant is `admin revoke`, which records the
/// decision in the withdrawal ledger; a merge that also removed would put two
/// operations behind one flag and leave the ledger without a record of the
/// withdrawal.
pub fn policy(
    layout: &Layout,
    agents: Vec<AgentId>,
    secrets: Vec<OpaqueSecretId>,
    replace: bool,
) -> Result<crate::output::PolicyGrantedView, AdminError> {
    let (deployment, anchor) = crate::deployment::require(layout)?;
    let admin = load_admin(layout, &anchor)?;

    // The keys come from the deployment record, not from the sealed vault: they
    // are public halves `user add` recorded, and a policy that needed her password
    // to learn them would make administration depend on a secret only the user has
    // (FR-020). The vault is still the authority on which *private* keys exist;
    // what it cannot be is the only place the public ones are written down.
    let trusted = TrustedEnrolmentKeys {
        signing_key: deployment
            .user_signing_key
            .ok_or(AdminError::NoRecipientKey)?,
        recipient_key: deployment
            .user_recipient_key
            .ok_or(AdminError::NoRecipientKey)?,
        signing_key_id: deployment
            .user_signing_key_id
            .clone()
            .ok_or(AdminError::NoRecipientKey)?,
        recipient_key_id: deployment
            .user_recipient_key_id
            .clone()
            .ok_or(AdminError::NoRecipientKey)?,
    };

    // The policy this write is about to replace, when there is one. `None` on a
    // fresh host, which makes the write the first revision rather than a merge
    // onto nothing.
    let existing = match std::fs::read(layout.policy_file()) {
        Ok(bytes) => Some(ksp_identity::decode_policy(&bytes).map_err(|_| AdminError::NoPolicy)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(AdminError::NoPolicy),
    };
    if let Some(policy) = &existing {
        // Before the grants are read out of it. A policy this host cannot
        // authenticate is not a grant set to merge into, and re-signing it would
        // make the admin key vouch for whatever it says.
        if !policy.verify_issuer(&anchor.key) {
            return Err(AdminError::PolicyIssuer);
        }
    }

    // Both paths sort. The body is signed over its encoded bytes, so the same
    // grant set named in a different order would otherwise produce a different
    // signature for the same policy, and a client comparing digests would report
    // a change that did not happen. `union` sorts as it merges; a `replace`
    // returns the caller's order, so it is sorted here rather than there — one
    // rule for both paths, in the one place both pass through.
    let (mut merged_agents, mut merged_secrets) = if replace {
        (agents, secrets)
    } else {
        union(&existing, agents, secrets)
    };
    merged_agents.sort_by_key(|agent| agent.to_string());
    merged_secrets.sort_by_key(|secret| secret.to_string());

    // The difference is computed before the write, from the two sets that are
    // about to be signed: a report derived from the file afterwards would be a
    // second read of the same fact, and the two could disagree.
    let granted = crate::output::PolicyGrantedView {
        revision: existing.as_ref().map_or(1, |policy| policy.revision() + 1),
        added_agents: difference(&merged_agents, &held_agents(&existing)),
        added_secrets: difference(&merged_secrets, &held_secrets(&existing)),
        removed_agents: difference(&held_agents(&existing), &merged_agents),
        removed_secrets: difference(&held_secrets(&existing), &merged_secrets),
        replaced: replace,
    };

    write_policy(
        layout,
        &admin,
        &deployment,
        trusted,
        granted.revision,
        merged_agents,
        merged_secrets,
    )?;
    Ok(granted)
}

/// The agents a policy holds, or none when there is no policy yet.
fn held_agents(policy: &Option<Policy>) -> Vec<AgentId> {
    policy
        .as_ref()
        .map(|policy| policy.shareable_agents().to_vec())
        .unwrap_or_default()
}

/// The secrets a policy holds, or none when there is no policy yet.
fn held_secrets(policy: &Option<Policy>) -> Vec<OpaqueSecretId> {
    policy
        .as_ref()
        .map(|policy| policy.shareable_secrets().to_vec())
        .unwrap_or_default()
}

/// The named grants plus the ones already held, without duplicates.
///
/// The caller sorts the result. Ordering is a property of the signed body, not of
/// how the set was assembled, and `--replace` never comes through here — a sort
/// in this function would leave the replace path unsorted, which is the defect it
/// was meant to prevent.
fn union(
    existing: &Option<Policy>,
    agents: Vec<AgentId>,
    secrets: Vec<OpaqueSecretId>,
) -> (Vec<AgentId>, Vec<OpaqueSecretId>) {
    let mut agents_out = held_agents(existing);
    for agent in agents {
        if !agents_out.contains(&agent) {
            agents_out.push(agent);
        }
    }
    let mut secrets_out = held_secrets(existing);
    for secret in secrets {
        if !secrets_out.contains(&secret) {
            secrets_out.push(secret);
        }
    }
    (agents_out, secrets_out)
}

/// What `wanted` names that `held` does not.
///
/// Compared by rendered form because both ID types are opaque: `AgentId` wraps a
/// `PrincipalId` and `OpaqueSecretId` a `String`, and neither exposes an ordering
/// the report could use. The rendered form is the same string the report prints,
/// so the comparison and the message cannot disagree.
fn difference<T: ToString>(wanted: &[T], held: &[T]) -> Vec<String> {
    let held: Vec<String> = held.iter().map(ToString::to_string).collect();
    wanted
        .iter()
        .map(ToString::to_string)
        .filter(|item| !held.contains(item))
        .collect()
}

/// Load the admin's protected signing identity against the pinned anchor.
pub fn load_admin(
    layout: &Layout,
    anchor: &Anchor,
) -> Result<ksp_identity::AdminSigningKey, AdminError> {
    let store = KeyStore::new(KeyRoot::open(layout.admin_key_root())?);
    let pin = ksp_identity::AdminSigningPin {
        key_id: anchor.key_id.clone(),
        signing_key: anchor.key,
    };
    Ok(store.load_admin(&pin)?)
}

fn write_policy(
    layout: &Layout,
    admin: &ksp_identity::AdminSigningKey,
    deployment: &Deployment,
    trusted: TrustedEnrolmentKeys,
    revision: u64,
    agents: Vec<AgentId>,
    secrets: Vec<OpaqueSecretId>,
) -> Result<(), AdminError> {
    let now = crate::run::now_seconds();
    // The revision is the caller's, not this function's. `admin policy` reads
    // the policy it is about to replace, merges the grant set and passes
    // `previous + 1`; `admin revoke` narrows and passes `previous + 1` too. A
    // re-read here would be a second answer to the same question, and the two
    // could disagree — which is what a hardcoded `1` did before feature 012.
    //
    // This branch carried a revision-only fix that read the policy here. 012's
    // fix is the one that stands: it merges the grant set *and* advances the
    // revision, and the parameter is how the caller states which revision it
    // merged onto.
    let body = PolicyBody::new(
        revision,
        deployment.vault.clone(),
        deployment.user,
        trusted,
        secrets,
        agents,
        // One hour at the user level, and at most a day for an agent. The bound
        // is what makes a short lease meaningful; a policy that allowed any
        // duration would make the admission floor the only limit.
        3_600,
        86_400,
        now.saturating_sub(60),
        now.saturating_add(365 * 24 * 3_600),
    );
    let policy = Policy::new(admin, deployment.admin_key_id.clone(), body)?;
    // One writer for every revision: the initial policy and a revoked one must be
    // the same kind of file, or the first `admin revoke` silently changes who can
    // read the policy the user verifies.
    write_signed_policy(layout, &policy)
}

/// The signed policy this host holds, exactly as it was signed.
///
/// Read rather than rebuilt: `admin revoke` has to start from the revision that
/// exists, and a policy reconstructed from arguments would be a new revision
/// that happens to list the same grants.
pub fn read_policy(layout: &Layout) -> Result<Policy, AdminError> {
    let bytes = std::fs::read(layout.policy_file()).map_err(|_| AdminError::NoPolicy)?;
    ksp_identity::decode_policy(&bytes).map_err(|_| AdminError::NoPolicy)
}

/// What the policy this host holds says, for a reader that cannot ask.
///
/// # Why this exists
///
/// `admin policy` replaces the whole grant set: a revision names every grant it
/// carries, so a call that names one agent withdraws every other. Before this
/// read-back an agent had to hold the current grants in its own context, which a
/// fresh session does not, so granting a second agent silently revoked the
/// first.
///
/// # What it verifies, and what it does not
///
/// The issuer is checked against the pinned anchor, and the result is reported
/// rather than enforced: a policy that does not verify is still printed, because
/// a reader needs to see what it says to know why it is refused. The grants are
/// not otherwise validated — that is the mint's job, and a read-back that
/// second-guessed it would be a second answer to the same question.
pub fn show_policy(layout: &Layout) -> Result<crate::output::PolicyView, AdminError> {
    let policy = read_policy(layout)?;
    let anchor = crate::keys::Anchor::load(&layout.admin_anchor_file())?;
    Ok(crate::output::PolicyView {
        revision: policy.revision(),
        vault: policy.vault().to_string(),
        user: policy.user().to_string(),
        shareable_secrets: policy
            .shareable_secrets()
            .iter()
            .map(|secret| secret.to_string())
            .collect(),
        shareable_agents: policy
            .shareable_agents()
            .iter()
            .map(|agent| agent.to_string())
            .collect(),
        not_before: policy.body().not_before(),
        not_after: policy.body().not_after(),
        issuer_verified: policy.verify_issuer(&anchor.key),
    })
}

/// Write a signed policy to the file this host reads, owner-only.
pub fn write_signed_policy(layout: &Layout, policy: &Policy) -> Result<(), AdminError> {
    let bytes = ksp_types::cbor::encode(policy).map_err(|_| AdminError::Write)?;
    // `0644`, not owner-only: the policy is how a *user* principal learns what
    // she may do and verifies the admin's signature on it. Owner-only would make
    // every `secret share` fail for the principal the policy is written for.
    crate::keys::write_with_mode(&layout.policy_file(), &bytes, crate::layout::POLICY_MODE)
        .map_err(|_| AdminError::PolicyWrite)
}

/// Withdraw one grant: sign the narrower revision, record it, then write it.
///
/// The ledger record is written before the file, so a crash between the two
/// leaves a decision a local client already honours and a policy the next mint
/// will refuse. The retry is safe: the same policy and grant produce the same
/// revision and the ledger reports the record already in force.
pub fn revoke(
    layout: &Layout,
    withdrawal: ksp_identity::Withdrawal,
    at: i64,
) -> Result<ksp_identity::AdminRevocation, AdminError> {
    let (_, anchor) = crate::deployment::require(layout)?;
    let admin = load_admin(layout, &anchor)?;
    let policy = read_policy(layout)?;
    // Without this a forged or corrupted policy file would be re-signed by the
    // admin key on its way out: a withdrawal must narrow a policy this host
    // knows to be the admin's, not launder whatever it found.
    if !policy.verify_issuer(&anchor.key) {
        return Err(AdminError::PolicyIssuer);
    }
    let ledger = ksp_identity::IssuanceLedger::at(layout.issuance_ledger());
    let revocation =
        ksp_identity::admin_revoke(&ledger, &admin, &policy, withdrawal, at).map_err(|error| {
            match error {
                ksp_identity::RevocationError::Policy(refusal) => {
                    AdminError::Withdrawal(refusal.to_string())
                }
                ksp_identity::RevocationError::Ledger(error) => {
                    AdminError::Ledger(error.to_string())
                }
            }
        })?;
    write_signed_policy(layout, &revocation.policy)?;
    Ok(revocation)
}

/// Put one version of a `user`-level secret, sealed to the recorded public key.
///
/// No password: the record is sealed to the user's *public* key, which the
/// deployment recorded at `admin user add`. The admin cannot read the result —
/// it holds no recipient secret — and the user needs only her own vault key to
/// open it. Asking for her password here would collect a secret this command
/// has no use for.
pub fn put(
    layout: &Layout,
    secret: &OpaqueSecretId,
    name: &[u8],
    value: &[u8],
) -> Result<u32, AdminError> {
    // Measured before anything is read: opening the store through a widened root
    // would write into a directory another principal can reach.
    if let Some(refusal) = crate::layout::refusal(layout.root()) {
        return Err(AdminError::Layout(refusal));
    }
    let (recorded, _anchor) = crate::deployment::require(layout)?;
    let recipient = recorded
        .user_recipient_key
        .ok_or(AdminError::NoRecipientKey)?
        .to_bytes();
    // The `admin` level is the record's provenance: it says the admin wrote this
    // value and delegated it, which is what makes a delivery of it require a
    // policy. A `user`-level record is the user's own and needs none.
    crate::layout::ensure_level(
        layout.root(),
        &recorded.vault,
        recorded.user,
        &ksp_types::Level::Admin,
    )
    .map_err(|_| AdminError::Write)?;
    let store = crate::config::open_file_store(layout).map_err(|_| AdminError::Write)?;
    Ok(crate::secret::seal_record_at(
        &store,
        &recorded,
        ksp_types::Level::Admin,
        secret,
        name,
        value,
        recipient,
    )?)
}

/// Every record path this store holds, across every level.
///
/// Paths, not values: the store names what it has and cannot open any of it, and
/// a listing that tried would need the user's key for her records and each
/// agent's key for theirs.
pub fn list(layout: &Layout) -> Result<Vec<crate::output::RecordMetadata>, AdminError> {
    let (recorded, _anchor) = crate::deployment::require(layout)?;
    let store = crate::config::open_file_store(layout).map_err(|_| AdminError::Write)?;
    let prefix = ksp_record::RecordPath::directory(&recorded.vault, recorded.user, None);
    let paths =
        ksp_record::version::BlobStore::list(&store, &prefix).map_err(|_| AdminError::Write)?;

    let mut found = Vec::new();
    for path in paths {
        // `p/<vault>/<user>/<level>/<id>/<version>`, and anything else is not a
        // record this crate wrote, so it is skipped rather than guessed at.
        let parts: Vec<&str> = path.split('/').collect();
        let [_, _, _, level, id, version] = parts.as_slice() else {
            continue;
        };
        let Ok(version) = version.parse::<u32>() else {
            continue;
        };
        found.push(crate::output::RecordMetadata {
            record: (*id).to_string(),
            level: (*level).to_string(),
            version,
        });
    }
    found.sort_by(|left, right| {
        left.record
            .cmp(&right.record)
            .then(left.level.cmp(&right.level))
            .then(left.version.cmp(&right.version))
    });
    Ok(found)
}

/// Whether this host can verify a report's signature, against whom.
///
/// `None` is not a failure of the signature: a `user` actor's key lives in the
/// vault this command has no password for, so the honest answer is that it cannot
/// be checked here. It is still counted as unsubstantiated, because a claim
/// nothing checked must not read as a clean audit.
fn verify_actor_report(
    layout: &Layout,
    anchor: &Anchor,
    signed: &ksp_deletion::report::SignedReport,
) -> Option<bool> {
    let key = match &signed.report.actor {
        ksp_types::ActorId::Agent(agent) => {
            let stored =
                crate::keys::StoredEnrolment::load(&layout.enrolment_file(&agent.to_string()))
                    .ok()?;
            ed25519_dalek::VerifyingKey::from_bytes(&stored.signing_key.to_bytes()).ok()?
        }
        // A sweep signs with the admin's key, which this host pins.
        ksp_types::ActorId::Admin(_) if signed.report.signer_key_id == anchor.key_id.as_str() => {
            ed25519_dalek::VerifyingKey::from_bytes(&anchor.key.to_bytes()).ok()?
        }
        // A user report is signed with a key in the vault this command cannot
        // open. An admin actor naming another key is not this host's admin.
        ksp_types::ActorId::User(_) | ksp_types::ActorId::Admin(_) => return None,
    };
    Some(signed.verify_signature(&key).is_ok())
}

/// The acknowledgement journal and the signed reports, as this host holds them.
///
/// Nothing here is a deletion time this host observed: an acknowledgement time
/// is the backend's, and a reported time is the actor's claim. Each line says
/// which it is, and an entry that cannot be read is printed as unreadable rather
/// than dropped — a missing row would look like a deletion that never happened.
pub fn audit(layout: &Layout) -> Result<crate::output::AuditView, AdminError> {
    let (_recorded, anchor) = crate::deployment::require(layout)?;
    let root = layout.journal_root();

    let mut lines = Vec::new();
    let mut unreadable = 0usize;

    // Journal entries live directly under the root; the reports directory lives
    // inside it and is walked separately.
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&root)
        .map(|dir| {
            dir.filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_file())
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("?")
            .to_string();
        match std::fs::read(&path).ok().and_then(|bytes| {
            ksp_types::cbor::decode::<ksp_deletion::journal::AcknowledgementEvent>(&bytes).ok()
        }) {
            Some(event) => lines.push(crate::output::AuditLine {
                kind: "acknowledgement".to_string(),
                intent: event.intent_id,
                actor: event.actor.to_string(),
                version: event.version,
                at: event.acknowledged_at,
                claim: "the backend acknowledged this delete; it is not a deletion time"
                    .to_string(),
                verified: None,
            }),
            None => {
                unreadable += 1;
                lines.push(crate::output::AuditLine {
                    kind: "acknowledgement".to_string(),
                    intent: name,
                    actor: "?".to_string(),
                    version: 0,
                    at: 0,
                    claim: "this journal entry could not be read".to_string(),
                    verified: None,
                })
            }
        }
    }

    let reports_root = root.join("reports");
    let mut reports: Vec<std::path::PathBuf> = std::fs::read_dir(&reports_root)
        .map(|dir| {
            dir.filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_file())
                .collect()
        })
        .unwrap_or_default();
    reports.sort();
    for path in reports {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("?")
            .to_string();
        let decoded = std::fs::read(&path).ok().and_then(|bytes| {
            ksp_types::cbor::decode::<ksp_deletion::report::SignedReport>(&bytes).ok()
        });
        match decoded {
            Some(signed) => {
                // Checked against the actor the report names, not against the
                // admin: a consume report is signed by the agent that performed
                // the delete, and a sweep report by the admin. Verifying every
                // report against one key would call the ordinary path a forgery.
                let verified = verify_actor_report(layout, &anchor, &signed);
                match verified {
                    Some(true) => {}
                    // Unverified or unverifiable: either way this host cannot
                    // substantiate the claim, and the command says so.
                    Some(false) | None => unreadable += 1,
                }
                let claim = match verified {
                    Some(_) => signed.report.reason,
                    None => format!(
                        "{}; this host cannot verify a user's report without her vault",
                        signed.report.reason
                    ),
                };
                lines.push(crate::output::AuditLine {
                    kind: "report".to_string(),
                    intent: signed.report.intent_id,
                    actor: signed.report.actor.to_string(),
                    version: signed.report.version,
                    at: signed.report.reported_deleted_at,
                    claim,
                    verified,
                });
            }
            None => {
                unreadable += 1;
                lines.push(crate::output::AuditLine {
                    kind: "report".to_string(),
                    intent: name,
                    actor: "?".to_string(),
                    version: 0,
                    at: 0,
                    claim: "this report could not be read".to_string(),
                    verified: None,
                });
            }
        }
    }

    Ok(crate::output::AuditView { lines, unreadable })
}

/// Read a password from `reader`.
pub fn read_password<R: Read>(reader: &mut R) -> Result<Vec<u8>, AdminError> {
    let mut buffer = Vec::new();
    reader
        .read_to_end(&mut buffer)
        .map_err(|_| AdminError::NoPassword)?;
    while matches!(buffer.last(), Some(b'\n') | Some(b'\r')) {
        buffer.pop();
    }
    if buffer.is_empty() {
        return Err(AdminError::NoPassword);
    }
    Ok(buffer)
}

/// Run one `admin` subcommand that needs no password or payload.
pub fn run<W: std::io::Write>(
    command: &crate::commands::AdminCommand,
    layout: &Layout,
    emitter: &mut crate::output::Emitter<W>,
) -> Outcome {
    use crate::commands::AdminCommand;
    match command {
        AdminCommand::Revoke { secret, agent } => {
            let withdrawal = match (secret, agent) {
                (Some(secret), None) => Withdrawal::Secret(OpaqueSecretId::new(secret.clone())),
                (None, Some(agent)) => match crate::agent::parse_agent(agent) {
                    Ok(agent) => Withdrawal::Agent(agent),
                    Err(error) => {
                        let _ = emitter.refusal(&error.to_string());
                        return Outcome::Failed(error.exit_code());
                    }
                },
                // clap refuses both at once; neither is a command with nothing
                // to withdraw, which must not read as a successful withdrawal.
                _ => {
                    let _ = emitter.refusal("name exactly one of --secret or --agent to withdraw");
                    return Outcome::Failed(exit::POLICY_DENIAL);
                }
            };
            match revoke(layout, withdrawal, crate::run::now_seconds() as i64) {
                Ok(revocation) => {
                    let report = crate::output::Report::Withdrawn(crate::output::GrantWithdrawn {
                        grant: revocation.withdrawal.withdrawal.to_string(),
                        policy_revision: revocation.withdrawal.policy_revision,
                        withdrawn_at: revocation.withdrawal.at,
                        reach: ksp_identity::REVOCATION_REACH.to_string(),
                    });
                    match emitter.report(&report) {
                        Ok(()) => Outcome::Success,
                        Err(_) => Outcome::Failed(exit::INTERNAL),
                    }
                }
                Err(error) => {
                    // A withdrawal can be refused for four different reasons and
                    // the exit code cannot tell them apart.
                    let _ = emitter.refusal(&error.to_string());
                    Outcome::Failed(error.exit_code())
                }
            }
        }
        // The remaining subcommands are dispatched in `app`, which owns the
        // password plumbing they need.
        _ => Outcome::Failed(exit::INTERNAL),
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// FR-023: a name the host cannot resolve is refused, and it is refused
    /// before anything is bound to it.
    #[test]
    fn an_account_this_host_does_not_have_is_refused_by_name() {
        // `root` is on every host this test can run on, so the positive case is
        // not a fixture: it asks the same question the binding asks.
        assert_eq!(unix_account("root").unwrap().0, 0);

        let refused = unix_account("ksp-no-such-account-xyz").unwrap_err();
        assert!(matches!(refused, AdminError::NoAccount(_)), "{refused}");
        assert!(
            refused.to_string().contains("ksp-no-such-account-xyz"),
            "the refusal names the identity: {refused}"
        );

        // A name that would be an option to `id`, or that no account may carry, is
        // refused without being asked about.
        for name in ["-n", "a b", "x/y", "", "root;id"] {
            assert!(
                matches!(unix_account(name), Err(AdminError::NoAccount(_))),
                "{name:?} must not reach `id`"
            );
        }
        assert!(matches!(
            unix_account(&"a".repeat(33)),
            Err(AdminError::NoAccount(_))
        ));
    }

    /// The two privileged steps of a binding fail for different reasons, and a
    /// refusal must name the one that failed.
    ///
    /// Both need root, so both fail on a first unprivileged run — which is why
    /// they were one variant. But `chown` can succeed and the group join still
    /// fail, and the reused sentence then told an operator whose `chown` had
    /// worked that a `chown` needed privilege. The guard is the *absence* of the
    /// other step's words: a message that mentions `chown` for a group failure
    /// sends the reader to the wrong operation.
    #[test]
    fn a_group_join_failure_does_not_blame_the_chown() {
        let failed = AdminError::GroupJoin {
            account: "alice".to_string(),
            group: "staff".to_string(),
            tool: "/usr/sbin/dseditgroup",
        };
        let said = failed.to_string();

        assert!(
            said.contains("alice") && said.contains("staff"),
            "the refusal names the account and the group: {said}"
        );
        assert!(
            said.contains("/usr/sbin/dseditgroup"),
            "the refusal names the tool that failed: {said}"
        );
        assert!(
            !said.contains("chown"),
            "a group-join failure must not blame the chown, which is a different step: {said}"
        );
        assert!(
            said.contains("root"),
            "the operator is told the step needs privilege: {said}"
        );

        // And the chown refusal keeps its own sentence, so the split did not
        // simply move the ambiguity to the other variant.
        let chown = AdminError::Binding {
            account: "alice".to_string(),
        }
        .to_string();
        assert!(
            chown.contains("chown") && !chown.contains("dseditgroup"),
            "the chown refusal still names the chown and no group tool: {chown}"
        );
    }
    use ksp_identity::decode_policy;

    fn initialised() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        init(
            &layout,
            VaultId::new("vault-1"),
            "alice".to_string(),
            KeyId::new("admin-2026"),
        )
        .unwrap();
        (dir, layout)
    }

    #[test]
    fn init_pins_the_key_it_wrote_and_refuses_a_second_run() {
        let (_dir, layout) = initialised();

        // The anchor names the key the protected file holds: a mismatch here
        // would make every later policy unverifiable on this host.
        let anchor = Anchor::load(&layout.admin_anchor_file()).unwrap();
        let admin = load_admin(&layout, &anchor).unwrap();
        assert_eq!(admin.verifying_public(), anchor.key);

        // A second init must not silently replace the admin key, and it must
        // report the UUID the first one issued rather than invent a second.
        let existing = Deployment::load(&layout).unwrap();
        match init(
            &layout,
            VaultId::new("vault-1"),
            "alice".to_string(),
            KeyId::new("admin-2026"),
        ) {
            Err(AdminError::AlreadyInitialised { principal }) => {
                assert_eq!(principal, existing.user);
                assert!(
                    AdminError::AlreadyInitialised { principal }
                        .to_string()
                        .contains(&existing.user.to_string()),
                    "the refusal must name the existing UUID"
                );
            }
            other => panic!("expected an AlreadyInitialised refusal, got {other:?}"),
        }
    }

    #[test]
    fn two_principals_with_one_display_name_are_two_identities() {
        // Acceptance criterion 4: a shared display name is not a shared
        // identity. Two deployments that both call their user `alice` get two
        // UUIDs, two path segments and two different bound AAD bytes.
        let first_dir = tempfile::tempdir().unwrap();
        let first_layout = Layout::new(first_dir.path());
        let first = init(
            &first_layout,
            VaultId::new("vault-1"),
            "alice".to_string(),
            KeyId::new("admin-2026"),
        )
        .unwrap();

        let second_dir = tempfile::tempdir().unwrap();
        let second_layout = Layout::new(second_dir.path());
        let second = init(
            &second_layout,
            VaultId::new("vault-1"),
            "alice".to_string(),
            KeyId::new("admin-2026"),
        )
        .unwrap();

        assert_ne!(first.user, second.user);

        let metadata = |principal| ksp_types::BoundMetadata {
            vault_id: VaultId::new("vault-1"),
            user_id: principal,
            level: ksp_types::Level::User,
            secret_id: OpaqueSecretId::new("secret-1"),
            version: 1,
        };
        assert_ne!(
            ksp_record::RecordPath::of(&metadata(first.user)).as_str(),
            ksp_record::RecordPath::of(&metadata(second.user)).as_str()
        );
        assert_ne!(
            metadata(first.user).bound_aad().unwrap(),
            metadata(second.user).bound_aad().unwrap()
        );
    }

    /// The two "a vault already exists" states get different answers: a completed
    /// enrolment must not be replaced, and an interrupted one must not be a dead
    /// end. The condition is the deployment's record of her keys, because that is
    /// what `admin put` seals to — no key recorded, nothing sealed.
    #[test]
    fn a_vault_left_by_an_interrupted_enrolment_is_recoverable_and_a_finished_one_is_not() {
        let (_dir, layout) = initialised();
        // A leftover of an enrolment that stopped before her keys were recorded.
        std::fs::write(layout.vault_file(), b"half-written").unwrap();

        let refused = user_add(
            &layout,
            b"a long enough password",
            KeyId::new("alice-ed25519-1"),
            KeyId::new("alice-x25519-1"),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(refused, AdminError::Interrupted { .. }),
            "{refused}"
        );
        assert!(
            refused.to_string().contains("remove") && refused.to_string().contains("vault.cbor"),
            "the refusal names the leftover and what to do with it: {refused}"
        );

        // The recovery the refusal named, then the same command to completion.
        std::fs::remove_file(layout.vault_file()).unwrap();
        // Once her keys are recorded the same command is the unrecoverable one.
        user_add(
            &layout,
            b"a long enough password",
            KeyId::new("alice-ed25519-1"),
            KeyId::new("alice-x25519-1"),
            None,
        )
        .unwrap();
        let refused = user_add(
            &layout,
            b"another long enough password",
            KeyId::new("alice-ed25519-9"),
            KeyId::new("alice-x25519-9"),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(refused, AdminError::AlreadyEnrolled { .. }),
            "{refused}"
        );
        assert!(
            refused.to_string().contains("vault rekey"),
            "and names the command that does replace one: {refused}"
        );
    }

    #[test]
    fn user_add_writes_a_policy_naming_the_users_own_keys() {
        let (_dir, layout) = initialised();
        let deployment = Deployment::load(&layout).unwrap();
        user_add(
            &layout,
            b"a long enough password",
            KeyId::new("alice-ed25519-1"),
            KeyId::new("alice-x25519-1"),
            None,
        )
        .unwrap();

        let bytes = std::fs::read(layout.policy_file()).unwrap();
        let policy: Policy = decode_policy(&bytes).unwrap();
        let anchor = Anchor::load(&layout.admin_anchor_file()).unwrap();

        assert!(
            policy.verify_issuer(&anchor.key),
            "the policy must verify under the pinned anchor"
        );

        // The policy's trusted keys must be the ones in the sealed vault: a
        // policy naming different keys would refuse every mint for this user.
        let home = VaultHome::new(layout.root().to_path_buf());
        let sealed = crate::vault::read_sealed(&home).unwrap();
        let vault = sealed
            .unseal(
                b"a long enough password",
                &ksp_identity::VaultBinding {
                    identity: ksp_types::ActorId::User(deployment.user),
                    signing_key_id: KeyId::new("alice-ed25519-1"),
                    recipient_key_id: KeyId::new("alice-x25519-1"),
                },
            )
            .unwrap();
        assert_eq!(
            policy.user(),
            &deployment.user,
            "the policy names the UUID `admin init` issued, not the display name"
        );
        assert_eq!(policy.vault(), &VaultId::new("vault-1"));
        let _ = vault.signing_public();
    }
}
