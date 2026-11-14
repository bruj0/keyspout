//! The decision half of `ksp run`: verify, confine, then launch.
//!
//! # The order, and why it is enforced here
//!
//! The proof of possession is verified **before** anything is delivered, because
//! a token without a valid proof must never reach a child. Confinement is applied
//! **before** the child is launched, because Landlock confines the process tree
//! that opts in — applying it after the child exists confines nothing that
//! matters. And the plaintext reaches the child through exactly one channel.
//!
//! The child and the confiner are traits rather than calls into `std::process`
//! and `landlock`, so the order is assertable: a test can record when each ran
//! and prove the sequence, which a test that spawns a real process cannot do
//! without racing it.
//!
//! # The plaintext
//!
//! `--env` is the declared exception: it hands plaintext to a child deliberately.
//! Nothing else here carries a value. [`Delivery`] has no `Display`, and no
//! function in this module writes a plaintext byte to the emitter.

use ksp_identity::run::{HostKeys, PresentedProof, RunOutcome, RunRequest, verify_run};
use ksp_posture::ConfinementSpec;
use zeroize::Zeroize;

use crate::exit::{self, Outcome};

/// Why a child could not be launched.
#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    /// The operating system refused to start the child.
    #[error("the child could not be started")]
    Spawn,
    /// The child started and exited non-zero.
    #[error("the child exited with {code}")]
    NonZero {
        /// The child's exit status.
        code: i32,
    },
}

/// Starts the child.
pub trait ChildLauncher {
    /// Launch `argv`, handing it `env` as the child's environment only.
    fn launch(&self, argv: &[String], env: &[(String, String)]) -> Result<i32, LaunchError>;
}

/// Why a delivery could not be confined, before any child exists.
///
/// One type for both reasons so the gate has exactly one branch: a ruleset that
/// could not be established, and a descriptor that would have escaped it, are the
/// same refusal to the operator — the secret is not delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityRefusal {
    /// The kernel could not establish the required confinement.
    Confinement(ksp_posture::ConfinementRefusal),
    /// An inherited descriptor could not be closed, so the child would have held
    /// a handle the ruleset cannot restrict.
    Descriptors(String),
}

impl std::fmt::Display for CapabilityRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Confinement(refusal) => write!(f, "{refusal}"),
            Self::Descriptors(cause) => write!(
                f,
                "required confinement cannot be established by descriptor sanitation: {cause}; \
                 the child was not started"
            ),
        }
    }
}

impl std::error::Error for CapabilityRefusal {}

/// Applies the confinement ruleset to this process tree.
pub trait Confiner {
    /// Apply `spec`. Called exactly once, before the launch.
    ///
    /// The spec is passed in rather than held by the implementor: a confiner that
    /// carried its own ruleset could apply a weaker one and the gate would have no
    /// way to notice, which would make the run's confinement a property of the
    /// caller's diligence rather than of the gate.
    ///
    /// A failure is typed, not a string: the gate prints it, and "Landlock failed"
    /// would leave the operator guessing which right or path refused.
    fn apply(&self, spec: &ConfinementSpec) -> Result<(), CapabilityRefusal>;
}

/// A delivered plaintext, and how it reaches the child.
///
/// Deliberately has no `Display`, no `Debug` that reveals bytes, and no accessor
/// that returns them: the only way out is [`RunGate::deliver`], which hands them
/// to a launcher as environment entries.
pub struct Delivery {
    name: String,
    value: Vec<u8>,
}

impl Delivery {
    /// Wrap a plaintext for one environment variable.
    pub fn new(name: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }

    /// The variable name, which is not secret.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Named, never rendered: a derived Debug would put the value in every
        // panic message and test failure that touched a Delivery.
        f.debug_struct("Delivery")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Everything the gate needs to decide, then launch.
pub struct RunGate<'a> {
    /// The request the caller believes it is making.
    pub request: &'a RunRequest,
    /// The proof presented with it, if any.
    pub proof: Option<PresentedProof<'a>>,
    /// The host's keys for the enrolled agent.
    pub keys: HostKeys<'a>,
    /// The confinement to apply before launching.
    pub confinement: &'a ConfinementSpec,
    /// The plaintext to deliver, if the verification succeeds.
    pub delivery: Option<Delivery>,
}

/// Verify, confine, launch.
///
/// Returns the outcome the process should carry: `0` when the child exited zero,
/// `6`/`8` for the two refusal classes, or the child's own code. A refusal means
/// **no confinement was applied and no child ran** — there is nothing to undo.
pub fn gate(
    gate: RunGate<'_>,
    confiner: &dyn Confiner,
    launcher: &dyn ChildLauncher,
    argv: &[String],
) -> Outcome {
    // 1. Verify before anything else. A refusal here never touches the host.
    if let RunOutcome::Refuse(refusal) = verify_run(gate.keys, gate.request, gate.proof) {
        return Outcome::Failed(exit::from_run(&refusal));
    }

    // 2. Confine before launching. If required confinement fails, the run is
    //    refused rather than launched unconfined.
    if let Err(refusal) = confiner.apply(gate.confinement) {
        // Required confinement that the host cannot provide is a capability
        // refusal: the host cannot do what the run needs, which is a different
        // statement from a failed proof.
        //
        // The reason is printed before the exit code reaches `main`, because the
        // generic sentence for a capability refusal ("cannot admit this lease")
        // does not say which right or path the host is missing — and an operator
        // who cannot tell what to fix works around the confinement instead.
        let _ = crate::output::Emitter::new(false, std::io::stderr()).refusal(&refusal.to_string());
        return Outcome::Failed(exit::CAPABILITY_REFUSAL);
    }

    // 3. Launch, handing the plaintext over as environment entries and nowhere
    //    else.
    // The plaintext is *moved* here, never cloned: a clone would be a second copy
    // with no owner responsible for wiping it, which is the recovery copy this
    // subsystem exists to not create.
    let env: Vec<(String, String)> = match gate.delivery {
        None => Vec::new(),
        Some(delivery) => match String::from_utf8(delivery.value) {
            Ok(value) => vec![(delivery.name, value)],
            Err(error) => {
                // An environment variable must be text. Wipe the bytes before
                // refusing so the failed path leaves nothing behind either.
                let mut bytes = error.into_bytes();
                bytes.as_mut_slice().zeroize();
                return Outcome::Failed(exit::INTERNAL);
            }
        },
    };

    match launcher.launch(argv, &env) {
        Ok(0) => Outcome::Success,
        Ok(code) => Outcome::Failed(code),
        Err(_) => Outcome::Failed(exit::INTERNAL),
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct RecordingConfiner(Rc<RefCell<Vec<&'static str>>>, bool);
    impl Confiner for RecordingConfiner {
        fn apply(&self, _spec: &ConfinementSpec) -> Result<(), CapabilityRefusal> {
            self.0.borrow_mut().push("confine");
            if self.1 {
                Ok(())
            } else {
                Err(capability_refusal())
            }
        }
    }

    /// Records the spec it was handed, so the test can check the gate passed
    /// the *required* one rather than anything the confiner preferred.
    #[derive(Default)]
    struct SpecSpy(RefCell<Option<(usize, bool)>>);
    impl Confiner for SpecSpy {
        fn apply(&self, spec: &ConfinementSpec) -> Result<(), CapabilityRefusal> {
            *self.0.borrow_mut() = Some((spec.rules().len(), spec.is_required()));
            Ok(())
        }
    }

    struct RecordingLauncher(Rc<RefCell<Vec<&'static str>>>, i32);
    impl ChildLauncher for RecordingLauncher {
        fn launch(&self, _argv: &[String], _env: &[(String, String)]) -> Result<i32, LaunchError> {
            self.0.borrow_mut().push("launch");
            Ok(self.1)
        }
    }

    fn spec() -> ConfinementSpec {
        ConfinementSpec::required(Vec::new())
    }

    /// A refusal of the kind a host without Landlock produces, built through the
    /// same path the real confiner uses.
    fn capability_refusal() -> CapabilityRefusal {
        CapabilityRefusal::Confinement(
            spec()
                .refusal_for(None)
                .expect("no Landlock must refuse a required spec"),
        )
    }

    fn request() -> RunRequest {
        RunRequest {
            jti: "jti-1".to_owned(),
            record_version: ksp_types::RecordVersion(1),
            record_path: "p/v/a/agent-7/s/1".to_owned(),
            argv: vec![b"printenv".to_vec()],
            now: 1_700_000_000,
        }
    }

    fn gate_with<'a>(
        request: &'a RunRequest,
        confinement: &'a ConfinementSpec,
        keys: HostKeys<'a>,
    ) -> RunGate<'a> {
        RunGate {
            request,
            proof: None,
            keys,
            confinement,
            delivery: None,
        }
    }

    #[test]
    fn a_missing_signing_key_refuses_with_six_and_never_confines_or_launches() {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let request = request();
        let confinement = spec();
        let keys = HostKeys {
            signing_public: None,
            recipient_public: None,
        };
        let runner = gate_with(&request, &confinement, keys);

        let outcome = gate(
            runner,
            &RecordingConfiner(Rc::clone(&trace), true),
            &RecordingLauncher(Rc::clone(&trace), 0),
            &["true".to_owned()],
        );

        assert_eq!(outcome.code(), crate::exit::MISSING_KEY);
        assert!(
            trace.borrow().is_empty(),
            "a refusal must not confine or launch: {:?}",
            trace.borrow()
        );
    }

    #[test]
    fn a_valid_proof_confines_before_launching() {
        // The order is the property: confinement must be in force before the
        // child exists, because Landlock confines the tree that opts in.
        let trace = Rc::new(RefCell::new(Vec::new()));
        let request = request();
        let confinement = spec();
        let signing = ksp_identity::SigningSecretKey::generate();
        let public = signing.verifying_public();
        let recipient = ksp_identity::RecipientPublicKey::from_bytes([21u8; 32]);

        let preimage = ksp_identity::PopPreimage::new(
            &request.jti,
            request.record_version,
            &request.record_path,
            &request.argv,
            ksp_identity::bucket_start(request.now),
        )
        .unwrap();
        let signature = ksp_identity::sign_pop(&signing, &preimage).unwrap();

        let keys = HostKeys {
            signing_public: Some(&public),
            recipient_public: Some(&recipient),
        };
        let runner = RunGate {
            request: &request,
            proof: Some(PresentedProof {
                preimage: &preimage,
                signature: &signature,
            }),
            keys,
            confinement: &confinement,
            delivery: Some(Delivery::new("API_TOKEN", b"the-plaintext".to_vec())),
        };

        let outcome = gate(
            runner,
            &RecordingConfiner(Rc::clone(&trace), true),
            &RecordingLauncher(Rc::clone(&trace), 0),
            &["printenv".to_owned()],
        );

        assert_eq!(outcome.code(), crate::exit::SUCCESS);
        assert_eq!(
            *trace.borrow(),
            vec!["confine", "launch"],
            "confinement must complete before the child is launched"
        );
    }

    /// A proof that is real but names a different request is still a refusal.
    ///
    /// The gate must pass *this* request into `verify_run`; a gate that verified
    /// the proof against anything else would accept a signature the agent made
    /// for some other invocation.
    #[test]
    fn a_proof_made_for_another_request_refuses_before_confining_or_launching() {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let request = request();
        let confinement = spec();
        let signing = ksp_identity::SigningSecretKey::generate();
        let public = signing.verifying_public();
        let recipient = ksp_identity::RecipientPublicKey::from_bytes([22u8; 32]);

        // Signed over a different argv, so the signature is valid for a request
        // this run is not making.
        let elsewhere = vec![b"printenv".to_vec(), b"OTHER_SECRET".to_vec()];
        let preimage = ksp_identity::PopPreimage::new(
            &request.jti,
            request.record_version,
            &request.record_path,
            &elsewhere,
            ksp_identity::bucket_start(request.now),
        )
        .unwrap();
        let signature = ksp_identity::sign_pop(&signing, &preimage).unwrap();

        let keys = HostKeys {
            signing_public: Some(&public),
            recipient_public: Some(&recipient),
        };
        let runner = RunGate {
            request: &request,
            proof: Some(PresentedProof {
                preimage: &preimage,
                signature: &signature,
            }),
            keys,
            confinement: &confinement,
            delivery: Some(Delivery::new("API_TOKEN", b"the-plaintext".to_vec())),
        };

        let outcome = gate(
            runner,
            &RecordingConfiner(Rc::clone(&trace), true),
            &RecordingLauncher(Rc::clone(&trace), 0),
            &["printenv".to_owned()],
        );

        assert_eq!(outcome.code(), crate::exit::UNPROVEN);
        assert!(
            trace.borrow().is_empty(),
            "a refused proof must not confine or launch anything, got {:?}",
            *trace.borrow()
        );
    }

    #[test]
    fn a_failed_required_confinement_refuses_the_run_instead_of_launching_unconfined() {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let request = request();
        let confinement = spec();
        let signing = ksp_identity::SigningSecretKey::generate();
        let public = signing.verifying_public();
        let recipient = ksp_identity::RecipientPublicKey::from_bytes([21u8; 32]);
        let preimage = ksp_identity::PopPreimage::new(
            &request.jti,
            request.record_version,
            &request.record_path,
            &request.argv,
            ksp_identity::bucket_start(request.now),
        )
        .unwrap();
        let signature = ksp_identity::sign_pop(&signing, &preimage).unwrap();
        let keys = HostKeys {
            signing_public: Some(&public),
            recipient_public: Some(&recipient),
        };
        let runner = RunGate {
            request: &request,
            proof: Some(PresentedProof {
                preimage: &preimage,
                signature: &signature,
            }),
            keys,
            confinement: &confinement,
            delivery: None,
        };

        let outcome = gate(
            runner,
            &RecordingConfiner(Rc::clone(&trace), false),
            &RecordingLauncher(Rc::clone(&trace), 0),
            &["true".to_owned()],
        );

        assert_eq!(outcome.code(), crate::exit::CAPABILITY_REFUSAL);
        assert_eq!(
            *trace.borrow(),
            vec!["confine"],
            "a run whose required confinement failed must not launch"
        );
    }

    fn signed_runner<'a>(
        request: &'a RunRequest,
        confinement: &'a ConfinementSpec,
        public: &'a ksp_identity::VerifyingPublicKey,
        recipient: &'a ksp_identity::RecipientPublicKey,
        delivery: Option<Delivery>,
        preimage: &'a ksp_identity::PopPreimage,
        signature: &'a ksp_identity::TokenSignature,
    ) -> RunGate<'a> {
        RunGate {
            request,
            proof: Some(PresentedProof {
                preimage,
                signature,
            }),
            keys: HostKeys {
                signing_public: Some(public),
                recipient_public: Some(recipient),
            },
            confinement,
            delivery,
        }
    }

    #[test]
    fn the_gate_hands_the_required_spec_to_the_confiner() {
        // The confiner is a collaborator, not an authority: it must be told the
        // spec the run requires. A confiner left to its own devices could apply a
        // weaker ruleset and the gate would never know.
        let request = request();
        let confinement = ConfinementSpec::required(Vec::new());
        let signing = ksp_identity::SigningSecretKey::generate();
        let public = signing.verifying_public();
        let recipient = ksp_identity::RecipientPublicKey::from_bytes([21u8; 32]);
        let preimage = ksp_identity::PopPreimage::new(
            &request.jti,
            request.record_version,
            &request.record_path,
            &request.argv,
            ksp_identity::bucket_start(request.now),
        )
        .unwrap();
        let signature = ksp_identity::sign_pop(&signing, &preimage).unwrap();
        let runner = signed_runner(
            &request,
            &confinement,
            &public,
            &recipient,
            None,
            &preimage,
            &signature,
        );

        let spy = SpecSpy::default();
        let _ = gate(
            runner,
            &spy,
            &RecordingLauncher(Rc::new(RefCell::new(Vec::new())), 0),
            &["true".to_owned()],
        );

        let seen = spy.0.borrow().expect("the confiner must be called");
        assert!(
            seen.1,
            "the confiner must be told the run requires confinement"
        );
        assert_eq!(seen.0, confinement.rules().len());
    }

    #[test]
    fn a_plaintext_that_is_not_text_is_refused_rather_than_delivered_lossily() {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let request = request();
        let confinement = spec();
        let signing = ksp_identity::SigningSecretKey::generate();
        let public = signing.verifying_public();
        let recipient = ksp_identity::RecipientPublicKey::from_bytes([21u8; 32]);
        let preimage = ksp_identity::PopPreimage::new(
            &request.jti,
            request.record_version,
            &request.record_path,
            &request.argv,
            ksp_identity::bucket_start(request.now),
        )
        .unwrap();
        let signature = ksp_identity::sign_pop(&signing, &preimage).unwrap();
        let runner = signed_runner(
            &request,
            &confinement,
            &public,
            &recipient,
            Some(Delivery::new("API_TOKEN", vec![0xff, 0xfe, 0x00])),
            &preimage,
            &signature,
        );

        let outcome = gate(
            runner,
            &RecordingConfiner(Rc::clone(&trace), true),
            &RecordingLauncher(Rc::clone(&trace), 0),
            &["true".to_owned()],
        );

        // An environment variable must be text; a lossy conversion would deliver
        // a different value than the one stored.
        assert_eq!(outcome.code(), crate::exit::INTERNAL);
        assert_eq!(*trace.borrow(), vec!["confine"], "nothing is launched");
    }

    #[test]
    fn a_delivery_never_renders_its_value() {
        let delivery = Delivery::new("API_TOKEN", b"super-secret-value".to_vec());
        let rendered = format!("{delivery:?}");
        assert!(rendered.contains("API_TOKEN"));
        assert!(
            !rendered.contains("super-secret-value"),
            "a Delivery must not print its value: {rendered}"
        );
    }
}
