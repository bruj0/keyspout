# Security

How a Keyspout release is built, how you can check that the binary you downloaded
came from the source you can read, and what that check does **not** prove.

Read the third section before you rely on the first two.

---

## 1. Verify a download

Every release asset carries a GitHub build-provenance attestation. It records
which repository, which workflow and which commit produced the bytes.

```bash
# 1. Download the artifact.
gh release download v0.1.0 --repo bruj0/keyspout \
  --pattern 'ksp-x86_64-unknown-linux-musl.tar.xz'

# 2. Prove it was built by this repository's release workflow.
gh attestation verify ksp-x86_64-unknown-linux-musl.tar.xz \
  --repo bruj0/keyspout \
  --signer-workflow bruj0/keyspout/.github/workflows/release.yml

# 3. Check the checksum against the published list.
gh release download v0.1.0 --repo bruj0/keyspout --pattern 'sha256.sum'
sha256sum --check sha256.sum --ignore-missing

# 4. Read what is inside it.
gh release download v0.1.0 --repo bruj0/keyspout --pattern '*sbom.cdx.json'
jq '.components[] | {name, version}' ksp-*-sbom.cdx.json | head
```

Step 2 is the one that answers the question. `gh attestation verify` exits 0 only
if the artifact's digest is named in an attestation signed by that workflow, in
that repository, through GitHub's OIDC identity. A binary built anywhere else
fails it.

The `.deb` and `.rpm` are attested too. Use the same command on them.

### If you do not have `gh`

The attestation is a Sigstore bundle verifiable with `cosign`:

```bash
cosign verify-blob \
  --bundle ksp-x86_64-unknown-linux-musl.tar.xz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/bruj0/keyspout/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ksp-x86_64-unknown-linux-musl.tar.xz
```

---

## 2. What verification proves

It proves **which source produced the binary**. Specifically:

- the artifact was built by `.github/workflows/release.yml` in
  `bruj0/keyspout`, not by a fork, a laptop, or a different workflow;
- it was built from a specific commit, whose SHA is in the attestation;
- the bytes you hold are the bytes that build produced, because the attestation
  names their digest.

That is the whole claim. It is a real one: a binary with code added after the
build — replaced on the release page, mirrored elsewhere, or handed to you by
someone else — fails the check.

---

## 3. What verification does **not** prove

**It does not prove the source is safe.** A backdoor committed to `main` and
built by the release workflow produces a perfectly valid attestation. The
attestation says "this came from that commit", and it is telling the truth.

Verification moves the question from *"is this binary what the project built?"*
to *"is the project's code what I want to run?"*. The second question is answered
by reading the code, not by a tool.

**It does not prove a release asset cannot be replaced.** GitHub's release
immutability is not available on this repository (see §5), so someone with write
access could replace an asset. The attestation makes that **detectable** — the
new bytes fail step 2 — but not impossible.

**It does not prove the dependency tree is clean.** See §4.

---

## 4. The vulnerability scanner, and its blind spot

Two scanners run on every release.

`cargo audit` reads `Cargo.lock` against the RustSec advisory database. It is
fast and it runs on every commit.

`OSV-Scanner` reads the same lockfile against a wider advisory set (OSV.dev
aggregates RustSec, the GitHub Advisory Database and NVD) and gates on severity.
The two disagree about what counts as a vulnerability — `cargo audit` currently
classifies two findings in this tree as *warnings* and exits 0, while OSV-Scanner
reports them as vulnerabilities — which is why both run.

**The blind spot, stated plainly.** OSV-Scanner has an experimental Rust
call-graph analysis that is meant to answer "does this vulnerable function
actually reach our code?". **On this repository it does not work**: it cannot
build the workspace, so every finding arrives with no analysis conclusion.

The gate therefore treats **a finding with no analysis conclusion as
reachable**. That is the conservative direction, and it means:

- what the gate buys today is a **severity-filtered presence check** over a wider
  advisory set than `cargo audit`;
- it does **not** buy reachability analysis, and a green gate does not mean the
  vulnerable functions are unreachable;
- an advisory class that is not a code weakness — `unmaintained`, `yanked` — is
  reported and does not fail the gate. `unsound` **does** fail it, because it is
  a real code weakness.

If you are relying on the scanner to tell you a vulnerable dependency is
unreachable: it cannot, yet.

---

## 5. The attack surface, and what covers it

| # | Attack | Control | Residual risk |
|---|---|---|---|
| **T1** | A maintainer commits a backdoor | Code review | **Not covered by any tool.** The attestation proves the binary matches the commit; it cannot prove the commit is honest. |
| **T2** | A dependency is compromised | `Cargo.lock` pinning, `cargo audit`, OSV-Scanner, and `cargo-vet` once initialised (§6) | A compromised crate that no advisory names yet ships until someone reviews it. `cargo-vet` is the control for that, and it is not enabled. |
| **T3** | The build workflow is modified | Every action pinned to a commit SHA; Dependabot bumps them as reviewable commits; the gate runs before any build | Someone with write access to `.github/` can still change it. The change is visible in the repository history. |
| **T4** | A published binary is replaced | Attestation makes it detectable | Release immutability is unavailable on this repository. Detection, not prevention. |
| **T5** | A binary is built elsewhere and published as if from CI | Provenance attestation names the workflow and commit; the `release` environment requires human approval before publish | A leaked token cannot publish without the approval, but an approved publish of a bad build is still a publish. |

Two things follow from the table, and they are the honest summary:

1. **T1 is a review problem.** No build system can solve it. What this pipeline
   does is make a backdoor require an **observable commit** rather than a quiet
   binary swap.
2. **T4 is detected, not prevented.** Verify your download. That is the control.

---

## 6. Dependency review is not enabled

`cargo-vet` is the control that catches a compromised dependency before an
advisory names it — it is your own review of what the code does, rather than a
database lookup.

It is **not initialised on this repository**. `cargo vet init` is interactive and
writes a ledger of audit entries; writing that ledger by hand would mean claiming
reviews nobody performed, which is worse than having no ledger at all.

The gate prints `cargo vet: NOT CONFIGURED` on every run rather than skipping
silently. `docs/supply-chain-vetting.md` records what enabling it takes.

---

## 7. Reproducing the build

The release is built with path remapping and a pinned timestamp, so two builds of
the same commit in the same container image produce the same bytes.

```bash
git clone https://github.com/bruj0/keyspout && cd keyspout
git checkout v0.1.0

export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export RUSTFLAGS="--remap-path-prefix=$PWD=/build/keyspout \
  --remap-path-prefix=$HOME/.cargo=/build/cargo \
  --remap-path-prefix=$HOME/.rustup=/build/rustup"

cargo build --release --locked -p ksp-cli
sha256sum target/release/ksp
```

Compare that digest with the one in `sha256.sum`.

**This is a narrow claim.** It holds for the same container image, the same
toolchain and the same linker. A different distribution's linker will produce
different bytes for reasons that have nothing to do with tampering. If your
digest does not match, that is not evidence of a backdoor — use the attestation
in §1, which is the check that answers the question.

---

## 8. Reporting a vulnerability

Email **ramakandra@gmail.com** with a description and, if you have one, a
reproduction. Do not open a public issue for a security problem.

Expect an acknowledgement within a few days. There is one maintainer, so a fix
may take longer than an acknowledgement; you will be told which it is.

Please allow time for a fix before disclosing publicly.
