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

### 1.1 The signature is keyless Sigstore, and you can check that

There is **no long-lived signing key**. Signing is Sigstore keyless: the workflow
requests a short-lived OIDC token from GitHub, exchanges it at Fulcio for a
certificate that lives for minutes, and records the signature in the Rekor
transparency log. Nothing is stored that could leak, and there is no key to
rotate or revoke.

That is a claim, so here is how to check it rather than take it.

**Check the trusted root.** `gh` ships the Sigstore trust material it verifies
against. Ask it what that is:

```bash
gh attestation trusted-root | head -1 | jq '{
  mediaType,
  tlogs: [.tlogs[].baseUrl],
  cas: [.certificateAuthorities[].uri]
}'
```

You should see Sigstore's own roots, not a private CA:

```json
{
  "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
  "tlogs": ["https://rekor.sigstore.dev", "https://log2025-1.rekor.sigstore.dev"],
  "cas": ["https://fulcio.sigstore.dev", "https://fulcio.sigstore.dev"]
}
```

If a project signed with a long-lived key, verification would not go through
Fulcio at all and this root would be irrelevant to it.

**Check the certificate identity.** The attestation carries the certificate
Fulcio issued, and its identity is the workflow rather than a person. Download
the bundle for a file you already have, then read the certificate:

```bash
gh attestation download ./ksp-x86_64-unknown-linux-musl.tar.xz --repo bruj0/keyspout
# The bundle is JSONL; the certificate is under the signature it carries.
jq -r 'select(.verificationResult) |
       .verificationResult.signature.certificate |
       {issuer, subject: .subjectAlternativeName}' ./*.jsonl
```

The issuer is `https://token.actions.githubusercontent.com` and the subject is
the release workflow path. That is what "keyless" means concretely: the signer is
an OIDC identity that existed for the length of one job, not a key anyone holds.

**Verify offline.** The same download gives you a bundle that verifies without
network access to GitHub:

```bash
gh attestation verify ./ksp-x86_64-unknown-linux-musl.tar.xz \
  --bundle ./*.jsonl \
  --repo bruj0/keyspout \
  --signer-workflow bruj0/keyspout/.github/workflows/release.yml
```

**Check the transparency log.** Rekor is append-only and public, so the entry can
be found without trusting this repository at all. Search
`https://search.sigstore.dev` for the artifact's digest. A signature that is not
in the log is not a signature this project produced.

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
The two disagree about what counts as a vulnerability, which is why both run.

That disagreement found a real one. `cargo audit` classified `rustix` 1.1.5
`RUSTSEC-2026-0486` as an *unsound* warning and exited 0; OSV-Scanner reported it
as a vulnerability. It was real — the xattr functions marked unwritten bytes as
initialised when given a zero-length buffer — and it is **fixed**: the tree is on
`rustix` 1.1.6, the version the advisory names.

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
| **T2** | A dependency is compromised | `Cargo.lock` pinning, `cargo audit`, OSV-Scanner, and `cargo-vet` (§6) | A compromised crate that no advisory names yet ships until someone reviews it. `cargo-vet` is the control for that, and it is configured but has **no audits yet** — see §6. |
| **T3** | The build workflow is modified | Every action pinned to a commit SHA; Dependabot bumps them as reviewable commits; the gate runs before any build | Someone with write access to `.github/` can still change it. The change is visible in the repository history. |
| **T4** | A published binary is replaced | Attestation makes it detectable | Release immutability is unavailable on this repository. Detection, not prevention. |
| **T5** | A binary is built elsewhere and published as if from CI | Provenance attestation names the workflow and commit; the `release` environment requires human approval before publish | A leaked token cannot publish without the approval, but an approved publish of a bad build is still a publish. |

Two things follow from the table, and they are the honest summary:

1. **T1 is a review problem.** No build system can solve it. What this pipeline
   does is make a backdoor require an **observable commit** rather than a quiet
   binary swap.
2. **T4 is detected, not prevented.** Verify your download. That is the control.

---

## 6. Dependency review: configured, with no audits yet

`cargo-vet` is the control that catches a compromised dependency before an
advisory names it — it is your own review of what the code does, rather than a
database lookup.

It is **configured and enforced in CI**. `cargo vet --locked` runs on every gate
and fails when a dependency has neither an audit nor an exemption.

**But it currently reviews nothing.** The state, measured:

```
$ cargo vet --locked
Vetting Succeeded (314 exempted)
$ wc -l supply-chain/audits.toml
```

`supply-chain/config.toml` carries **314 exemptions** — one per crate in the
tree, each marked `safe-to-deploy` — and `supply-chain/audits.toml` is **empty**.
An exemption is a record that nobody has reviewed the crate yet. It is the honest
starting state, not a review.

What that means for you:

- **A new dependency fails the gate.** That is the control working: adding a crate
  requires someone to write an exemption or an audit, which is a decision made in
  a commit rather than a silent pull.
- **The existing 314 crates are not reviewed.** An exemption says "not yet", and
  the count is the size of the backlog, not a measure of coverage.

To reduce the backlog, `cargo vet suggest` lists the cheapest reviews to do
first — usually the crates with the most dependents. Each review replaces an
exemption with an audit entry that says what was checked.

`docs/supply-chain-vetting.md` records the mechanics.

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
