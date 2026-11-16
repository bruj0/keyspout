# Security

How a Keyspout release is built, how you can check that the binary you downloaded
came from the source you can read, and what that check does **not** prove.

Read §3 before you rely on §1 and §2.

---

## Verify a release — all the commands, in one place

Copy these in order. Each one is explained below, and each is a claim you can
check rather than take on trust.

```bash
# --- 1. Download an artifact and its checksum list -------------------------
# The tag is resolved rather than written down. A pinned tag in a recipe goes
# stale silently: it keeps succeeding against an old release while reading as
# the way to verify the current one.
TAG=$(gh release view --repo bruj0/keyspout --json tagName -q .tagName)
gh release download "$TAG" --repo bruj0/keyspout \
  --pattern 'ksp-x86_64-unknown-linux-musl.tar.xz'
gh release download "$TAG" --repo bruj0/keyspout --pattern 'sha256.sum'

# --- 2. Prove which commit and workflow built it --------------------------
gh attestation verify ksp-x86_64-unknown-linux-musl.tar.xz \
  --repo bruj0/keyspout \
  --signer-workflow bruj0/keyspout/.github/workflows/attest.yml

# --- 3. Check the bytes against the published checksums -------------------
sha256sum --check sha256.sum --ignore-missing

# --- 4. Confirm the signature is keyless Sigstore, not a private key ------
gh attestation trusted-root | head -1 | jq '{
  mediaType,
  tlogs: [.tlogs[].baseUrl],
  cas: [.certificateAuthorities[].uri]
}'
# expect: rekor.sigstore.dev + fulcio.sigstore.dev

# --- 5. Read the certificate identity ------------------------------------
gh attestation download ./ksp-x86_64-unknown-linux-musl.tar.xz \
  --repo bruj0/keyspout
jq -r 'select(.verificationResult) |
       .verificationResult.signature.certificate |
       {issuer, subject: .subjectAlternativeName}' ./*.jsonl
# expect: issuer https://token.actions.githubusercontent.com
#         subject .../bruj0/keyspout/.github/workflows/attest.yml

# --- 6. Verify offline, without GitHub --------------------------------
gh attestation verify ./ksp-x86_64-unknown-linux-musl.tar.xz \
  --bundle ./*.jsonl \
  --repo bruj0/keyspout \
  --signer-workflow bruj0/keyspout/.github/workflows/attest.yml

# --- 7. Read what is inside the binary --------------------------------
# Empty for a release published before SBOMs existed; see 1.2.
gh release download "$TAG" --repo bruj0/keyspout --pattern '*sbom.cdx.json'
jq '.components[] | {name, version}' ksp-*-sbom.cdx.json | head

# --- 8. Check the transparency log yourself ---------------------------
# Open https://search.sigstore.dev and search for the artifact's sha256.
# A signature that is not in Rekor is not a signature this project produced.
```

**What this proves:** the binary was built by that workflow, in that repository,
from a specific commit, and the bytes you hold are the bytes that build produced.

**What it does not prove:** that the commit is safe. A backdoor merged to `main`
produces a valid attestation. §3 is the section to read.

Steps 1–3 are explained in §1, step 4–6 in §1.1, step 7 in §1.2, and step 8 in
§1.1. The rest of this document is the reasoning behind them.

---

## 1. Verify a download

Every file whose name carries a target triple carries a GitHub
build-provenance attestation: the tarball, its `.sha256`, and from the release
after v1.0.2 its SBOM. It records which repository, which workflow and which
commit produced the bytes.

`sha256.sum`, `source.tar.gz`, `source.tar.gz.sha256`, `ksp-installer.sh`,
`ksp.rb` and `dist-manifest.json` are not attested. That is the shape of the
pipeline rather than an oversight: the attestation globs
`target/distrib/*<target>*`, and none of those names contains a target.

```bash
# 1. Download the artifact. The tag is resolved, never pinned: a pinned tag
#    keeps verifying an old release while reading as the current recipe.
TAG=$(gh release view --repo bruj0/keyspout --json tagName -q .tagName)
gh release download "$TAG" --repo bruj0/keyspout \
  --pattern 'ksp-x86_64-unknown-linux-musl.tar.xz'

# 2. Prove it was built by this repository's release workflow.
gh attestation verify ksp-x86_64-unknown-linux-musl.tar.xz \
  --repo bruj0/keyspout \
  --signer-workflow bruj0/keyspout/.github/workflows/attest.yml

# 3. Check the checksum against the published list.
gh release download "$TAG" --repo bruj0/keyspout --pattern 'sha256.sum'
sha256sum --check sha256.sum --ignore-missing

# 4. Read what is inside it. See 1.2.
gh release download "$TAG" --repo bruj0/keyspout --pattern '*sbom.cdx.json'
jq '.components[] | {name, version}' ksp-*-sbom.cdx.json | head
```

Step 2 is the one that answers the question. `gh attestation verify` exits 0 only
if the artifact's digest is named in an attestation signed by that workflow, in
that repository, through GitHub's OIDC identity. A binary built anywhere else
fails it.

Step 3 prints `sha256sum: WARNING: 1 line is improperly formatted` on a good
release: `sha256.sum` ends with a blank line. The verdict is the
`<file>: OK` line at the end, and the command exits 0.

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
  --signer-workflow bruj0/keyspout/.github/workflows/attest.yml
```

**Check the transparency log.** Rekor is append-only and public, so the entry can
be found without trusting this repository at all. Search
`https://search.sigstore.dev` for the artifact's digest. A signature that is not
in the log is not a signature this project produced.

### 1.2 What is inside the binary

Each platform tarball ships with a CycloneDX SBOM, `ksp-<target>-sbom.cdx.json`,
generated from the same `Cargo.lock` the binary was built against. It lists the
crates and versions that were actually linked, not the ranges in `Cargo.toml`.

```bash
TAG=$(gh release view --repo bruj0/keyspout --json tagName -q .tagName)
gh release download "$TAG" --repo bruj0/keyspout --pattern '*sbom.cdx.json'
jq '.components[] | {name, version}' ksp-*-sbom.cdx.json | head
```

There is one SBOM per target rather than one for the workspace, because a musl
build and a gnu build link different crates and one file claiming otherwise would
misdescribe every binary beside it.

**SBOMs ship with every release after v1.0.2.** That release predates them, so
the download above matches nothing there and `gh` exits non-zero. On any later
release it matches one file per target, and each one is attested by the same
command as the tarball — the glob covers both files.

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

- the artifact was built by this repository's release pipeline, and signed by
  `.github/workflows/attest.yml` — a reusable workflow that does nothing but
  sign, so the build job never holds the signing identity. The claim is about
  that signer, not about a fork, a laptop, or a different workflow;
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

## 4. The vulnerability scanners, and the current state

Three checks run on every release, and the state they report today is **zero
vulnerabilities**.

| Check | What it reads | Current result |
|---|---|---|
| `cargo audit` | `Cargo.lock` against RustSec | **0 vulnerabilities**, 1 advisory-class warning |
| OSV-Scanner | the same lockfile against OSV.dev (RustSec + GitHub Advisory + NVD) | **0 vulnerabilities**, 1 advisory-class note |
| `cargo vet` | the review ledger | 3 audited, 311 exempted |

### 4.1 The one remaining finding, and why it is not a vulnerability

```
Crate:     proc-macro-error2
Version:   2.0.1
Warning:   unmaintained
ID:        RUSTSEC-2026-0173
Title:     proc-macro-error2 is unmaintained
```

`unmaintained` is an advisory **class**, not a severity. It says nobody is
patching the crate; it does not say the crate has a flaw. RustSec records it as a
warning and `cargo audit` exits 0 on it.

It also cannot be removed. It is a transitive dependency of the HPKE
implementation the record format depends on:

```
proc-macro-error2 v2.0.1
└── hax-lib-macros v0.3.7 (proc-macro)
    └── hax-lib v0.3.7 → core-models → libcrux-intrinsics
        → libcrux-sha3 → hpke-rs 0.8.0 → ksp-record
```

**And it does not reach you.** It is a proc-macro: it runs at compile time and
produces no code in the output. Measured against the release binary:

```bash
$ strings target/release/ksp | grep -c 'proc-macro-error'
0
$ strings target/release/ksp | grep -c 'hax'
0
```

So the honest statement is: **no vulnerability reaches a user**, and one
compile-time-only dependency is unmaintained. The gate reports it and does not
fail, which is the correct treatment — failing on it would make an unmaintained
build tool as urgent as a remote code execution, and the first person to hit that
adds an ignore rather than a fix.

### 4.2 Two findings this pipeline already fixed

The scanners are not decoration. Both of these were found and closed here:

| Advisory | What it was | Fix |
|---|---|---|
| `RUSTSEC-2026-0486` (`rustix` 1.1.5) | xattr functions marked unwritten bytes as initialised when given a zero-length buffer. `cargo audit` called it an *unsound* **warning** and exited 0; OSV-Scanner called it a vulnerability. | upgraded to `rustix` 1.1.6, the version the advisory names |
| `crypto-bigint` 0.7.6 **yanked** | the version was withdrawn upstream | upgraded to `crypto-bigint` 0.7.11 |

The first is the argument for running two scanners: the tool that was already in
the gate classified a real defect as a warning and passed it.

### 4.3 The blind spot, stated plainly

OSV-Scanner has an experimental Rust call-graph analysis meant to answer "does
this vulnerable function actually reach our code?". **On this repository it does
not work**: it cannot build the workspace, so every finding arrives with no
analysis conclusion.

The gate therefore treats **a finding with no analysis conclusion as reachable**.
That is the conservative direction, and it means:

- what the gate buys today is a **severity-filtered presence check** over a wider
  advisory set than `cargo audit`;
- it does **not** buy reachability analysis. A green gate does not mean the
  vulnerable functions are unreachable — it means no advisory at or above `high`
  names a crate in the lockfile;
- `unsound` **does** fail the gate, because it is a real code weakness.
  `unmaintained` and `yanked` are reported and do not.

If you are relying on the scanner to tell you a vulnerable dependency is
unreachable: it cannot, yet.

### 4.4 Checking this yourself

Every claim above is reproducible from a clone:

```bash
cargo audit                       # RustSec
cargo vet --locked                # the review ledger
osv-scanner scan source --call-analysis=rust --no-call-analysis=go \
  --all-vulns --format=json --output-file=/tmp/osv.json .
python3 scripts/osv-gate.py /tmp/osv.json --fail-on high
```

---

## 5. The attack surface, and what covers it

| # | Attack | Control | Residual risk |
|---|---|---|---|
| **T1** | A maintainer commits a backdoor | Code review | **Not covered by any tool.** The attestation proves the binary matches the commit; it cannot prove the commit is honest. |
| **T2** | A dependency is compromised | `Cargo.lock` pinning, `cargo audit`, OSV-Scanner, and `cargo-vet` (§6) | A compromised crate that no advisory names yet ships until someone reviews it. `cargo-vet` is the control for that: 3 crates are audited, 311 are exempted — see §6. |
| **T3** | The build workflow is modified | Every action pinned to a commit SHA; Dependabot bumps them as reviewable commits; the gate runs before any build | Someone with write access to `.github/` can still change it. The change is visible in the repository history. |
| **T4** | A published binary is replaced | Attestation makes it detectable | Release immutability is unavailable on this repository. Detection, not prevention. |
| **T5** | A binary is built elsewhere and published as if from CI | Provenance attestation names the workflow and commit; the `release` environment requires human approval before publish | A leaked token cannot publish without the approval, but an approved publish of a bad build is still a publish. |

Two things follow from the table, and they are the honest summary:

1. **T1 is a review problem.** No build system can solve it. What this pipeline
   does is make a backdoor require an **observable commit** rather than a quiet
   binary swap.
2. **T4 is detected, not prevented.** Verify your download. That is the control.

---

## 6. Dependency review: 3 audited, 311 exempted

`cargo-vet` is the control that catches a compromised dependency before an
advisory names it — it is your own review of what the code does, rather than a
database lookup.

It is **configured and enforced in CI**. `cargo vet --locked` runs on every gate
and fails when a dependency has neither an audit nor an exemption.

The state, measured:

```
$ cargo vet --locked
Vetting Succeeded (3 fully audited, 311 exempted)
```

Read those two numbers together. **3 audited** comes from Google's Chromium audit
set, which is trusted via `supply-chain/imports.lock` and covers `core-foundation-sys`,
`nom` and `num-traits`. **311 exempted** is the backlog: an exemption records that
nobody has reviewed the crate yet.

An exemption is not a pass. It is a recorded decision to defer, and the gate still
does something useful with it:

- **A new dependency fails the gate.** Adding a crate requires someone to write an
  exemption or an audit, which is a decision made in a commit rather than a silent
  pull.
- **A version bump of an exempted crate also fails**, because the exemption is
  pinned to a version. This happened twice during this hardening work — `rustix`
  1.1.5 → 1.1.6 and `crypto-bigint` 0.7.6 → 0.7.11 — and both times the gate
  refused the upgrade until the exemption was moved.

What it does **not** do is review 311 crates. That count is the size of the
backlog, not a measure of coverage.

To reduce it, `cargo vet suggest` lists the cheapest reviews first — usually the
crates with the most dependents. Each review replaces an exemption with an audit
entry that says what was checked. `docs/supply-chain-vetting.md` records the
mechanics.

---

## 7. Reproducing the build

The release is built with path remapping and a pinned timestamp, so two builds of
the same commit in the same container image produce the same bytes.

```bash
git clone https://github.com/bruj0/keyspout && cd keyspout
git checkout "$(gh release view --repo bruj0/keyspout --json tagName -q .tagName)"
# or, without gh:
#   git checkout "$(git describe --tags "$(git rev-list --tags --max-count=1)")"

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
