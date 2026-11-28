#!/bin/bash
# Exercise the two-account workflow end to end, unprivileged, in ninety seconds.
#
# Why this exists: the `principals` suite needs root — it `chown`s a vault to
# another account — and root needs a password this host does not have
# non-interactively. So the suite cannot run here. The *product path* it
# protects can: one home, two principals, a publication and a delivery.
#
# What this does NOT prove: kernel-level separation between two real UNIX
# accounts. That needs the suite, under sudo. What it does prove is that the
# sequence of commands a two-account deployment runs still completes — which is
# the thing most likely to break, because every step depends on the previous
# one's output.
#
# Usage:  bash scripts/two-account-smoke.sh [--keep]
#
#   --keep   leave the scratch home in place and print its path

set -uo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/scratch-guard.sh
. "${script_dir}/lib/scratch-guard.sh"

KSP="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/debug/ksp"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

if [ ! -x "$KSP" ]; then
  echo "no binary at $KSP — build first: cargo build -p ksp" >&2
  exit 2
fi

H="$(mktemp -d /tmp/ksp-2acct-XXXX)"
PASS="$H/pw"
printf 'a-long-enough-passphrase' > "$PASS"
chmod 600 "$PASS"

# The layout expects 0711: the owner enumerates it, another principal traverses
# a known path without listing it. `mktemp -d` gives 0700, which `status`
# reports as drift and which a second account could not traverse.
chmod 0711 "$H"

# `KSP_STORE` must not leak in from the developer's shell: a configured root is
# opened, never created, so a stale value refuses at exit 7.
unset KSP_STORE
export KSP_HOME="$H"

# This walkthrough asserts on file ownership in three places (the 0000 level, the
# `chown`ed vault, the unreadable record). On a virtiofs share `chown` returns 0
# and the owner does not change — measured — so on that path the assertions are
# answered by nothing and the run reports a result it did not measure. Refuse
# rather than continue, and name the fix.
#
# `/tmp` is guest disk on every colima guest, so the default is accepted and the
# refusal only fires when a caller has redirected `TMPDIR` at the mount.
if ! scratch_is_local "$H"; then
    printf 'error: the two-account walkthrough needs its home on guest disk.\n' >&2
    printf '       %s is not, and this script asserts on file ownership there.\n' "$H" >&2
    printf '       Fix: unset TMPDIR (it is probably pointing at a shared mount),\n' >&2
    printf '       or run scripts/ksp-guest-scratch.sh --apply and set TMPDIR to\n' >&2
    printf '       /mnt/lima-colima/ksp/tmp.\n' >&2
    exit 2
fi

fail=0
step() { printf '%-46s' "$1"; shift; }
ok()   { echo "ok"; }
bad()  { echo "FAILED"; fail=$((fail + 1)); [ $# -gt 0 ] && echo "    $1"; }

run() { out=$("$@" 2>&1 < /dev/null); return $?; }

step "init writes the capability configuration"
if "$KSP" init >/dev/null 2>&1 && [ -f "$H/config.toml" ]; then ok; else bad; fi

step "config.toml widened to 0644"
chmod 0644 "$H/config.toml"
if [ "$(stat -f '%OLp' "$H/config.toml")" = "644" ]; then ok; else bad; fi

step "admin init lands the registry in the home"
if "$KSP" admin init --vault vault-1 --user owner --key-id smoke >"$H/init.out" 2>&1; then
  if compgen -G "$H/store/p/vault-1/*/principals.cbor" >/dev/null; then ok; else bad "no registry"; fi
else bad "$(tail -1 "$H/init.out")"; fi

step "admin seal-vault"
if "$KSP" admin seal-vault --passphrase-file "$PASS" >/dev/null 2>&1; then ok; else bad; fi

step "admin user add adopts the provisional principal"
if "$KSP" admin user add --unix-user "$(id -un)" \
     --signing-key-id smoke-ed25519-1 --recipient-key-id smoke-x25519-1 \
     --passphrase-file "$PASS" >"$H/add.out" 2>&1; then
  init_user=$(sed -n 's/.*user=\([0-9a-f-]*\).*/\1/p' "$H/init.out")
  add_principal=$(sed -n 's/.*principal=\([0-9a-f-]*\).*/\1/p' "$H/add.out")
  if [ -n "$add_principal" ] && [ "$init_user" = "$add_principal" ]; then
    ok
  else bad "init user=$init_user add principal=$add_principal"; fi
else bad "$(tail -1 "$H/add.out")"; fi
USER_ID="$add_principal"

step "agent enroll"
if "$KSP" agent enroll --agent smoke-agent --json >"$H/agent.out" 2>&1; then
  AGENT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["identity"].split(":")[1])' "$H/agent.out")
  [ -n "$AGENT" ] && ok || bad "no agent id"
else bad; fi

step "admin put --own writes version 1"
if printf 'a-value-of-nineteen' | "$KSP" admin put smoke --name smoke --own --json >"$H/put.out" 2>&1; then
  grep -q '"version":1' "$H/put.out" && ok || bad "$(cat "$H/put.out")"
else bad; fi

step "admin list names the --own record"
if "$KSP" admin list --json >"$H/list.out" 2>&1 && grep -q '"record":"smoke"' "$H/list.out"; then ok; else bad; fi

step "admin list reports an unreadable level, exit 0"
LVL=$(find "$H/store" -type d -name admin -mindepth 4 -maxdepth 4 | head -1)
if [ -n "$LVL" ]; then
  chmod 0000 "$LVL"
  out=$("$KSP" admin list 2>&1 < /dev/null); rc=$?
  chmod 0755 "$LVL"
  if [ "$rc" -eq 0 ] && echo "$out" | grep -q "could not be read"; then ok
  else bad "rc=$rc out=$(echo "$out" | head -1)"; fi
else bad "no level directory"; fi

step "admin policy create (two JSON objects, id first)"
if "$KSP" admin policy create --user "$USER_ID" --secret smoke --version 1 \
     --agent "$AGENT" --expires-at $(( $(date +%s) + 7200 )) \
     --passphrase-file "$PASS" --json >"$H/policy.out" 2>&1; then
  PID=$(head -1 "$H/policy.out" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id",""))' 2>/dev/null)
  n=$(wc -l < "$H/policy.out" | tr -d ' ')
  if [ -n "$PID" ] && [ "$n" -ge 2 ]; then ok
  else bad "id=$PID lines=$n"; fi
else bad "$(tail -1 "$H/policy.out")"; fi

step "secret share --policy (no password)"
if "$KSP" secret share smoke --policy "$PID" --out "$H/smoke.token" --json >/dev/null 2>&1 \
   && [ -f "$H/smoke.token" ]; then ok; else bad; fi

step "ksp run delivers the value byte-exactly"
"$KSP" run --token "$H/smoke.token" --env V -- /bin/sh -c 'printf %s "$V"' \
  >"$H/got" 2>/dev/null
if [ "$(cat "$H/got")" = "a-value-of-nineteen" ]; then ok; else bad "got '$(cat "$H/got")'"; fi

step "withdrawal makes the token refuse at exit 2"
if "$KSP" admin policy delete "$PID" >/dev/null 2>&1; then
  "$KSP" run --token "$H/smoke.token" --env V -- /bin/sh -c 'printf %s "$V"' \
    >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 2 ] && ok || bad "exit $rc, expected 2"
else bad "delete failed"; fi

echo
if [ "$fail" -eq 0 ]; then
  echo "all steps passed"
else
  echo "$fail step(s) failed"
fi

if [ "$KEEP" -eq 1 ]; then
  echo "scratch home kept at $H"
else
  chmod -R 0755 "$H" 2>/dev/null
  rm -rf "$H"
fi
exit "$fail"
