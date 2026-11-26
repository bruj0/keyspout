#!/bin/bash
# Provision the two accounts the two-account boundary suite consumes, then run it.
#
# Why this script exists: `sysadminctl -addUser` prompts for a password, and no
# privilege path on this host lets an agent obtain root without one. So the
# operator runs this; it writes a transcript an agent can read, which keeps the
# password in the operator's own terminal and out of every log the agent owns.
#
# The accounts are created once and reused. Re-running is safe: each add is
# skipped when the account already exists.
#
# Usage:  bash scripts/provision-test-accounts.sh [--remove]
#
#   --remove   delete both accounts again (they are throwaway)

set -uo pipefail

WORKTREE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="/tmp/ksp-wp05-accounts.log"
ADMIN="${KSP_TEST_ADMIN_USER:-ksp-admin}"
USER="${KSP_TEST_USER:-ksp-user}"
# Consumed by the account-removal assertion, which deletes it. Recreated below on
# every run: it is what lets that test verify a binding whose account is gone
# without touching either of the accounts the rest of the suite depends on.
DISPOSABLE="${KSP_TEST_DISPOSABLE_USER:-ksp-disposable}"

exec > >(tee "$LOG") 2>&1

if [ "${1:-}" = "--remove" ]; then
  echo "Removing $ADMIN and $USER."
  for account in "$ADMIN" "$USER"; do
    sudo dscl . -delete "/Users/$account" 2>/dev/null && echo "  removed $account" \
      || echo "  $account was already absent"
  done
  echo
  echo "transcript: $LOG"
  exit 0
fi

echo "This creates two throwaway accounts for the boundary suite."
echo "It asks for your password; it is typed here, never passed to an agent."
echo

# A random password each: the accounts are for file ownership, not for logging in,
# and a password nobody records cannot be used to log in later.
for account in "$ADMIN" "$USER" "$DISPOSABLE"; do
  if [ "$account" = "$DISPOSABLE" ]; then
    # Always recreated: the assertion below deletes it, so a leftover from an
    # earlier run is not the account this run needs.
    sudo dscl . -delete "/Users/$account" 2>/dev/null || true
  elif id -un "$account" >/dev/null 2>&1; then
    echo "$account already exists, leaving it alone"
    continue
  fi
  password="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
  # No -admin: the suite measures ONE ACCOUNT'S AUTHORITY, and an admin account
  # silently turns the grant it exercises into a root grant.
  if sudo sysadminctl -addUser "$account" -password "$password" -shell /bin/sh; then
    echo "created $account"
  else
    echo "FAILED to create $account" >&2
    exit 1
  fi
done

# A run before this guard existed added an account to `wheel`, because the store
# root it resolved had gid 0 and `join_store_group` maps gid 0 to `wheel` on macOS.
# That is D6 in docs/known-defects.md; the product still does it. Removing the
# membership here means a re-run leaves the host clean rather than refusing
# forever.
for account in "$ADMIN" "$USER" "$DISPOSABLE"; do
  if id -Gn "$account" 2>/dev/null | tr ' ' '\n' | grep -qx wheel; then
    echo "removing $account from wheel (gid 0): a previous run's store root had a"
    echo "  gid-0 group, which is D6 — the defect is recorded, not yet fixed."
    sudo dseditgroup -o edit -d "$account" -t user wheel >/dev/null 2>&1 \
      && echo "  removed $account from wheel" \
      || echo "  FAILED to remove $account from wheel" >&2
  fi
done

echo
echo "Verifying they are not in admin, sudo or wheel:"
for account in "$ADMIN" "$USER" "$DISPOSABLE"; do
  groups="$(id -Gn "$account" 2>/dev/null | tr ' ' '\n' | grep -E '^(admin|sudo|wheel)$' || true)"
  if [ -n "$groups" ]; then
    echo "  REFUSING: $account is in $groups. The suite would measure a root grant." >&2
    exit 1
  fi
  echo "  $account: no admin group, good"
done

echo
echo "Running the suite as root. This is the second password prompt."
echo

# Not `sudo -E`. The suite builds its own homes under a temporary directory, and
# `layout::table()` resolves the store through `configured_store()`, which reads
# `KSP_STORE`. Carrying this shell's value in made every `admin init` write its
# layout row into a directory owned by another account, and the suite failed with
# "a protected file this operation had to write could not be written" — an
# environment leak that reads exactly like a product defect.
#
# The accounts are passed explicitly instead, and `KSP_STORE` is removed.
sudo env -u KSP_STORE \
  KSP_TEST_ADMIN_USER="$ADMIN" \
  KSP_TEST_USER="$USER" \
  KSP_TEST_DISPOSABLE_USER="$DISPOSABLE" \
  bash -c "cd '$WORKTREE' && CARGO_TARGET_DIR=/tmp/ksp-wp05-root cargo test -p ksp --test principals -- --test-threads=1"
status=$?

echo
echo "transcript: $LOG"
echo "suite exit code: $status"
exit "$status"
