#!/bin/bash
# Run WP01's root-gated two-account suite and record the result.
#
# Why this script exists: the suite must run as root (it chowns files to another
# UNIX account), and no privilege path on this host lets an agent obtain root
# without a password. So the operator runs this; it writes a transcript an agent
# can read, which keeps the password in the operator's own terminal and out of
# every log the agent owns.
#
# Usage:  bash scripts/run-wp01-rooted.sh
#
# Exit code is the suite's, so `echo $?` answers the question on its own.

set -uo pipefail

WORKTREE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="/tmp/ksp-wp01-root"
LOG="/tmp/ksp-wp01-rooted.log"

# The binary is pre-built at a separate CARGO_TARGET_DIR: a root-owned
# `target/` in the worktree would break every later non-root build.
#
# Resolved rather than hardcoded: the deps filename carries a cargo hash that
# changes with the build, so a literal path is correct for one build and wrong
# for the next. Newest wins, because a stale binary from an earlier build is the
# failure this avoids — it would run the old tests and report success.
BIN=$(ls -t "$TARGET_DIR"/debug/deps/principals-* 2>/dev/null |
      grep -v '\.' | head -1)

if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "no pre-built test binary under $TARGET_DIR/debug/deps" >&2
  echo "build it first:  cd $WORKTREE && CARGO_TARGET_DIR=$TARGET_DIR cargo test -p ksp --test principals --no-run" >&2
  exit 2
fi

echo "binary: $BIN"

echo "Running the two-account boundary suite as root."
echo "This asks for your password once; it is typed here, never passed to an agent."
echo

# `--test-threads=1`: `useradd`/`userdel` take a global /etc/passwd lock, and the
# suite's own mutex only serialises within one process.
sudo "$BIN" --test-threads=1 2>&1 | tee "$LOG"
status=${PIPESTATUS[0]}

echo
echo "transcript written to $LOG"
echo "exit code: $status"
exit "$status"
