#!/bin/bash
# Set up, inspect and tear down a Keyspout deployment — and wrap `ksp` while
# doing it.
#
# The steps are USER_MANUAL.md's, in its order, with the parts a two-account
# deployment always runs. The manual explains *why* each one exists; this script
# runs them and checks the result.
#
# Why a script rather than a fourth copy of the commands: the order is
# load-bearing (the admin's signing key, then the sealed vault, then the
# handover, then the agent), and several steps fail in a way that looks like a
# different problem — a `chmod 0644` missed on `config.toml` reads as
# "Permission denied" from an unrelated command three steps later.
#
# Usage:
#   ksp-op.sh setup [--vault NAME] [--admin-account NAME] [--dry-run]
#   ksp-op.sh status
#   ksp-op.sh reset [--yes] [--purge-account]
#   ksp-op.sh ksp <args…>          # run ksp as you
#   ksp-op.sh asadmin <args…>      # run ksp as the admin account
#   ksp-op.sh home                 # print the two paths a caller needs
#
# Environment:
#   KSP           the binary to use (default: `command -v ksp`)
#   KSP_ADMIN_HOME  the admin account's home (default: /Users/keyspout or /home/keyspout)
#
# Exit codes: 0 ok, 1 refused, 2 usage, 3 missing prerequisite.

set -uo pipefail

# --- platform and paths ------------------------------------------------------

case "$(uname -s)" in
  Darwin) DEFAULT_ADMIN_HOME=/Users/keyspout ;;
  *)      DEFAULT_ADMIN_HOME=/home/keyspout ;;
esac

ADMIN_ACCOUNT="${KSP_ADMIN_ACCOUNT:-keyspout}"
KSP_ADMIN_HOME="${KSP_ADMIN_HOME:-$DEFAULT_ADMIN_HOME}"
KSP_HOME="$KSP_ADMIN_HOME/.ksp"
USER_NAME="$(id -un)"
USER_HOME="$HOME"
VAULT="vault-1"
DRY_RUN=0

# `KSP_STORE` must not leak in from a shell profile. A configured store root is
# *opened, never created*, and it splits a deployment between the home and that
# path — the failure names the registry, which reads like a permissions bug.
if [ -n "${KSP_STORE:-}" ]; then
  echo "refusing: KSP_STORE is set to $KSP_STORE" >&2
  echo "  this deployment keeps its store at \$KSP_HOME/store." >&2
  echo "  unset it in this shell (and remove the export from your profile):" >&2
  echo "    unset KSP_STORE" >&2
  exit 1
fi

KSP="${KSP:-$(command -v ksp || true)}"

# --- helpers -----------------------------------------------------------------

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
# Print a message on stderr and exit. `$2` is the status, so `"$*"` must not be
# used for the text — it would join the status onto the sentence.
die() {
  local msg="$1" code="${2:-1}"
  printf 'error: %s\n' "$msg" >&2
  exit "$code"
}

# Run a command, or print it when --dry-run is in force. Every mutation goes
# through here so the dry run is honest rather than approximate.
run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf '  would run: %s\n' "$*"
    return 0
  fi
  "$@"
}

# sudo that never prompts. A missing credential becomes a readable refusal
# rather than a prompt in the middle of an unattended run.
need_root() {
  if ! sudo -n true 2>/dev/null; then
    die "this step needs root and sudo would prompt.
  Run it by hand:  sudo $0 $*
  Or pre-authorise: sudo -v   # then re-run within the timeout" 3
  fi
}

# The group the store and the home use. On macOS every ordinary account is in
# `staff`; on Linux the admin is put in the *user's* group so the two share one.
store_group() {
  case "$(uname -s)" in
    Darwin) echo staff ;;
    *)      id -gn ;;
  esac
}

asadmin() {
  sudo -n -u "$ADMIN_ACCOUNT" -H env KSP_HOME="$KSP_HOME" LC_ALL=C "$KSP" "$@"
}

# Read the passphrase once and keep it in a variable. Nothing is written to
# disk. `-s` so it does not echo.
#
# `-p` is bash's prompt flag. `?prompt` is a *zsh* idiom and bash reads it as an
# invalid variable name, which is how this line shipped broken: it was written
# in zsh, and the script runs under `#!/bin/bash`.
#
# A dry run never reads a password: it runs no command that could need one.
read_passphrase() {
  if [ -n "${KSP_PASSPHRASE:-}" ]; then
    return 0
  fi
  if [ "$DRY_RUN" = 1 ]; then
    KSP_PASSPHRASE="dry-run-placeholder"
    return 0
  fi
  if [ -t 0 ]; then
    read -rs -p "Vault password: " KSP_PASSPHRASE || die "no password read"
    echo
  else
    IFS= read -r KSP_PASSPHRASE || die "no password on stdin"
  fi
  [ ${#KSP_PASSPHRASE} -ge 8 ] || die "the vault password must be at least 8 bytes"
}

# Feed the passphrase to a command on stdin, which is how every command that
# unseals the vault accepts it.
with_password() { printf '%s' "$KSP_PASSPHRASE" | "$@"; }

# --- setup -------------------------------------------------------------------

cmd_setup() {
  [ -n "$KSP" ] && [ -x "$KSP" ] || die "no ksp binary found; set KSP=/path/to/ksp" 3

  step "0. preflight"
  say "  binary:  $KSP ($("$KSP" version 2>/dev/null || echo unknown))"
  say "  user:    $USER_NAME"
  say "  admin:   $ADMIN_ACCOUNT"
  say "  home:    $KSP_HOME"

  if ! id "$ADMIN_ACCOUNT" >/dev/null 2>&1; then
    step "1. create the admin account"
    need_root setup
    case "$(uname -s)" in
      Darwin)
        run sudo sysadminctl -addUser "$ADMIN_ACCOUNT" \
          -UID 502 -GID 20 -shell /bin/zsh -home "$KSP_ADMIN_HOME"
        ;;
      *)
        # -g "$(id -gn)" puts the admin in the user's group, which is the group
        # the store is created in. Without it the two accounts share nothing.
        run sudo useradd -M -N -s /bin/sh -g "$(id -gn)" \
          -K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0 "$ADMIN_ACCOUNT"
        ;;
    esac
    if [ "$DRY_RUN" = 0 ] && ! id "$ADMIN_ACCOUNT" >/dev/null 2>&1; then
      die "the account did not resolve by name; a record with no UniqueID is
  the failure chown reports as 'illegal user name'"
    fi
  else
    step "1. the admin account exists"
    say "  $(id "$ADMIN_ACCOUNT")"
  fi

  step "2. the deployment home"
  local group; group="$(store_group)"
  if [ -d "$KSP_HOME" ]; then
    say "  exists: $(stat -f '%Sp %Su:%Sg' "$KSP_HOME" 2>/dev/null || stat -c '%A %U:%G' "$KSP_HOME")"
  else
    need_root setup
    run sudo mkdir -p "$KSP_HOME"
    run sudo chown -R "$ADMIN_ACCOUNT:$group" "$KSP_HOME"
  fi
  # 0711 lets another principal traverse a known path without enumerating it.
  # `mkdir` gives 0755, which `ksp status` reports as drift. A chmod on a
  # directory the admin already owns needs no root when run *as* the admin, so
  # only create-and-chown demands it.
  run sudo -n -u "$ADMIN_ACCOUNT" chmod 0711 "$KSP_HOME" 2>/dev/null ||
    run sudo chmod 0711 "$KSP_HOME"

  step "3. capability configuration"
  if [ -f "$KSP_HOME/config.toml" ]; then
    say "  exists (a second init changes nothing)"
  fi
  run asadmin init
  # The user's commands read this file, and a 0600 file the admin owns is
  # unopenable to her. The guard refuses a file another principal can *write*,
  # not one she can read, so 0644 is the shape the two-account session needs.
  run sudo -n -u "$ADMIN_ACCOUNT" chmod 0644 "$KSP_HOME/config.toml"

  step "4. the admin signing key"
  if [ -f "$KSP_HOME/deployment.cbor" ]; then
    say "  exists (already initialised)"
  else
    run asadmin admin init --vault "$VAULT" --user "$USER_NAME" --key-id keyspout
  fi

  step "5. seal the admin vault"
  if [ -f "$KSP_HOME/admin-vault.cbor" ]; then
    say "  exists (one per deployment; it cannot be replaced)"
  else
    read_passphrase
    run_with_stdin "$KSP_PASSPHRASE" sudo -n -u "$ADMIN_ACCOUNT" -H env \
      KSP_HOME="$KSP_HOME" LC_ALL=C "$KSP" admin seal-vault
  fi

  step "6. enrol $USER_NAME"
  if [ -f "$KSP_HOME/vault.cbor" ]; then
    say "  vault.cbor exists (already enrolled)"
  else
    need_root setup
    read_passphrase
    # `--unix-user` is what hands the vault to the user, and that chown needs
    # root. Omitting it would succeed and build a *single-account* deployment.
    run_with_stdin "$KSP_PASSPHRASE" sudo -n env KSP_HOME="$KSP_HOME" "$KSP" \
      admin user add \
        --unix-user "$USER_NAME" \
        --signing-key-id "$USER_NAME-ed25519-1" \
        --recipient-key-id "$USER_NAME-x25519-1"
  fi

  step "7. enrol the agent"
  if asadmin agent list --json 2>/dev/null | grep -q '"identity"'; then
    say "  an agent is already enrolled"
  else
    run "$KSP" agent enroll --agent "$USER_NAME-laptop"
  fi

  step "done"
  cmd_status
  say ""
  say "Next: store a value and grant it."
  say "  $0 asadmin admin put my_secret --name my_secret --own   # value on stdin"
  say "  $0 asadmin admin policy create --user \"\$USER_ID\" --secret my_secret \\"
  say "      --version 1 --agent \"\$AGENT\""
}

# Feed a string to a command's stdin, or print it in a dry run.
run_with_stdin() {
  local input="$1"; shift
  if [ "$DRY_RUN" = 1 ]; then
    printf '  would run (password on stdin): %s\n' "$*"
    return 0
  fi
  printf '%s' "$input" | "$@"
}

# --- status ------------------------------------------------------------------

cmd_status() {
  step "status"
  if [ ! -f "$KSP_HOME/deployment.cbor" ]; then
    say "  no deployment at $KSP_HOME"
    return 0
  fi
  asadmin status 2>/dev/null |
    grep -E '^(binding|permissions|confinement|barrier|cadence|proven|minimum|platform):' |
    sed 's/^/  /'
  say ""
  say "  grants:"
  asadmin admin policy list 2>/dev/null | sed 's/^/    /' | tail -5
  say ""
  say "  records:"
  asadmin admin list 2>/dev/null | grep 'level=admin' | sed 's/^/    /' | head -5
}

# --- reset -------------------------------------------------------------------

cmd_reset() {
  local purge_account=0 confirm=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --purge-account) purge_account=1; shift ;;
      --yes) confirm=1; shift ;;
      *) die "unknown option: $1" 2 ;;
    esac
  done

  step "what will be removed"
  say "  $KSP_HOME  (the deployment: keys, sealed vault, records, store)"
  say "  $USER_HOME/.ksp-tokens  (exported tokens)"
  say "  any loaded keyspout launchd job"
  [ "$purge_account" = 1 ] && say "  the $ADMIN_ACCOUNT account itself"

  if [ "$confirm" = 0 ] && [ "$DRY_RUN" = 0 ]; then
    die "refusing without --yes. This deletes every sealed value in
  $KSP_HOME/admin-vault.cbor, and nothing brings them back: the values exist in
  that file and wherever you copied them, nowhere else.

  Re-run with --yes, or set DRY_RUN with:  $0 reset --dry-run"
  fi

  step "stop any loaded job"
  local uid; uid="$(id -u)"
  for job in com.keyspout.sweep com.keyspout.user-sweep; do
    run launchctl bootout "gui/$uid/$job" 2>/dev/null || true
    run launchctl bootout "gui/$uid" "$USER_HOME/Library/LaunchAgents/$job.plist" 2>/dev/null || true
  done

  step "remove the deployment"
  need_root reset --yes
  run sudo rm -rf "$KSP_HOME"
  run rm -rf "$USER_HOME/.ksp-tokens"

  if [ "$purge_account" = 1 ]; then
    step "remove the account"
    case "$(uname -s)" in
      Darwin) run sudo sysadminctl -deleteUser "$ADMIN_ACCOUNT" ;;
      *)      run sudo userdel -r "$ADMIN_ACCOUNT" 2>/dev/null || run sudo userdel "$ADMIN_ACCOUNT" ;;
    esac
  fi

  step "done"
  say "  The export KSP_STORE is not touched by this script; if a profile sets it,"
  say "  remove that line yourself — see USER_MANUAL.md."
}

# --- dispatch ----------------------------------------------------------------

usage() {
  # The header block only, from `Usage:` to the exit-code line. A fixed line
  # range breaks the moment the header gains a line, so it is matched instead.
  sed -n '/^# Usage:/,/^# Exit codes:/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

[ $# -eq 0 ] && usage
verb="$1"; shift

case "$verb" in
  setup)
    while [ $# -gt 0 ]; do
      case "$1" in
        --vault) VAULT="$2"; shift 2 ;;
        --admin-account) ADMIN_ACCOUNT="$2"; KSP_ADMIN_HOME="/home/$2"; KSP_HOME="$KSP_ADMIN_HOME/.ksp"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) die "unknown option: $1" 2 ;;
      esac
    done
    cmd_setup ;;
  status) cmd_status ;;
  reset)
    for a in "$@"; do [ "$a" = "--dry-run" ] && DRY_RUN=1; done
    # keep --dry-run out of the reset parser's way
    args=(); for a in "$@"; do [ "$a" = "--dry-run" ] || args+=("$a"); done
    cmd_reset "${args[@]+"${args[@]}"}" ;;
  ksp)      exec "$KSP" "$@" ;;
  asadmin)  exec sudo -n -u "$ADMIN_ACCOUNT" -H env KSP_HOME="$KSP_HOME" LC_ALL=C "$KSP" "$@" ;;
  home)     printf 'KSP_HOME=%s\nKSP=%s\nKSP_ADMIN_HOME=%s\n' "$KSP_HOME" "$KSP" "$KSP_ADMIN_HOME" ;;
  help|-h|--help) usage ;;
  *) die "unknown verb: $verb (try: help)" 2 ;;
esac
