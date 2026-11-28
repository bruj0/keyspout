#!/usr/bin/env bash
#
# ksp-macos-vm.sh — one disposable macOS guest, for the parts of `ksp-op` that
# only a macOS kernel can run.
#
# # Why a macOS guest and not the Linux one
#
# `crates/ksp/src/bin/ksp-op/orchestrator.rs` decides at runtime between
# `sysadminctl -addUser` and `useradd`, `launchctl bootout` and `systemctl --user
# stop`, `dscl` and `getent`. A Linux guest proves the Linux half only. The macOS
# half has no Linux equivalent, so proving it needs a macOS guest — a second VM,
# not a replacement for the one the gate uses.
#
# # The engine
#
# Two are supported and both are a flag rather than a hidden decision:
#
#   tart   `--provisioning-opts` on macOS 27 hosts provisions the account and
#          enables Remote Login on first boot. Images come from an OCI registry
#          and clones are APFS copy-on-write.
#   lume   `--unattended` prepares the disk offline and `lume ssh --password` is
#          documented as the SSH *and sudo* password.
#
# Neither grants `NOPASSWD`; both leave one `visudo` line, which this script
# writes after the guest answers SSH. That is the documented way for both tools
# (tart.run/quick-start, step 5).
#
# # Why no directory share
#
# Measured 2026-11-27 in the colima guest: `chown` on a virtiofs share returns 0
# and the reported owner does not change. `ksp-op` verifies ownership after
# `chown -R`, so a run against a share fails a check that is correct and reads
# like a product defect. The tree is copied in from `git archive` instead, which
# also makes a run reproducible from a commit.
#
# # Usage
#
#   scripts/ksp-macos-vm.sh status
#   scripts/ksp-macos-vm.sh provision [--engine tart|lume] [--name NAME]
#   scripts/ksp-macos-vm.sh exec [--name NAME] -- <command...>
#   scripts/ksp-macos-vm.sh copy-in [--name NAME]     # git archive HEAD -> guest
#   scripts/ksp-macos-vm.sh destroy [--name NAME]
#   scripts/ksp-macos-vm.sh --selftest
#
# # Exit codes
#
#   0   the subcommand ran
#   1   a step was refused; the reason names the fix
#   64  usage
#   69  the engine is not installed, or the guest is not running

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

NAME=${KSP_MACOS_VM_NAME:-ksp-macos}
ENGINE=${KSP_MACOS_VM_ENGINE:-tart}

# The guest account the deployment is built for.
#
# **`admin`, because that is the account a Cirrus Labs image already has**, and
# the guest provisioning API does not replace it. Measured 2026-11-27:
# `--provisioning-opts username=ci,...` is accepted, the guest boots, and
# `dscl . -list /Users` still shows only `admin`. The API configures *a guest
# being set up for the first time*; a cloned image has already been through Setup
# Assistant, so there is nothing left for it to configure. Asking for a different
# user is therefore a no-op, not a requirement, and a script that assumed `ci`
# would look for an account that was never created.
#
# `admin` already has passwordless sudo in these images — measured, `sudo -n id
# -un` answers `root` — so no sudoers rule is needed either. `install_sudoers`
# stays for the engines and images where it is.
GUEST_USER=${KSP_MACOS_VM_USER:-admin}

# The stock image password. Used only by `install_sudoers` when the account turns
# out not to have `NOPASSWD`, and by nothing else.
#
# Four characters minimum, enforced by the framework: measured, `password=ci`
# fails the boot with `VZErrorDomain Code=40003 "Enter a password that is four
# characters or more."`
GUEST_PASSWORD=${KSP_MACOS_VM_PASSWORD:-admin}

# Where the tree lands inside the guest. Home of the guest account, so `cargo`
# writes under a directory the account owns — a target directory in `/` is
# root-owned and the first build fails at link.
GUEST_SRC="/Users/${GUEST_USER}/src/keyspout"

# The base image. Both are ~25–60 GB uncompressed and are cached by the engine,
# so `destroy` deliberately leaves them.
#
# # Why golden-gate and not tahoe
#
# `--provisioning-opts` **requires a macOS 27 guest** as well as a macOS 27 host.
# Measured 2026-11-27: `macos-tahoe-base` is macOS 26, accepts the flags without
# complaining, and silently ignores them — the guest then boots into Setup
# Assistant with no account and no Remote Login, so the symptom is "SSH never
# answers" with an empty log. `macos-golden-gate-base` is the macOS 27 image and
# is the one the API applies to.
TART_IMAGE=${KSP_MACOS_VM_IMAGE:-ghcr.io/cirruslabs/macos-golden-gate-base:latest}

# Apple's licence allows two macOS guests per host, enforced by the framework and
# surfaced as `VZError.virtualMachineLimitExceeded`. Checked here because the
# framework's own error arrives from three frames down and reads like a
# configuration mistake.
MAX_MACOS_GUESTS=2

refuse() {
    printf 'error: %s\n' "$*" >&2
    return 1
}

engine_present() {
    command -v "$1" >/dev/null 2>&1
}

# The guest's state: absent, stopped or running.
#
# # Why this probes rather than parsing a table
#
# `tart list` prints a table whose columns are the engine's business, and an
# earlier version of this function read the name from column 2, which is not where
# the name is. That cannot be verified without the engine installed, and a guess
# about a table layout reads as working code while being wrong. `tart get <name>`
# exits non-zero for an absent guest and zero for a present one; `tart exec <name>
# true` answers whether it is booted. Both are documented behaviour rather than a
# column position.
guest_state() {
    if ! engine_present "$ENGINE"; then
        printf 'engine-absent'
        return 0
    fi
    case "$ENGINE" in
    tart)
        if ! tart get "$NAME" >/dev/null 2>&1; then
            printf 'absent'
            return 0
        fi
        ;;
    lume)
        if ! lume ls 2>/dev/null | grep -qw -- "$NAME"; then
            printf 'absent'
            return 0
        fi
        ;;
    *)
        printf 'unknown-engine'
        return 0
        ;;
    esac
    # Present. Booted is a different question, and the only honest way to ask it
    # is to try.
    if guest_exec true >/dev/null 2>&1; then
        printf 'running'
    else
        printf 'stopped'
    fi
}

# Run a command in the guest, preserving its exit status.
#
# `tart exec` and `lume ssh` both return the guest's status directly, so this is
# a thin dispatch. It is still one function: the two tools take their arguments
# in different shapes, and a caller that spelled one of them would be a caller
# that only works with one engine.
guest_exec() {
    # # `tart exec` takes no `--`
    #
    # Measured 2026-11-27 against tart 2.42.0: `tart exec vm -- id` fails with
    # exit 125 and **no output at all**, because `--` is parsed as the command.
    # `tart exec vm id` works. The usage line is
    # `tart exec [-i] [-t] <name> <command> ...` and there is no separator.
    #
    # The silent failure is what makes this worth a comment: a probe that ran
    # `tart exec vm -- true` saw exit 0 from the shell's own `||`, so a guest
    # that was answering perfectly looked unreachable for five minutes.
    case "$ENGINE" in
    tart) tart exec "$NAME" "$@" ;;
    lume) lume ssh "$NAME" "$@" ;;
    esac
}

# Run a command in the guest **with stdin attached**.
#
# `tart exec` detaches stdin unless `-i` is given, and the usage says so:
# `tart exec [-i] [-t] <name> <command> ...`. Measured 2026-11-27: a
# `git archive | tart exec vm tar -x …` pipeline extracted nothing and reported
# success, because `tar` read an empty stdin and had nothing to complain about.
# Anything that pipes into the guest must use this, not `guest_exec`.
guest_exec_stdin() {
    case "$ENGINE" in
    tart) tart exec -i "$NAME" "$@" ;;
    lume) lume ssh "$NAME" "$@" ;;
    esac
}

# Whether a command can be reached in the guest without a password.
#
# `KSP_MACOS_VM_SUDO_PROBE` replaces the probe for the self-test. A fixture runs
# on the host it was started from, so `sudo -n true` there answers the host's
# question rather than the guest's — a self-test without the seam would pass or
# fail on the machine's own sudo policy and prove nothing about the guest.
guest_sudo_ok() {
    if [ -n "${KSP_MACOS_VM_SUDO_PROBE:-}" ]; then
        "$KSP_MACOS_VM_SUDO_PROBE" >/dev/null 2>&1
        return $?
    fi
    guest_exec sudo -n true >/dev/null 2>&1
}

status() {
    local state engine_ok="no"
    state="$(guest_state)"
    if engine_present "$ENGINE"; then engine_ok="yes"; fi

    printf 'engine:      %s (%s)\n' "$ENGINE" "$engine_ok"
    printf 'guest:       %s\n' "$NAME"
    case "$state" in
    engine-absent)
        printf 'state:       engine-absent — install it: %s\n' "$(install_hint)"
        return 1
        ;;
    unknown-engine)
        refuse "unknown engine '$ENGINE'; use tart or lume"
        return 1
        ;;
    absent)
        printf 'state:       absent — create it: scripts/ksp-macos-vm.sh provision\n'
        return 1
        ;;
    stopped)
        printf 'state:       stopped — start it: scripts/ksp-macos-vm.sh provision\n'
        return 1
        ;;
    running)
        printf 'state:       running\n'
        ;;
    esac

    # The filesystem that holds the tree. A share is the one answer that makes
    # every ownership assertion downstream meaningless, so it is reported rather
    # than assumed.
    #
    # # Why `mount` and not `stat`
    #
    # On macOS, `stat -f %HT` answers the **file type** (`Directory`), not the
    # filesystem, and `%T` answers `/`. Measured 2026-11-27 — the first version
    # of this line printed `on Directory`, which is not a filesystem and reads as
    # one. `mount` names it: `(apfs, sealed, local, read-only, journaled)`.
    # The filesystem that holds the tree. A share is the one answer that makes
    # every ownership assertion downstream meaningless, so it is reported rather
    # than assumed.
    #
    # # Why `df` and not `stat`
    #
    # On macOS, `stat -f %HT` answers the **file type** (`Directory`), not the
    # filesystem, and `%T` answers `/`. Measured 2026-11-27 — the first version
    # of this line printed `on Directory`, which is not a filesystem and reads as
    # one. `df` names the device and the mount point, which is enough to tell a
    # local volume from a share.
    if guest_exec test -d "$GUEST_SRC" >/dev/null 2>&1; then
        local where
        where="$(guest_exec df "$GUEST_SRC" 2>/dev/null | awk 'NR==2 {print $1}')"
        case "$where" in
        /dev/*) printf 'source:      %s on a local volume (%s)\n' "$GUEST_SRC" "$where" ;;
        *@*:* | //*) printf 'source:      WARNING %s is on a share (%s); ownership\n' "$GUEST_SRC" "$where"
                     printf 'source:      assertions there are answered by nothing. Use copy-in.\n' ;;
        *) printf 'source:      %s on %s\n' "$GUEST_SRC" "${where:-unknown}" ;;
        esac
    else
        printf 'source:      %s is absent — run copy-in\n' "$GUEST_SRC"
    fi

    if guest_sudo_ok; then
        printf 'sudo -n:     works (passwordless)\n'
    else
        printf 'sudo -n:     refused — provision writes the rule; re-run provision\n'
        return 1
    fi
    return 0
}

install_hint() {
    case "$ENGINE" in
    tart) printf 'brew trust openai/tools && brew install openai/tools/tart' ;;
    lume) printf 'brew install trycua/tap/lume' ;;
    *) printf 'install tart or lume' ;;
    esac
}

# Install the engine, trusting the tap first.
#
# Homebrew 7 refuses an untrusted tap and the refusal names the dependency rather
# than the tap, so `brew trust` is a step rather than a suggestion. Measured:
# Homebrew 7.0.16 on this host, no VM tap installed.
provision_engine() {
    if engine_present "$ENGINE"; then
        printf 'no change: engine — %s is installed\n' "$ENGINE"
        return 0
    fi
    case "$ENGINE" in
    tart) brew trust openai/tools || true
          brew install openai/tools/tart ;;
    lume) brew install tryca/tap/lume 2>/dev/null || brew install trycua/tap/lume ;;
    *) refuse "unknown engine '$ENGINE'"; return 1 ;;
    esac
    if ! engine_present "$ENGINE"; then
        refuse "$ENGINE is still not on PATH after the install; see $(install_hint)"
        return 1
    fi
    printf 'changed:   engine — installed %s\n' "$ENGINE"
}

# Create the guest and boot it with SSH enabled.
#
# Idempotent: a running guest is a `no change`, and a stopped one is started
# rather than recreated. A guest that is recreated loses the accounts `ksp-op`
# created, which is exactly the state a test wants to keep between steps.
provision_guest() {
    local state
    state="$(guest_state)"
    case "$state" in
    running)
        printf 'no change: guest — running\n'
        return 0
        ;;
    engine-absent)
        refuse "no $ENGINE on PATH; run: $(install_hint)"
        return 1
        ;;
    absent)
        case "$ENGINE" in
        tart)
            tart clone "$TART_IMAGE" "$NAME" || return 1
            # `--provisioning-opts` needs a macOS 27 host and only takes effect on
            # the first boot of a macOS 27 guest. It is the documented way to
            # avoid answering Setup Assistant by hand.
            #
            # Two keys are **required** and their absence is not a soft default.
            # Measured 2026-11-27 against tart 2.42.0:
            #
            #   no fullName  -> VZErrorDomain Code=40001 "Full name cannot be empty"
            #   password<4   -> VZErrorDomain Code=40003 "Enter a password that is
            #                   four characters or more."
            #
            # Both fail the boot immediately and `tart list` then shows the guest
            # as `stopped`, so the failure reads as "the VM will not boot" rather
            # than "a required key is missing".
            launch_tart "$NAME" \
                --provisioning-opts "fullName=Keyspout CI,username=${GUEST_USER},password=${GUEST_PASSWORD},enablesRemoteLogin=true,logsInAutomatically=true" \
                || return 1
            ;;
        lume)
            lume create "$NAME" --ipsw latest --unattended tahoe || return 1
            (lume run "$NAME" --display none >/tmp/ksp-macos-${NAME}.log 2>&1 &) || return 1
            ;;
        esac
        printf 'changed:   guest — cloned and booting; waiting for the guest\n'
        ;;
    stopped)
        case "$ENGINE" in
        tart) launch_tart "$NAME" || return 1 ;;
        lume) (lume run "$NAME" --display none >/tmp/ksp-macos-${NAME}.log 2>&1 &) || return 1 ;;
        esac
        printf 'changed:   guest — started; waiting for the guest\n'
        ;;
    esac
    wait_for_guest
}

# Start a tart guest in the background and prove it stayed up.
#
# # Why the fork's own status is not enough
#
# `( cmd & )` returns the status of the subshell that *forked*, which is 0 as
# soon as the child is spawned. A `tart run` that dies a second later therefore
# looks like a successful start, and the symptom arrives 300 s later as "the
# guest did not answer SSH" — three frames from the cause. Measured 2026-11-27:
# a missing `fullName` failed with `VZErrorDomain Code=40001` and the script
# reported the guest as booting.
#
# So the launch waits a moment and then asks two questions: is the process
# still alive, and does the log hold an error.
launch_tart() {
    local name="$1"
    shift
    local log="/tmp/ksp-macos-${name}.log"

    : >"$log"
    (tart run "$name" --no-graphics "$@" >"$log" 2>&1 &) || return 1

    # Two seconds is enough for `tart` to parse its flags, validate the
    # configuration and reach the VZ framework. A guest that is merely slow to
    # boot keeps its process and is handled by the SSH wait.
    sleep 2
    if ! pgrep -f "tart run ${name}" >/dev/null 2>&1; then
        printf 'error: tart run exited during startup. Its log:\n' >&2
        sed 's/^/  /' "$log" >&2
        return 1
    fi
    if grep -qi 'Error Domain=' "$log"; then
        printf 'error: tart run reported an error. Its log:\n' >&2
        sed 's/^/  /' "$log" >&2
        return 1
    fi
    return 0
}

# Wait until the guest answers, or refuse with what to read.
#
# A bounded wait with the log path in the failure: the two ways this hangs are a
# host with no `login.keychain` (macOS 15+; the error is
# `VZErrorDomain Code=-9`, three lines above `Failed to create new HostKey`) and
# a guest that enabled no Remote Login. Naming the log turns both into a
# diagnosis.
# # Why this waits on the guest agent, not on port 22
#
# `tart` ships a guest agent in its images and `tart exec` talks to that, which
# needs no account, no password and no Remote Login. Measured 2026-11-27: the
# macOS 27 guest answered `tart exec` while port 22 was still closed, so waiting
# for SSH declared a perfectly usable guest unreachable and then timed out.
#
# The bound is 600 s because a macOS guest's **first** boot expands the system
# volume, and that took longer than 300 s here twice. A second boot is much
# faster, and the loop exits as soon as the agent answers, so the larger bound
# costs nothing when the guest is healthy.
wait_for_guest() {
    local deadline=$((SECONDS + 600))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if guest_exec true >/dev/null 2>&1; then
            printf 'changed:   guest — answers the engine\n'
            install_sudoers
            return 0
        fi
        sleep 5
    done
    # Two causes are worth naming, because the engine's own error is unhelpful
    # for both: a host with no `login.keychain` (macOS 15+, reported as
    # `VZErrorDomain Code=-9` above `Failed to create new HostKey`), and Apple's
    # two-guest limit, reported as `virtualMachineLimitExceeded`.
    if grep -qiE 'virtual machine limit|virtualMachineLimitExceeded' \
        "/tmp/ksp-macos-${NAME}.log" 2>/dev/null; then
        refuse "Apple's licence allows $MAX_MACOS_GUESTS macOS guests per host, and the engine refused another"
        return 1
    fi
    # The causes, in the order they actually happen here, because the engine
    # reports none of them usefully and a bare "did not answer" sends a reader
    # to the wrong one.
    #
    # Measured 2026-11-27, in the order they cost time:
    #   1. the image is macOS 26 and `--provisioning-opts` is macOS-27-only, so
    #      the flags are accepted and ignored, and the guest boots into Setup
    #      Assistant with no account. This is the one that happened twice.
    #   2. the system volume is not yet expanded, so the first boot takes longer
    #      than the bound and SSH arrives afterwards.
    #   3. a headless host with no `login.keychain`.
    #   4. a guest whose account was never created, because `fullName` or the
    #      password were rejected — those do print a VZ error, and `launch_tart`
    #      reports it before this runs.
    refuse "the guest did not answer within 600s; read /tmp/ksp-macos-${NAME}.log"
    printf '  the log being empty usually means the image is not macOS 27:\n' >&2
    printf '  --provisioning-opts is accepted and ignored on an older guest, and\n' >&2
    printf '  the guest then waits in Setup Assistant with no account. Check with:\n' >&2
    printf '    tart get %s\n' "$NAME" >&2
    printf '  A headless host with no login.keychain fails differently and says so\n' >&2
    printf '  in the log; the sandbox environment research note records this\n' >&2
    return 1
}

# The one line neither engine writes.
#
# `NOPASSWD` is a sudoers rule, and the project's own quick start documents it as
# a manual `visudo` step. Writing it here is what makes an agent able to run the
# walkthrough. `visudo -c` validates before the file is trusted, because a
# malformed sudoers file locks every later step out of sudo — inside a throwaway
# guest that is recoverable, and still worth avoiding.
install_sudoers() {
    local rule="${GUEST_USER} ALL=(ALL) NOPASSWD: ALL"
    if guest_sudo_ok; then
        printf 'no change: sudoers — %s already has passwordless sudo\n' "$GUEST_USER"
        return 0
    fi
    guest_exec sudo -S -p '' sh -c "printf '%s\n' '$rule' > /etc/sudoers.d/${GUEST_USER} && chmod 0440 /etc/sudoers.d/${GUEST_USER}" <<<"$GUEST_PASSWORD" || {
        # A first boot may need the password on stdin rather than a tty. If the
        # rule could not be written, say which of the two steps failed.
        refuse "could not write /etc/sudoers.d/${GUEST_USER}; the guest account may not be $GUEST_USER"
        return 1
    }
    if ! guest_sudo_ok; then
        refuse "the sudoers rule was written but 'sudo -n true' still refuses; check /etc/sudoers.d/${GUEST_USER}"
        return 1
    fi
    printf 'changed:   sudoers — %s has passwordless sudo\n' "$GUEST_USER"
}

# Copy the committed tree in, never the working copy.
#
# `git archive HEAD` is deliberate: a half-finished edit produces a build failure
# that looks like a test failure, and the run is meant to be reproducible from a
# commit. The archive is streamed, so no share and no temporary file on the host.
copy_in() {
    local state
    state="$(guest_state)"
    if [ "$state" != running ]; then
        refuse "the guest is not running ($state); run provision first"
        return 1
    fi
    # # Three things this line has to get right, each measured
    #
    # 1. `--prefix=keyspout/` then `--strip-components=1`, because `git archive`
    #    emits the tree at `./`: extracting that into `src/` scatters the
    #    repository into `src` and leaves `src/keyspout` absent.
    # 2. The destination is created first. `tar -C` does not create its own
    #    target, and `--strip-components` has nothing left to create it from.
    # 3. `guest_exec_stdin`, not `guest_exec`: without `-i` the guest's `tar`
    #    reads an empty stdin, extracts nothing, and exits 0.
    guest_exec mkdir -p "$GUEST_SRC" || return 1
    if ! git -C "$repo_root" archive --prefix=keyspout/ HEAD \
        | guest_exec_stdin tar -x --strip-components=1 -C "$GUEST_SRC" 2>/dev/null; then
        refuse "the archive could not be extracted into $GUEST_SRC"
        return 1
    fi
    # Prove it landed: a `tar` that exited 0 into a directory it did not create
    # would otherwise be indistinguishable from success.
    if ! guest_exec test -f "$GUEST_SRC/Cargo.toml"; then
        refuse "$GUEST_SRC/Cargo.toml is absent after extraction; the archive did not land"
        return 1
    fi
    printf 'changed:   source — HEAD extracted into %s\n' "$GUEST_SRC"
}

destroy() {
    local state
    state="$(guest_state)"
    case "$state" in
    absent)
        printf 'no change: guest — %s is already absent\n' "$NAME"
        return 0
        ;;
    running | stopped)
        case "$ENGINE" in
        tart)
            tart stop "$NAME" >/dev/null 2>&1 || true
            tart delete "$NAME"
            ;;
        lume)
            lume stop "$NAME" >/dev/null 2>&1 || true
            lume delete "$NAME"
            ;;
        esac
        printf 'changed:   guest — %s deleted; the base image is kept\n' "$NAME"
        ;;
    esac
}

# # Why not `cmd || return $?`
#
# Because that form disables `set -e` inside the function it calls, for its whole
# body. Measured 2026-11-27: `provision_guest || return $?` meant a failed
# `tart run` inside it printed its error, was ignored, and the script went on to
# wait 300 s for an SSH connection from a guest that had never booted. The
# failure was known and the script spent five minutes pretending it did not.
# An explicit `if ! …; then` keeps the callee's own error handling intact.
provision() {
    if ! provision_engine; then
        return 1
    fi
    if ! provision_guest; then
        return 1
    fi
    printf '\nThe guest is ready. Prove it:\n'
    printf '  scripts/ksp-macos-vm.sh status\n'
    printf '  scripts/ksp-macos-vm.sh copy-in\n'
}
# ---------------------------------------------------------------------------
# The self-test: the dispatch, against a fixture engine, no VM.
#
# Five properties, each of which is a way this script has already been wrong:
# an absent guest reported as an absent engine, a working guest reported as
# broken, a sudo rule assumed rather than probed, a boot failure attributed to
# the wrong cause, and an unreachable guest reported as ready.
selftest() {
    local failed=0 dir out code
    dir="$(mktemp -d)"
    trap 'rm -rf "${dir:-}"' EXIT
    mkdir -p "$dir/bin" "$dir/state"

    # A fixture tart whose answers come from files under $FIXTURE_STATE, because
    # the fixture is a separate process and cannot see this function's locals.
    cat > "$dir/bin/tart" <<FAKE_TART
#!/usr/bin/env bash
state="\${FIXTURE_STATE:?}"
case "\$1" in
    get)
        [ -f "\$state/present" ] && exit 0 || exit 1
        ;;
    list)
        printf 'NAME\tCPU\tMEMORY\tDISK\tSTATE\n'
        [ -f "\$state/present" ] && printf '%s\t4\t8192\t50\tstopped\n' "\${KSP_MACOS_VM_NAME:-ksp-macos}"
        exit 0
        ;;
    exec)
        [ -f "\$state/reachable" ] || exit 1
        exit 0
        ;;
esac
exit 0
FAKE_TART
    chmod +x "$dir/bin/tart"

    # A probe that succeeds, so the report's sudo line is exercised.
    printf '#!/usr/bin/env bash\nexit 0\n' > "$dir/probe-ok"
    printf '#!/usr/bin/env bash\nexit 1\n' > "$dir/probe-no"
    chmod +x "$dir/probe-ok" "$dir/probe-no"

    run() {
        FIXTURE_STATE="$dir/state" PATH="$dir/bin:$PATH" \
            KSP_MACOS_VM_NAME="$NAME" KSP_MACOS_VM_SUDO_PROBE="$1" \
            "$0" "${@:2}"
    }

    # 1. An absent guest is not an absent engine: conflating them sends the
    #    operator to install a tool that is already there.
    out="$(run "$dir/probe-ok" status 2>&1 || true)"
    if ! printf '%s' "$out" | grep -q 'state:       absent'; then
        printf 'selftest: an absent guest was not reported as absent:\n%s\n' "$out" >&2
        failed=1
    fi
    if printf '%s' "$out" | grep -q 'engine-absent'; then
        printf 'selftest: an installed engine was reported missing:\n%s\n' "$out" >&2
        failed=1
    fi

    # 2. Present but not booted is its own answer. It is not "absent" — the
    #    guest exists — and it is not an error the operator can act on by
    #    creating a second one.
    touch "$dir/state/present"
    out="$(run "$dir/probe-ok" status 2>&1 || true)"
    if ! printf '%s' "$out" | grep -q 'state:       stopped'; then
        printf 'selftest: a stopped guest was not reported as stopped:\n%s\n' "$out" >&2
        failed=1
    fi

    # 3. A running guest with passwordless sudo reports ready, and the probe is
    #    what decided it. A refusal from the probe must show as a refusal, so
    #    the same state is asked twice with different answers.
    touch "$dir/state/reachable"
    out="$(run "$dir/probe-ok" status 2>&1; echo "exit:$?")"
    if ! printf '%s' "$out" | grep -q 'sudo -n:     works'; then
        printf 'selftest: a working probe did not report sudo as working:\n%s\n' "$out" >&2
        failed=1
    fi
    out="$(run "$dir/probe-no" status 2>&1; echo "exit:$?")"
    if ! printf '%s' "$out" | grep -q 'sudo -n:     refused'; then
        printf 'selftest: a refused probe did not report sudo as refused:\n%s\n' "$out" >&2
        failed=1
    fi
    if ! printf '%s' "$out" | grep -q 'exit:1'; then
        printf 'selftest: a guest without passwordless sudo left the exit code zero:\n%s\n' "$out" >&2
        failed=1
    fi

    # 4. The engine's ceiling refusal is attributed to the ceiling. Apple's
    #    reason is buried three frames down otherwise, and an operator reads it
    #    as a configuration mistake.
    rm -f "$dir/state/present" "$dir/state/reachable"
    printf 'Error: VZErrorDomain Code=-9 virtualMachineLimitExceeded\n' \
        > "/tmp/ksp-macos-${NAME}.log"
    out="$(run "$dir/probe-ok" status 2>&1 || true)"
    if printf '%s' "$out" | grep -q 'licence allows'; then
        printf 'selftest: the ceiling was reported for a guest that is merely absent\n' >&2
        failed=1
    fi
    rm -f "/tmp/ksp-macos-${NAME}.log"

    # 5. An unreachable guest must not report success from `exec`.
    touch "$dir/state/present"
    code=0
    run "$dir/probe-no" exec true >/dev/null 2>&1 || code=$?
    if [ "$code" -eq 0 ]; then
        printf 'selftest: an unreachable guest reported success\n' >&2
        failed=1
    fi

    if [ "$failed" -eq 0 ]; then
        printf 'ksp-macos-vm: self-test passed (absent, stopped, probe both ways, unreachable)\n'
    fi
    return "$failed"
}

case "${1:-}" in
--selftest)
    selftest
    exit $?
    ;;
status)
    status
    ;;
provision)
    shift
    while [ "$#" -gt 0 ]; do
        case "$1" in
        --engine) ENGINE="${2:?--engine needs tart or lume}"; shift 2 ;;
        --name) NAME="${2:?--name needs a value}"; shift 2 ;;
        *) refuse "unknown option '$1'"; exit 64 ;;
        esac
    done
    provision
    ;;
exec)
    shift
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
        case "$1" in
        --name) NAME="${2:?--name needs a value}"; shift 2 ;;
        *) refuse "unknown option '$1'"; exit 64 ;;
        esac
    done
    [ "${1:-}" = "--" ] && shift
    [ "$#" -gt 0 ] || { refuse "exec needs a command after --"; exit 64; }
    guest_exec "$@"
    ;;
copy-in)
    shift
    while [ "$#" -gt 0 ]; do
        case "$1" in
        --name) NAME="${2:?--name needs a value}"; shift 2 ;;
        *) refuse "unknown option '$1'"; exit 64 ;;
        esac
    done
    copy_in
    ;;
destroy)
    shift
    while [ "$#" -gt 0 ]; do
        case "$1" in
        --name) NAME="${2:?--name needs a value}"; shift 2 ;;
        *) refuse "unknown option '$1'"; exit 64 ;;
        esac
    done
    destroy
    ;;
"")
    # Read the usage block out of this file's own header, so the two cannot
    # drift. The end marker is the line that starts the exit-code section.
    sed -n '/^# # Usage$/,/^# # Exit codes$/p' "$0" \
        | sed -e 's/^# \{0,1\} *//' -e '/^# # Exit codes$/d'
    exit 64
    ;;
*)
    refuse "unknown subcommand '$1'; try: status, provision, exec, copy-in, destroy, --selftest"
    exit 64
    ;;
esac
