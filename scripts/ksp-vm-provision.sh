#!/usr/bin/env bash
#
# ksp-vm-provision.sh — bring the Keyspout Linux VM to the documented shape.
#
# Idempotent by construction, not by convention: every step asks the guest what it
# already has and does nothing when the answer is "it has this". A second run prints
# `no change` for every step and exits zero. That is the property the gate relies on:
# a provisioning command whose second run differs is a command nobody can put in a
# setup script twice.
#
# It never leaves a half-created VM behind a refusal. The first step starts the VM,
# and every later step only runs once the VM answers — so a failure leaves a working
# machine that needs the failed step re-run, not a partial one.
#
# See DEVELOPMENT.md for why each piece is here.
#
# Usage:
#   scripts/ksp-vm-provision.sh
#   scripts/ksp-vm-provision.sh --selftest    # the steps against a fixture guest
#
# Exit codes:
#   0   every step satisfied (a change happened, or nothing needed changing)
#   1   a step failed, named on stderr
#   69  colima is absent or the VM cannot be started
#   64  usage

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/vm-guard.sh
. "${script_dir}/lib/vm-guard.sh"

# The guest's package set, the kernel branch the Landlock ABI needs, and the three
# service units. One list each, so a change is one edit.
VM_PACKAGES=(build-essential pkg-config libssl-dev clang cmake)
VM_KERNEL_BRANCH=${VM_KERNEL_BRANCH:-7.}
VM_KERNEL_PACKAGE=${VM_KERNEL_PACKAGE:-linux-image-generic-hwe-24.04}
VM_TOOLCHAIN_VERSION=${VM_TOOLCHAIN_VERSION:-1.99.1}
VM_CARGO_TOOLS=(cargo-audit cargo-nextest)
VM_UNITS=(valkey-server ksp-rustfs ksp-garage)

# Run one shell string in the guest.
#
# `KSP_VM_GUEST` replaces the transport for the self-test: a command that takes the
# script as its only argument. It is a test seam, and the product never reads it —
# the real transport is `colima ssh`, which is the only way in.
vm_guest() {
    if [ -n "${KSP_VM_GUEST:-}" ]; then
        "$KSP_VM_GUEST" "$1"
        return $?
    fi
    colima ssh -- bash -lc "set -euo pipefail; export PATH=\"\$HOME/.cargo/bin:\$PATH\"; $1"
}

# Report one step. `changed` says what it did; `no change` says why nothing was due.
step_changed() {
    printf 'changed:   %s — %s\n' "$1" "$2"
}
step_unchanged() {
    printf 'no change: %s — %s\n' "$1" "$2"
}
step_failed() {
    printf 'error: step "%s" failed: %s\n' "$1" "$2" >&2
}

# 1. colima, then the VM itself.
provision_vm() {
    if ! command -v colima >/dev/null 2>&1; then
        printf 'error: colima is not installed; see DEVELOPMENT.md §2\n' >&2
        return 69
    fi
    if colima status >/dev/null 2>&1; then
        step_unchanged vm "colima reports a running VM"
        return 0
    fi
    # `$VM_START_COMMAND` is a single shell string by design: it is the line a
    # reader copies, and splitting it into argv here would let the two drift.
    if ! $VM_START_COMMAND >/dev/null 2>&1; then
        step_failed vm "colima start failed; nothing else was attempted"
        return 1
    fi
    step_changed vm "started with: $VM_START_COMMAND"
}

# 2. The guest packages the C-transitive crates need.
provision_packages() {
    local missing=() package
    for package in "${VM_PACKAGES[@]}"; do
        if ! vm_guest "dpkg -s '$package' >/dev/null 2>&1"; then
            missing+=("$package")
        fi
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        step_unchanged packages "${#VM_PACKAGES[@]} packages present"
        return 0
    fi
    # `"${missing[*]}"`, not `"${missing[@]}"` inside a larger string: the `@` form
    # expands to several words and would split the guest command at each name.
    local names
    names="$(printf '%s ' "${missing[@]}")"
    if ! vm_guest "sudo apt-get update -qq && sudo apt-get install -y ${names}"; then
        step_failed packages "apt-get refused: ${missing[*]}"
        return 1
    fi
    step_changed packages "installed ${missing[*]}"
}

# 3. The guest kernel. The ABI is the reason this step exists at all.
#
# The GRUB entry must name the kernel that was just *installed*, and the kernel that
# was installed is not the one running: `uname -r` on this machine answers the kernel
# the VM booted, which is the kernel this step replaces. It is also not a shell
# substitution to write inside `vm_guest "..."`, because those double quotes expand it
# on the **host** — the entry would name the macOS kernel version, and GRUB would boot
# the old kernel while the step reported success. So the guest derives the entry from
# `/boot`, and the package name is substituted into the script below rather than
# interpolated by the shell that sends it.
provision_kernel() {
    local running
    running="$(vm_guest "uname -r")"
    case "$running" in
    "${VM_KERNEL_BRANCH}"*)
        step_unchanged kernel "running $running, which carries Landlock ABI V8"
        return 0
        ;;
    esac

    local script result
    script="$(cat <<'GUEST'
set -euo pipefail
sudo apt-get install -y __PACKAGE__
branch='__BRANCH__'
installed="$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|.*/vmlinuz-||' | sort -V)"
if [ -z "$installed" ]; then
    printf 'the package installed no kernel into /boot\n' >&2
    exit 1
fi
newest=''
for candidate in $installed; do
    if [ "${candidate#"$branch"}" != "$candidate" ]; then
        newest="$candidate"
    fi
done
if [ -z "$newest" ]; then
    printf 'no installed kernel starts with %s; /boot has: %s\n' \
        "$branch" "$(printf '%s ' $installed)" >&2
    exit 1
fi
entry="Advanced options for Ubuntu>Ubuntu, with Linux $newest"
sudo sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"$entry\"|" /etc/default/grub
sudo update-grub
printf 'default=%s\n' "$entry"
GUEST
)"
    script="${script//__PACKAGE__/$VM_KERNEL_PACKAGE}"
    script="${script//__BRANCH__/$VM_KERNEL_BRANCH}"

    if ! result="$(vm_guest "$script")"; then
        step_failed kernel "the kernel package or GRUB refused; the running kernel is $running"
        return 1
    fi
    step_changed kernel "installed $VM_KERNEL_PACKAGE and pointed GRUB at ${result#default=}; reboot the VM before trusting the ABI"
}

# 4. The toolchain the gate builds with.
provision_toolchain() {
    local version
    if ! version="$(vm_guest "rustc --version")"; then
        if ! vm_guest "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $VM_TOOLCHAIN_VERSION --component rustfmt --component clippy"; then
            step_failed toolchain "rustup refused"
            return 1
        fi
        step_changed toolchain "installed rust $VM_TOOLCHAIN_VERSION with rustfmt and clippy"
        return 0
    fi
    case "$version" in
    *"$VM_TOOLCHAIN_VERSION"*)
        step_unchanged toolchain "$version"
        ;;
    *)
        # Installing beside the default is not a change the gate can use: `cargo` would
        # keep resolving to whatever `rustup default` already named, and the step would
        # report success while every build ran on the old compiler. `default` is part of
        # the step, not a separate convenience.
        if ! vm_guest "rustup toolchain install $VM_TOOLCHAIN_VERSION --component rustfmt --component clippy && rustup default $VM_TOOLCHAIN_VERSION"; then
            step_failed toolchain "rustup refused; running $version"
            return 1
        fi
        step_changed toolchain "installed $VM_TOOLCHAIN_VERSION beside $version and made it the default"
        ;;
    esac
    # The two cargo tools the gate runs. Asked one at a time so the report names the
    # one that was missing.
    local tool
    for tool in "${VM_CARGO_TOOLS[@]}"; do
        if vm_guest "command -v $tool >/dev/null 2>&1"; then
            step_unchanged "$tool" "present"
        elif ! vm_guest "cargo install --locked $tool"; then
            step_failed "$tool" "cargo install --locked $tool refused"
            return 1
        else
            step_changed "$tool" "installed"
        fi
    done
}

# 5. The three services, enabled at boot.
provision_services() {
    local unit
    for unit in "${VM_UNITS[@]}"; do
        if vm_guest "systemctl is-enabled --quiet '$unit' && systemctl is-active --quiet '$unit'"; then
            step_unchanged "service:$unit" "enabled and running"
            continue
        fi
        # The unit files are the guest's; this enables what is already installed.
        # A unit that does not exist is a failure here rather than a silent skip:
        # the S3 backend tests would otherwise fail much later with a connection
        # error that reads like a code defect.
        #
        # `enable` writes into `/etc/systemd/system/*.wants`, which is root's, and the
        # guest user is the mounted macOS account — measured: without `sudo` this
        # answers `Failed to enable unit: Access denied` and exits 1. `is-enabled` and
        # `is-active` are readable unprivileged, so only the writing half needs it.
        if ! vm_guest "sudo systemctl enable --now '$unit'"; then
            step_failed "service:$unit" "systemctl enable --now refused; is the unit installed?"
            return 1
        fi
        step_changed "service:$unit" "enabled and started"
    done
}

provision_all() {
    local step
    for step in vm packages kernel toolchain services; do
        "provision_${step}"
    done
    printf '\nThe VM matches the documented shape. Prove it with:\n  scripts/ksp-vm.sh status\n'
}

# The self-test: the steps against a fixture guest, no VM.
#
# Three properties, because they are the three ways an idempotent command fails:
# a second run that changes something, a failed step that reports success, and a
# start failure that leaves later steps running.
vm_selftest() {
    local failed=0
    VM_SELFTEST_DIR="$(mktemp -d)"
    trap 'rm -rf "${VM_SELFTEST_DIR:-}"' EXIT
    local dir="$VM_SELFTEST_DIR"

    mkdir -p "$dir/bin"
    cat > "$dir/bin/colima" <<'FAKE_RUNNING'
#!/usr/bin/env bash
case "$1" in
    status) exit 0 ;;
    start) exit 1 ;;
    ssh) exit 0 ;;
esac
exit 0
FAKE_RUNNING
    chmod +x "$dir/bin/colima"

    # A guest that already has everything: every check answers "present".
    cat > "$dir/guest-provisioned" <<'FAKE_GUEST'
#!/usr/bin/env bash
script="$1"
case "$script" in
    *"dpkg -s"*) exit 0 ;;
    *"uname -r"*) printf '7.0.0-38-generic\n' ;;
    *"rustc --version"*) printf 'rustc 1.99.1 (fixture)\n' ;;
    *"command -v"*) exit 0 ;;
    *"systemctl is-enabled"*) exit 0 ;;
    *"systemctl enable"*) exit 0 ;;
esac
exit 0
FAKE_GUEST
    chmod +x "$dir/guest-provisioned"

    local first second
    first="$(PATH="$dir/bin:$PATH" KSP_VM_GUEST="$dir/guest-provisioned" "$0" 2>&1)"
    second="$(PATH="$dir/bin:$PATH" KSP_VM_GUEST="$dir/guest-provisioned" "$0" 2>&1)"
    if ! printf '%s' "$second" | grep -q 'no change: vm'; then
        printf 'selftest: the second run did not report the VM as unchanged:\n%s\n' "$second" >&2
        failed=1
    fi
    # The step that mattered: a provisioned guest changes nothing at all on a rerun.
    local changed_count
    changed_count="$(printf '%s' "$second" | grep -c '^changed:' || true)"
    if [ "$changed_count" -ne 0 ]; then
        printf 'selftest: the second run changed %s step(s):\n%s\n' "$changed_count" "$second" >&2
        failed=1
    fi
    if [ "$first" != "$second" ]; then
        printf 'selftest: two runs over one guest disagreed:\nfirst:\n%s\nsecond:\n%s\n' "$first" "$second" >&2
        failed=1
    fi

    # A guest that has to be changed, and that records the script each step sends.
    #
    # The report is not the only thing a provisioner can get wrong: a step can send a
    # command that cannot work and still print `changed` because the fixture answered
    # the probe. These three assertions read the commands themselves — the kernel must
    # be derived in the guest, the toolchain must be selected and the unit enabled must
    # be enabled as root — because each of those was wrong while every other assertion
    # here passed.
    cat > "$dir/guest-needs-work" <<FAKE_GUEST_NEEDS_WORK
#!/usr/bin/env bash
printf '%s\n---\n' "\$1" >> "$dir/guest.log"
case "\$1" in
    *"dpkg -s"*) exit 0 ;;
    *"uname -r"*) printf '6.8.0-117-generic\n' ;;
    *"GRUB_DEFAULT"*) printf 'default=Advanced options for Ubuntu>Ubuntu, with Linux 7.0.0-38-generic\n' ;;
    *"rustc --version"*) printf 'rustc 1.90.0 (fixture)\n' ;;
    *"command -v"*) exit 0 ;;
    *"systemctl is-enabled"*) exit 1 ;;
    *"systemctl enable"*) exit 0 ;;
esac
exit 0
FAKE_GUEST_NEEDS_WORK
    chmod +x "$dir/guest-needs-work"

    local host_kernel
    host_kernel="$(uname -r)"
    PATH="$dir/bin:$PATH" KSP_VM_GUEST="$dir/guest-needs-work" "$0" >/dev/null 2>&1 || true

    # The installed kernel is read in the guest. A host-side `$(uname -r)` would put
    # this host's kernel into the entry, which is the defect this assertion pins.
    if ! grep -qF '/boot/vmlinuz-' "$dir/guest.log"; then
        printf 'selftest: the kernel step did not read /boot in the guest\n' >&2
        failed=1
    fi
    if grep -qF "$host_kernel" "$dir/guest.log"; then
        printf 'selftest: the kernel step sent this host'"'"'s kernel version (%s) to the guest\n' \
            "$host_kernel" >&2
        failed=1
    fi
    # Selecting the toolchain is part of installing it: a version installed beside the
    # default is one no build will use.
    if ! grep -qF "rustup default $VM_TOOLCHAIN_VERSION" "$dir/guest.log"; then
        printf 'selftest: the toolchain step installed %s but did not select it\n' \
            "$VM_TOOLCHAIN_VERSION" >&2
        failed=1
    fi
    # `enable` writes a root-owned symlink; without sudo the guest answers Access denied.
    if ! grep -qF 'sudo systemctl enable --now' "$dir/guest.log"; then
        printf 'selftest: the services step enabled a unit without root\n' >&2
        failed=1
    fi

    # A guest that refuses the rustfs unit: the step is named, and the exit is not zero.
    cat > "$dir/guest-refuses" <<'FAKE_GUEST_REFUSES'
#!/usr/bin/env bash
script="$1"
case "$script" in
    *"dpkg -s"*) exit 0 ;;
    *"uname -r"*) printf '7.0.0-38-generic\n' ;;
    *"rustc --version"*) printf 'rustc 1.99.1 (fixture)\n' ;;
    *"command -v"*) exit 0 ;;
    *"systemctl is-enabled"*) exit 1 ;;
    *"ksp-rustfs"*) exit 1 ;;
    *"systemctl enable"*) exit 0 ;;
esac
exit 0
FAKE_GUEST_REFUSES
    chmod +x "$dir/guest-refuses"

    local refused code
    refused="$(PATH="$dir/bin:$PATH" KSP_VM_GUEST="$dir/guest-refuses" "$0" 2>&1 || true)"
    if ! printf '%s' "$refused" | grep -q 'step "service:ksp-rustfs" failed'; then
        printf 'selftest: a refused unit was not named:\n%s\n' "$refused" >&2
        failed=1
    fi
    code="$(PATH="$dir/bin:$PATH" KSP_VM_GUEST="$dir/guest-refuses" "$0" >/dev/null 2>&1; echo $?)"
    if [ "$code" -eq 0 ]; then
        printf 'selftest: a refused unit left the exit code zero\n' >&2
        failed=1
    fi

    # A VM that will not start: the failure is named, and no later step runs.
    cat > "$dir/bin/colima-stopped" <<'FAKE_STOPPED'
#!/usr/bin/env bash
case "$1" in
    status) exit 1 ;;
    start) exit 1 ;;
esac
exit 0
FAKE_STOPPED
    chmod +x "$dir/bin/colima-stopped"
    mkdir -p "$dir/stopped-bin"
    mv "$dir/bin/colima-stopped" "$dir/stopped-bin/colima"

    local start_failed
    start_failed="$(PATH="$dir/stopped-bin:$PATH" KSP_VM_GUEST="$dir/guest-provisioned" "$0" 2>&1 || true)"
    if ! printf '%s' "$start_failed" | grep -q 'step "vm" failed'; then
        printf 'selftest: a failed start was not named:\n%s\n' "$start_failed" >&2
        failed=1
    fi
    # Nothing after the VM: a guest command that ran would have printed a step line.
    if printf '%s' "$start_failed" | grep -q 'no change: packages'; then
        printf 'selftest: steps ran after the VM failed to start:\n%s\n' "$start_failed" >&2
        failed=1
    fi

    if [ "$failed" -eq 0 ]; then
        printf 'ksp-vm-provision: self-test passed (idempotent rerun, named failure, no half-created VM)\n'
    fi
    return "$failed"
}

case "${1:-}" in
--selftest)
    vm_selftest
    exit $?
    ;;
"")
    provision_all
    ;;
*)
    echo "usage: $(basename "$0") [--selftest]" >&2
    exit 64
    ;;
esac
