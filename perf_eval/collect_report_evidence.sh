#!/usr/bin/env bash
set -u

repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

section() {
    printf '\n[%s]\n' "$1"
}

read_file() {
    printf '\n%s\n' "$1"
    if [ -r "$1" ]; then
        cat "$1"
    elif ! sudo -n cat "$1" 2>/dev/null; then
        printf 'Unavailable or not readable\n'
    fi
}

section 'Capture time'
date --iso-8601=seconds

section 'OS and running kernel'
cat /etc/os-release
uname -r

section 'CPU and memory'
lscpu
free -h

section 'Compiler'
gcc --version | head -n 1

section 'Installed SGX packages'
rpm -qa | sort | grep -i sgx || true

section 'SGX device nodes'
for path in /dev/isgx /dev/sgx_enclave /dev/sgx_provision; do
    if [ -e "$path" ]; then
        ls -l "$path"
    fi
done

section 'Active LSMs and ABAC settings'
for path in \
    /sys/kernel/security/lsm \
    /sys/kernel/security/abac/mode \
    /sys/kernel/security/abac/tee_mode \
    /sys/kernel/security/abac/hashmap \
    /sys/kernel/security/abac/tee_policy \
    /etc/abac/tee_env.conf
do
    read_file "$path"
done

section 'Running-kernel ABAC configuration'
read_file "/boot/config-$(uname -r)" |
    grep -E 'CONFIG_(SECURITY_ABAC|SECURITYFS|SECURITY_PATH|LSM)=|Unavailable' ||
    true

section 'Source revision'
git rev-parse HEAD
git status --short

section 'Interpretation'
printf 'This records current settings, not historical benchmark settings.\n'
printf 'Configured EPC size may need confirmation from BIOS settings.\n'
