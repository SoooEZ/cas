#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT_DIR
readonly SETTINGS_LOCK="${ROOT_DIR}/settings-gradle.lockfile"
readonly VERIFICATION_METADATA="${ROOT_DIR}/gradle/verification-metadata.xml"
readonly -a LOCKFILES=(
    "${ROOT_DIR}/gradle.lockfile"
    "${ROOT_DIR}/core/cas-server-core-web/gradle.lockfile"
    "${ROOT_DIR}/docs/cas-server-documentation-processor/gradle.lockfile"
    "${ROOT_DIR}/support/cas-server-support-redis-ticket-registry/gradle.lockfile"
    "${ROOT_DIR}/webapp/cas-server-webapp/gradle.lockfile"
    "${ROOT_DIR}/webapp/cas-server-webapp-native/gradle.lockfile"
    "${ROOT_DIR}/webapp/cas-server-webapp-jetty/gradle.lockfile"
    "${ROOT_DIR}/webapp/cas-server-webapp-tomcat/gradle.lockfile"
)
readonly -a GRADLE_COMMON_ARGUMENTS=(
    '--no-daemon'
    '--no-build-cache'
    '--no-configuration-cache'
    '--dependency-verification=strict'
    '--console=plain'
    '-Porg.gradle.java.installations.auto-download=false'
    '-Dorg.gradle.unsafe.isolated-projects=false'
    '-DCI=true'
)
readonly -a LOCK_GRAPH_ARGUMENTS=(
    ':dependencies'
    ':core:cas-server-core-web:dependencies'
    ':docs:cas-server-documentation-processor:dependencies'
    ':support:cas-server-support-redis-ticket-registry:dependencies'
    ':webapp:cas-server-webapp:dependencies'
    ':webapp:cas-server-webapp-native:dependencies'
    ':webapp:cas-server-webapp-jetty:dependencies'
    ':webapp:cas-server-webapp-tomcat:dependencies'
    '--write-locks'
)
SNAPSHOT_DIR=''
METADATA_SNAPSHOT=''
SETTINGS_LOCK_OWNED=false

cleanup() {
    if [[ ${SETTINGS_LOCK_OWNED} == true ]]; then
        rm -f -- "${SETTINGS_LOCK}"
    fi
    if [[ -n ${SNAPSHOT_DIR} ]]; then
        rm -rf -- "${SNAPSHOT_DIR}"
    fi
}

[[ -f ${VERIFICATION_METADATA} && ! -L ${VERIFICATION_METADATA} ]] \
    || { printf 'Dependency verification metadata is missing or unsafe: %s\n' "${VERIFICATION_METADATA}" >&2; exit 1; }
[[ ! -e ${SETTINGS_LOCK} && ! -L ${SETTINGS_LOCK} ]] \
    || { printf 'Refusing to replace pre-existing settings dependency lock: %s\n' "${SETTINGS_LOCK}" >&2; exit 1; }

python3 - "${ROOT_DIR}" "${LOCKFILES[@]}" <<'PY'
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
for value in sys.argv[2:]:
    lockfile = pathlib.Path(value)
    try:
        lockfile.parent.resolve(strict=True).relative_to(root)
    except (FileNotFoundError, ValueError):
        raise SystemExit(f"Dependency lock parent escapes the repository: {lockfile}") from None
    try:
        mode = os.lstat(lockfile).st_mode
    except FileNotFoundError:
        continue
    if not stat.S_ISREG(mode):
        raise SystemExit(f"Refusing unsafe pre-existing dependency lock: {lockfile}")
    try:
        lockfile.resolve(strict=True).relative_to(root)
    except ValueError:
        raise SystemExit(f"Dependency lock escapes the repository: {lockfile}") from None
PY

SNAPSHOT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/casidp-locks.XXXXXXXX")
METADATA_SNAPSHOT="${SNAPSHOT_DIR}/verification-metadata.xml"
cp -- "${VERIFICATION_METADATA}" "${METADATA_SNAPSHOT}"
trap cleanup EXIT
cd -- "${ROOT_DIR}"

verify_metadata_unchanged() {
    [[ -f ${VERIFICATION_METADATA} && ! -L ${VERIFICATION_METADATA} ]] \
        || { printf 'Dependency verification metadata became unsafe: %s\n' "${VERIFICATION_METADATA}" >&2; exit 1; }
    cmp -s -- "${METADATA_SNAPSHOT}" "${VERIFICATION_METADATA}" \
        || { printf 'Dependency verification metadata changed during lock generation: %s\n' "${VERIFICATION_METADATA}" >&2; exit 1; }
}

generate_locks() {
    local pass_name=$1
    local gradle_log="${SNAPSHOT_DIR}/${pass_name}.gradle.log"
    local gradle_status=0
    SETTINGS_LOCK_OWNED=true
    ./gradlew "${GRADLE_COMMON_ARGUMENTS[@]}" \
        "${LOCK_GRAPH_ARGUMENTS[@]}" >"${gradle_log}" 2>&1 || gradle_status=$?
    verify_metadata_unchanged
    if (( gradle_status == 0 )); then
        ./gradlew "${GRADLE_COMMON_ARGUMENTS[@]}" \
            '-DcasIdpResolveCycloneDxLock=true' \
            ':dependencies' \
            '--configuration' 'cyclonedxBom' \
            '--write-locks' >>"${gradle_log}" 2>&1 || gradle_status=$?
        verify_metadata_unchanged
    fi
    rm -f -- "${SETTINGS_LOCK}"
    SETTINGS_LOCK_OWNED=false
    if (( gradle_status != 0 )); then
        printf 'Gradle dependency lock %s failed; final log lines follow.\n' "${pass_name}" >&2
        tail -n 200 -- "${gradle_log}" >&2
        return "${gradle_status}"
    fi
    printf 'Gradle dependency lock %s completed.\n' "${pass_name}"
    return "${gradle_status}"
}

generate_locks first-pass

python3 - "${SNAPSHOT_DIR}" "${LOCKFILES[@]}" <<'PY'
import hashlib
import pathlib
import shutil
import sys

snapshot_dir = pathlib.Path(sys.argv[1])
for index, value in enumerate(sys.argv[2:]):
    lockfile = pathlib.Path(value)
    if lockfile.is_symlink() or not lockfile.is_file():
        raise SystemExit(f"Generated dependency lock is missing or unsafe: {lockfile}")
    payload = lockfile.read_bytes()
    shutil.copyfile(lockfile, snapshot_dir / f"{index}.gradle.lockfile")
    print(f"First pass SHA-256 {hashlib.sha256(payload).hexdigest()}  {lockfile}")
PY

generate_locks second-pass

python3 - "${SNAPSHOT_DIR}" "${LOCKFILES[@]}" <<'PY'
import hashlib
import pathlib
import sys

snapshot_dir = pathlib.Path(sys.argv[1])
for index, value in enumerate(sys.argv[2:]):
    lockfile = pathlib.Path(value)
    if lockfile.is_symlink() or not lockfile.is_file():
        raise SystemExit(f"Generated dependency lock is missing or unsafe: {lockfile}")
    expected = (snapshot_dir / f"{index}.gradle.lockfile").read_bytes()
    actual = lockfile.read_bytes()
    if actual != expected:
        raise SystemExit(f"Dependency lock is not byte-stable across two generations: {lockfile}")
    print(f"Stable SHA-256 {hashlib.sha256(actual).hexdigest()}  {lockfile}")
PY

printf 'All eight strict dependency locks are byte-stable.\n'
