#!/usr/bin/env bash

# Independent, fail-closed release driver for the CAS-IDP CAS 8 fork.
# It never creates/deletes tags, pushes Git refs, or invokes ci/release.sh.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly EXPECTED_GROUP='io.github.soooez.cas'
readonly EXPECTED_UPSTREAM_VERSION='8.0.1'
readonly EXPECTED_UPSTREAM_COMMIT='ca02a58b41ddd65d3b43270d01c854b845d5e1dc'
readonly EXPECTED_FORK_REPOSITORY='https://github.com/SoooEZ/cas'
readonly EXPECTED_GITHUB_REPOSITORY='SoooEZ/cas'
readonly PACKAGE_REPOSITORY='https://maven.pkg.github.com/SoooEZ/cas'

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT_DIR
readonly RELEASE_DIR="${ROOT_DIR}/.casidp-release"
readonly STAGING_REPOSITORY="${RELEASE_DIR}/repository"
readonly TASK_LOG="${RELEASE_DIR}/publish-task-graph.log"
readonly TASK_GRAPH="${RELEASE_DIR}/publish-task-graph.json"
readonly SIGNING_PUBLIC_KEY="${RELEASE_DIR}/casidp-signing-public-key.asc"
readonly AUDITOR="${ROOT_DIR}/ci/casidp-supply-chain.py"
readonly -a STRICT_DEPENDENCY_LOCKS=(
    "${ROOT_DIR}/gradle.lockfile"
    ':'
    "${ROOT_DIR}/core/cas-server-core-web/gradle.lockfile"
    ':core:cas-server-core-web'
    "${ROOT_DIR}/docs/cas-server-documentation-processor/gradle.lockfile"
    ':docs:cas-server-documentation-processor'
    "${ROOT_DIR}/support/cas-server-support-palantir/gradle.lockfile"
    ':support:cas-server-support-palantir'
    "${ROOT_DIR}/support/cas-server-support-redis-core/gradle.lockfile"
    ':support:cas-server-support-redis-core'
    "${ROOT_DIR}/support/cas-server-support-redis-ticket-registry/gradle.lockfile"
    ':support:cas-server-support-redis-ticket-registry'
    "${ROOT_DIR}/support/cas-server-support-trusted-mfa-redis/gradle.lockfile"
    ':support:cas-server-support-trusted-mfa-redis'
    "${ROOT_DIR}/support/cas-server-support-webauthn-redis/gradle.lockfile"
    ':support:cas-server-support-webauthn-redis'
    "${ROOT_DIR}/webapp/cas-server-webapp/gradle.lockfile"
    ':webapp:cas-server-webapp'
    "${ROOT_DIR}/webapp/cas-server-webapp-native/gradle.lockfile"
    ':webapp:cas-server-webapp-native'
    "${ROOT_DIR}/webapp/cas-server-webapp-jetty/gradle.lockfile"
    ':webapp:cas-server-webapp-jetty'
    "${ROOT_DIR}/webapp/cas-server-webapp-tomcat/gradle.lockfile"
    ':webapp:cas-server-webapp-tomcat'
)
export GRADLE_USER_HOME="${RELEASE_DIR}/gradle-user-home"

MODE='dry-run'
MODE_EXPLICIT=false
ALLOW_DIRTY=false
SKIP_TAG_VERIFICATION=false
UNSIGNED=false
GNUPG_TEMP=''
SBOM_TEMP=''
REPRO_TEMP=''
SUPPLY_CHAIN_INPUT_DIGEST=''
PUBLISH_GITHUB_ACTOR=''
PUBLISH_GITHUB_TOKEN=''

usage() {
    printf '%s\n' \
        'Usage: ci/casidp-release.sh [mode] [local-only options]' \
        '' \
        'Modes (exactly one):' \
        '  --dry-run       Build/audit an unsigned local Maven candidate (default).' \
        '  --ci            Build/test one unsigned source commit without staging a release.' \
        '  --sign-existing Sign and re-audit existing unsigned staged bytes; never run Gradle.' \
        '  --publish       Directly upload an existing signed candidate; never run Gradle.' \
        '  --verify-only   Validate source metadata and the complete Gradle publication task graph.' \
        '' \
        'Local-only options (rejected by --sign-existing/--publish):' \
        '  --allow-dirty             Permit an uncommitted development worktree.' \
        '  --skip-tag-verification   Permit HEAD not to be the signed release tag.' \
        '  --unsigned                Skip PGP artifact signing.'
}

die() {
    printf 'CAS-IDP release failed: %s\n' "$*" >&2
    exit 1
}

set_mode() {
    if [[ ${MODE_EXPLICIT} == true ]]; then
        die 'Specify exactly one release mode'
    fi
    MODE=$1
    MODE_EXPLICIT=true
}

while (($#)); do
    case "$1" in
        --dry-run) set_mode 'dry-run' ;;
        --ci) set_mode 'ci' ;;
        --sign-existing) set_mode 'sign-existing' ;;
        --publish) set_mode 'publish' ;;
        --verify-only) set_mode 'verify-only' ;;
        --allow-dirty) ALLOW_DIRTY=true ;;
        --skip-tag-verification) SKIP_TAG_VERIFICATION=true ;;
        --unsigned) UNSIGNED=true ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
    shift
done

if [[ ${MODE} == dry-run || ${MODE} == ci ]]; then
    UNSIGNED=true
fi

if [[ ${MODE} == sign-existing || ${MODE} == publish ]]; then
    [[ ${ALLOW_DIRTY} == false ]] || die '--allow-dirty is forbidden for a real release'
    [[ ${SKIP_TAG_VERIFICATION} == false ]] || die '--skip-tag-verification is forbidden for a real release'
    [[ ${UNSIGNED} == false ]] || die '--unsigned is forbidden for a real release'
fi

if [[ ${MODE} == dry-run || ${MODE} == verify-only || ${MODE} == ci ]]; then
    [[ -z ${PGP_PRIVATE_KEY:-} && -z ${PGP_PASSPHRASE:-} \
        && -z ${CASIDP_SIGNING_FINGERPRINT:-} \
        && -z ${CASIDP_TRUSTED_SIGNING_FINGERPRINT:-} \
        && -z ${GITHUB_TOKEN:-} && -z ${GH_TOKEN:-} ]] \
        || die "--${MODE} refuses signing or publication credentials"
fi

if [[ ${MODE} == sign-existing ]]; then
    [[ -z ${GITHUB_TOKEN:-} && -z ${GH_TOKEN:-} \
        && -z ${CASIDP_TRUSTED_SIGNING_FINGERPRINT:-} ]] \
        || die '--sign-existing refuses publication credentials'
fi

if [[ ${MODE} == publish ]]; then
    [[ -z ${PGP_PRIVATE_KEY:-} && -z ${PGP_PASSPHRASE:-} \
        && -z ${CASIDP_SIGNING_FINGERPRINT:-} ]] \
        || die '--publish refuses PGP signing material'
    PUBLISH_GITHUB_ACTOR=${GITHUB_ACTOR:-}
    PUBLISH_GITHUB_TOKEN=${GITHUB_TOKEN:-}
    unset GITHUB_ACTOR GITHUB_TOKEN
fi

cleanup() {
    PUBLISH_GITHUB_TOKEN=''
    if [[ -n ${GNUPG_TEMP} && -d ${GNUPG_TEMP} ]]; then
        rm -rf -- "${GNUPG_TEMP}"
    fi
    if [[ -n ${SBOM_TEMP} && -f ${SBOM_TEMP} ]]; then
        rm -f -- "${SBOM_TEMP}"
    fi
    if [[ -n ${REPRO_TEMP} && -d ${REPRO_TEMP} ]]; then
        rm -rf -- "${REPRO_TEMP}"
    fi
}
trap cleanup EXIT

cd -- "${ROOT_DIR}"

read_property() {
    local key=$1
    local value
    value=$(sed -n "s/^${key}=//p" gradle.properties)
    [[ -n ${value} && ${value} != *$'\n'* ]] || die "gradle.properties must contain exactly one ${key}"
    printf '%s' "${value}"
}

PROJECT_GROUP=$(read_property 'group')
readonly PROJECT_GROUP
PROJECT_VERSION=$(read_property 'version')
readonly PROJECT_VERSION
UPSTREAM_VERSION=$(read_property 'casIdpUpstreamVersion')
readonly UPSTREAM_VERSION
UPSTREAM_COMMIT=$(read_property 'casIdpUpstreamCommit')
readonly UPSTREAM_COMMIT
FORK_REPOSITORY=$(read_property 'casIdpForkRepository')
readonly FORK_REPOSITORY
FORK_COMMIT=$(git rev-parse --verify 'HEAD^{commit}')
readonly FORK_COMMIT
readonly RELEASE_TAG="v${PROJECT_VERSION}"

normalize_fingerprint() {
    printf '%s' "$1" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]'
}

trusted_signing_fingerprint() {
    case "${MODE}" in
        sign-existing) normalize_fingerprint "${CASIDP_SIGNING_FINGERPRINT:-}" ;;
        publish) normalize_fingerprint "${CASIDP_TRUSTED_SIGNING_FINGERPRINT:-}" ;;
        *) die "Mode ${MODE} has no trusted signing fingerprint" ;;
    esac
}

inspect_public_key_fingerprint() {
    local public_key=$1
    local listing public_key_count fingerprint
    [[ -f ${public_key} && ! -L ${public_key} ]] \
        || die "Signing public key is not a regular file: ${public_key}"
    listing=$(gpg --batch --with-colons --show-keys "${public_key}" 2>/dev/null) \
        || die "Unable to inspect signing public key ${public_key}"
    public_key_count=$(printf '%s\n' "${listing}" | awk -F: '$1 == "pub" { count += 1 } END { print count + 0 }')
    [[ ${public_key_count} == 1 ]] \
        || die "Signing public-key evidence must contain exactly one primary key, found ${public_key_count}"
    fingerprint=$(printf '%s\n' "${listing}" \
        | awk -F: '$1 == "pub" { primary = 1; next } primary && $1 == "fpr" { print toupper($10); exit }')
    [[ ${fingerprint} =~ ^[0-9A-F]{40}([0-9A-F]{24})?$ ]] \
        || die "Signing public-key evidence has an invalid primary fingerprint: ${fingerprint:-<none>}"
    printf '%s' "${fingerprint}"
}

initialize_gpg() {
    [[ -n ${PGP_PRIVATE_KEY:-} ]] || die 'PGP_PRIVATE_KEY is required for a signed release candidate'
    [[ -n ${PGP_PASSPHRASE:-} ]] || die 'PGP_PASSPHRASE is required for a signed release candidate'
    [[ -n ${CASIDP_SIGNING_FINGERPRINT:-} ]] || die 'CASIDP_SIGNING_FINGERPRINT is required'

    GNUPG_TEMP=$(mktemp -d "${TMPDIR:-/tmp}/casidp-gnupg.XXXXXX")
    export GNUPGHOME=${GNUPG_TEMP}
    chmod 700 "${GNUPGHOME}"
    printf '%s' "${PGP_PRIVATE_KEY}" | gpg --batch --quiet --import
    printf '%s' "${PGP_PASSPHRASE}" > "${GNUPGHOME}/passphrase"
    chmod 600 "${GNUPGHOME}/passphrase"
    unset PGP_PRIVATE_KEY PGP_PASSPHRASE

    local expected actual
    expected=$(normalize_fingerprint "${CASIDP_SIGNING_FINGERPRINT}")
    actual=$(gpg --batch --with-colons --list-secret-keys "${expected}" \
        | awk -F: '$1 == "fpr" { print toupper($10); exit }')
    [[ ${actual} == "${expected}" ]] \
        || die "Imported signing key fingerprint ${actual:-<none>} does not match ${expected}"
}

initialize_trusted_public_key() {
    [[ -n ${CASIDP_TRUSTED_SIGNING_FINGERPRINT:-} ]] \
        || die 'CASIDP_TRUSTED_SIGNING_FINGERPRINT is required for publication verification'
    local expected actual
    expected=$(normalize_fingerprint "${CASIDP_TRUSTED_SIGNING_FINGERPRINT}")
    [[ ${expected} =~ ^[0-9A-F]{40}([0-9A-F]{24})?$ ]] \
        || die 'CASIDP_TRUSTED_SIGNING_FINGERPRINT has an invalid format'

    GNUPG_TEMP=$(mktemp -d "${TMPDIR:-/tmp}/casidp-verify-gnupg.XXXXXX")
    export GNUPGHOME=${GNUPG_TEMP}
    chmod 700 "${GNUPGHOME}"
    actual=$(inspect_public_key_fingerprint "${SIGNING_PUBLIC_KEY}")
    [[ ${actual} == "${expected}" ]] \
        || die "Candidate signing public key ${actual} does not match trusted fingerprint ${expected}"

    gpg --batch --quiet --import "${SIGNING_PUBLIC_KEY}"
    actual=$(gpg --batch --with-colons --list-keys "${expected}" \
        | awk -F: '$1 == "fpr" { print toupper($10); exit }')
    [[ ${actual} == "${expected}" ]] \
        || die "Imported candidate public key ${actual:-<none>} does not match ${expected}"
}

validate_strict_dependency_locks() {
    python3 - "${STRICT_DEPENDENCY_LOCKS[@]}" <<'PY'
import os
import pathlib
import re as regex
import stat
import sys

arguments = sys.argv[1:]
if len(arguments) != 24 or len(arguments) % 2:
    raise SystemExit("Unsafe strict dependency-lock boundary: expected exactly twelve locks")

lock_specs = [
    (pathlib.Path(arguments[index]), arguments[index + 1])
    for index in range(0, len(arguments), 2)
]
expected_specs = [
    (pathlib.Path("gradle.lockfile"), ":"),
    (
        pathlib.Path("core/cas-server-core-web/gradle.lockfile"),
        ":core:cas-server-core-web",
    ),
    (
        pathlib.Path("docs/cas-server-documentation-processor/gradle.lockfile"),
        ":docs:cas-server-documentation-processor",
    ),
    (
        pathlib.Path("support/cas-server-support-palantir/gradle.lockfile"),
        ":support:cas-server-support-palantir",
    ),
    (
        pathlib.Path("support/cas-server-support-redis-core/gradle.lockfile"),
        ":support:cas-server-support-redis-core",
    ),
    (
        pathlib.Path("support/cas-server-support-redis-ticket-registry/gradle.lockfile"),
        ":support:cas-server-support-redis-ticket-registry",
    ),
    (
        pathlib.Path("support/cas-server-support-trusted-mfa-redis/gradle.lockfile"),
        ":support:cas-server-support-trusted-mfa-redis",
    ),
    (
        pathlib.Path("support/cas-server-support-webauthn-redis/gradle.lockfile"),
        ":support:cas-server-support-webauthn-redis",
    ),
    (
        pathlib.Path("webapp/cas-server-webapp/gradle.lockfile"),
        ":webapp:cas-server-webapp",
    ),
    (
        pathlib.Path("webapp/cas-server-webapp-native/gradle.lockfile"),
        ":webapp:cas-server-webapp-native",
    ),
    (
        pathlib.Path("webapp/cas-server-webapp-jetty/gradle.lockfile"),
        ":webapp:cas-server-webapp-jetty",
    ),
    (
        pathlib.Path("webapp/cas-server-webapp-tomcat/gradle.lockfile"),
        ":webapp:cas-server-webapp-tomcat",
    ),
]
root = pathlib.Path.cwd().resolve()
actual_specs = [(path.resolve().relative_to(root), project) for path, project in lock_specs]
if actual_specs != expected_specs:
    raise SystemExit(
        "Unsafe strict dependency-lock boundary: lockfile allowlist is not exact"
    )

coordinate_pattern = regex.compile(
    r"([A-Za-z0-9][A-Za-z0-9_.-]*):"
    r"([A-Za-z0-9][A-Za-z0-9_.-]*):"
    r"([A-Za-z0-9][A-Za-z0-9_.-]*)="
    r"([A-Za-z0-9][A-Za-z0-9_.-]*(?:,[A-Za-z0-9][A-Za-z0-9_.-]*)*)"
)
configuration_pattern = regex.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:,[A-Za-z0-9][A-Za-z0-9_.-]*)*"
)

for lockfile, project in lock_specs:
    description = f"{project} dependency lock"
    try:
        mode = os.lstat(lockfile).st_mode
    except FileNotFoundError:
        raise SystemExit(f"Unsafe {description}: lockfile is missing") from None
    if not stat.S_ISREG(mode):
        raise SystemExit(f"Unsafe {description}: lockfile must be a regular non-symlink file")

    raw = lockfile.read_bytes()
    if not raw or b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        raise SystemExit(
            f"Unsafe {description}: expected non-empty UTF-8 LF text with a final newline"
        )
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SystemExit(f"Unsafe {description}: invalid UTF-8: {error}") from None

    dependency_task = ":dependencies" if project == ":" else f"{project}:dependencies"
    header = [
        "# This is a Gradle generated file for dependency locking.",
        "# Manual edits can break the build and are not advised.",
        "# This file is expected to be part of source control.",
        (
            "# To regenerate this file, run: ./gradlew "
            f"{dependency_task} --write" "-locks"
        ),
    ]
    if lines[: len(header)] != header:
        raise SystemExit(f"Unsafe {description}: non-canonical header")
    entries = lines[len(header) :]
    if not entries or any(not line or line.startswith("#") for line in entries):
        raise SystemExit(f"Unsafe {description}: empty or unexpected lines")

    coordinates: set[str] = set()
    configurations_seen: set[str] = set()
    empty_seen = False
    for index, line in enumerate(entries, start=len(header) + 1):
        if line.startswith("empty="):
            if empty_seen or index != len(lines):
                raise SystemExit(
                    f"Unsafe {description}: empty= must appear exactly once at EOF"
                )
            configurations = line.removeprefix("empty=")
            if not configuration_pattern.fullmatch(configurations):
                raise SystemExit(
                    f"Unsafe {description}: malformed empty= configuration list"
                )
            empty_configurations = configurations.split(",")
            if len(empty_configurations) != len(set(empty_configurations)):
                raise SystemExit(
                    f"Unsafe {description}: duplicate empty= configuration"
                )
            empty_seen = True
            configurations_seen.update(empty_configurations)
            continue

        match = coordinate_pattern.fullmatch(line)
        if match is None:
            raise SystemExit(f"Unsafe {description} line {index}: {line!r}")
        group, module, version, configurations = match.groups()
        coordinate = f"{group}:{module}:{version}"
        if coordinate in coordinates:
            raise SystemExit(f"Unsafe {description}: duplicate coordinate {coordinate}")
        coordinates.add(coordinate)
        lowered = version.lower()
        if (
            "snapshot" in lowered
            or "+" in version
            or "*" in version
            or any(character in version for character in "[](),")
            or lowered in {"latest", "release", "latest.release", "latest.integration"}
            or lowered.startswith("latest.")
        ):
            raise SystemExit(f"Unsafe {description}: non-static version {coordinate}")
        locked_configurations = configurations.split(",")
        if len(locked_configurations) != len(set(locked_configurations)):
            raise SystemExit(
                f"Unsafe {description}: duplicate configuration for {coordinate}"
            )
        configurations_seen.update(locked_configurations)

    if not coordinates or not empty_seen:
        raise SystemExit(
            f"Unsafe {description}: dependency entries or empty= footer missing"
        )
    required_configurations = {
        ":": {"aggregateJavadocClasspath", "cyclonedxBom"},
        ":core:cas-server-core-web": {"testRuntimeClasspath"},
        ":support:cas-server-support-palantir": {"runtimeClasspath"},
        ":support:cas-server-support-redis-core": {"testRuntimeClasspath"},
        ":support:cas-server-support-redis-ticket-registry": {
            "testRuntimeClasspath"
        },
        ":support:cas-server-support-trusted-mfa-redis": {
            "testRuntimeClasspath"
        },
        ":support:cas-server-support-webauthn-redis": {
            "testRuntimeClasspath"
        },
    }.get(project, set())
    missing_configurations = required_configurations - configurations_seen
    if missing_configurations:
        raise SystemExit(
            f"Unsafe {description}: required configurations are not locked: "
            f"{sorted(missing_configurations)}"
        )
    print(f"Verified {len(coordinates)} static dependency locks for {project}.")
PY
}

validate_metadata() {
    local option_name option_value
    for option_name in GRADLE_OPTS JAVA_OPTS JAVA_TOOL_OPTIONS _JAVA_OPTIONS; do
        option_value=${!option_name:-}
        if [[ ${option_value} =~ -D(publishReleases|publishSnapshots|casIdpForkRepository|repositoryUsername|repositoryPassword) ]]; then
            die "${option_name} may not inject publication system properties"
        fi
    done

    [[ ${PROJECT_GROUP} == "${EXPECTED_GROUP}" ]] \
        || die "Fork group must be exactly ${EXPECTED_GROUP}, not ${PROJECT_GROUP}"
    [[ ${UPSTREAM_VERSION} == "${EXPECTED_UPSTREAM_VERSION}" ]] \
        || die "Upstream version must be exactly ${EXPECTED_UPSTREAM_VERSION}"
    [[ ${UPSTREAM_COMMIT} == "${EXPECTED_UPSTREAM_COMMIT}" ]] \
        || die "Upstream commit must be exactly ${EXPECTED_UPSTREAM_COMMIT}"
    [[ ${FORK_REPOSITORY} == "${EXPECTED_FORK_REPOSITORY}" ]] \
        || die "Fork repository must be exactly ${EXPECTED_FORK_REPOSITORY}"
    [[ ${PROJECT_VERSION} =~ ^8\.0\.1-casidp\.[1-9][0-9]*$ ]] \
        || die "Fork version must match 8.0.1-casidp.N, not ${PROJECT_VERSION}"
    [[ ${PROJECT_VERSION} != *-SNAPSHOT ]] || die 'Fork releases cannot be snapshots'
    [[ -f gradle/verification-metadata.xml \
        && ! -L gradle/verification-metadata.xml ]] \
        || die 'gradle/verification-metadata.xml is required and must be a regular file'
    validate_strict_dependency_locks

    if [[ -n ${GITHUB_REPOSITORY:-} ]]; then
        [[ ${GITHUB_REPOSITORY} == "${EXPECTED_GITHUB_REPOSITORY}" ]] \
            || die "This workflow is restricted to ${EXPECTED_GITHUB_REPOSITORY}"
    fi
    if [[ -n ${CASIDP_RELEASE_TAG:-} ]]; then
        [[ ${CASIDP_RELEASE_TAG} == "${RELEASE_TAG}" ]] \
            || die "Requested ref ${CASIDP_RELEASE_TAG} is not exact release tag ${RELEASE_TAG}"
    fi
    if [[ ${GITHUB_ACTIONS:-false} == true ]]; then
        [[ ${GITHUB_SHA:-} == "${FORK_COMMIT}" ]] \
            || die "Checked-out commit ${FORK_COMMIT} is not trusted workflow SHA ${GITHUB_SHA:-<none>}"
        if [[ ${MODE} == ci ]]; then
            [[ ${GITHUB_EVENT_NAME:-} =~ ^(push|pull_request|workflow_dispatch)$ ]] \
                || die 'Fork CI accepts only push, pull_request, or workflow_dispatch events'
            [[ ${GITHUB_REF_TYPE:-} == branch ]] \
                || die 'Fork CI must validate a branch or pull-request merge ref'
            case "${GITHUB_REF:-}" in
                refs/heads/*|refs/pull/*/merge) ;;
                *) die "Fork CI ref ${GITHUB_REF:-<none>} is not a branch or pull-request merge ref" ;;
            esac
            [[ ${GITHUB_WORKFLOW:-} == 'CAS-IDP Fork CI' ]] \
                || die "Unexpected fork CI workflow ${GITHUB_WORKFLOW:-<none>}"
            [[ ${GITHUB_WORKFLOW_REF:-} \
                == "${EXPECTED_GITHUB_REPOSITORY}/.github/workflows/casidp-ci.yml@"* ]] \
                || die "Workflow ref ${GITHUB_WORKFLOW_REF:-<none>} is not the fork CI workflow"
            [[ -z ${CASIDP_RELEASE_TAG:-} ]] \
                || die 'Fork CI must not receive a release tag'
        else
            [[ ${GITHUB_EVENT_NAME:-} == workflow_dispatch ]] \
                || die 'GitHub releases must be started by workflow_dispatch'
            [[ ${GITHUB_REF_TYPE:-} == tag ]] \
                || die 'GitHub releases must be dispatched from the signed release tag'
            [[ ${GITHUB_REF_NAME:-} == "${RELEASE_TAG}" ]] \
                || die "GitHub ref ${GITHUB_REF_NAME:-<none>} is not exact release tag ${RELEASE_TAG}"
            [[ ${GITHUB_REF:-} == "refs/tags/${RELEASE_TAG}" ]] \
                || die "GitHub ref ${GITHUB_REF:-<none>} is not refs/tags/${RELEASE_TAG}"
            [[ ${CASIDP_RELEASE_TAG:-} == "${GITHUB_REF_NAME}" ]] \
                || die 'Workflow release_tag is not the selected GitHub tag'
            [[ ${GITHUB_WORKFLOW_SHA:-} == "${FORK_COMMIT}" ]] \
                || die "Workflow commit ${GITHUB_WORKFLOW_SHA:-<none>} is not release commit ${FORK_COMMIT}"
            [[ ${GITHUB_WORKFLOW_REF:-} \
                == "${EXPECTED_GITHUB_REPOSITORY}/.github/workflows/casidp-release.yml@refs/tags/${RELEASE_TAG}" ]] \
                || die "Workflow ref ${GITHUB_WORKFLOW_REF:-<none>} is not the release-tag workflow"
        fi
    fi

    git cat-file -e "${UPSTREAM_COMMIT}^{commit}" \
        || die "Upstream commit ${UPSTREAM_COMMIT} is not present in the checkout"
    [[ $(git rev-parse --verify "v${UPSTREAM_VERSION}^{commit}") == "${UPSTREAM_COMMIT}" ]] \
        || die "Upstream tag v${UPSTREAM_VERSION} is not pinned to ${UPSTREAM_COMMIT}"
    git merge-base --is-ancestor "${UPSTREAM_COMMIT}" "${FORK_COMMIT}" \
        || die 'Fork release commit does not descend from the pinned upstream commit'

    local origin
    origin=$(git remote get-url origin)
    case "${origin}" in
        https://github.com/SoooEZ/cas|https://github.com/SoooEZ/cas.git|git@github.com:SoooEZ/cas.git) ;;
        *) die "origin must be the CAS-IDP fork, not ${origin}" ;;
    esac

    if [[ ${ALLOW_DIRTY} == false ]]; then
        [[ -z $(git status --porcelain=v1 --untracked-files=all) ]] \
            || die 'Release worktree must be clean, including untracked files'
    fi
}

verify_release_tag() {
    if [[ ${MODE} == ci ]]; then
        printf 'Fork CI is source validation only; no release tag is consumed.\n'
        return
    fi
    if [[ ${SKIP_TAG_VERIFICATION} == true ]]; then
        printf 'WARNING: signed tag verification was explicitly skipped for a local %s.\n' "${MODE}" >&2
        return
    fi

    [[ $(git cat-file -t "refs/tags/${RELEASE_TAG}") == tag ]] \
        || die "${RELEASE_TAG} must be an annotated, signed tag"
    [[ $(git rev-parse --verify "${RELEASE_TAG}^{commit}") == "${FORK_COMMIT}" ]] \
        || die "HEAD is not exactly ${RELEASE_TAG}"
    local tag_contents
    tag_contents=$(git cat-file tag "refs/tags/${RELEASE_TAG}")
    [[ ${tag_contents} == *'-----BEGIN PGP SIGNATURE-----'* ]] \
        || die "${RELEASE_TAG} must contain an OpenPGP signature"

    if [[ ${MODE} != sign-existing && ${MODE} != publish ]]; then
        printf 'Verified signed-tag structure and immutable commit binding for %s.\n' "${RELEASE_TAG}"
        return
    fi

    local status signer_fingerprint primary_fingerprint expected
    status=$(git verify-tag --raw "${RELEASE_TAG}" 2>&1) \
        || die "Git tag signature verification failed for ${RELEASE_TAG}"
    signer_fingerprint=$(printf '%s\n' "${status}" \
        | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print toupper($3); exit }')
    primary_fingerprint=$(printf '%s\n' "${status}" \
        | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print toupper($NF); exit }')
    expected=$(trusted_signing_fingerprint)
    [[ -n ${signer_fingerprint} \
        && (${signer_fingerprint} == "${expected}" || ${primary_fingerprint} == "${expected}") ]] \
        || die "Tag signer ${signer_fingerprint:-<none>} (primary ${primary_fingerprint:-<none>}) is not authorized by ${expected:-<none>}"
    printf 'Cryptographically verified release-tag signer %s.\n' "${expected}"
}

verify_workflow_boundary() {
    local workflow='.github/workflows/casidp-release.yml'
    local ci_workflow='.github/workflows/casidp-ci.yml'
    local reviewed_workflow
    local lock_update_flag selective_lock_update_flag verification_write_flag verification_export_flag
    printf -v lock_update_flag '%s%s' '--write' '-locks'
    printf -v selective_lock_update_flag '%s%s' '--update' '-locks'
    printf -v verification_write_flag '%s%s' '--write-verification' '-metadata'
    printf -v verification_export_flag '%s%s' '--export' '-keys'
    for reviewed_workflow in "${workflow}" "${ci_workflow}"; do
        [[ -f ${reviewed_workflow} ]] || die "Missing ${reviewed_workflow}"
        if grep -nE '^[[:space:]]*uses:[[:space:]]*[^#[:space:]]+@' "${reviewed_workflow}" \
            | grep -vE '@[0-9a-f]{40}([[:space:]]|$)'; then
            die 'Every third-party action in a CAS-IDP workflow must be pinned to a full commit SHA'
        fi
        ! grep -Eq '(^|[[:space:]/])ci/release\.sh([[:space:]]|$)' "${reviewed_workflow}" \
            || die 'CAS-IDP workflows must never call the upstream release script'
    done
    local forbidden_mutation_flag
    for forbidden_mutation_flag in \
        "${lock_update_flag}" \
        "${selective_lock_update_flag}" \
        "${verification_write_flag}" \
        "${verification_export_flag}"; do
        if grep -Fq -- "${forbidden_mutation_flag}" \
            "${workflow}" "${ci_workflow}" 'ci/casidp-release.sh'; then
            die 'CAS-IDP workflows and the release driver must never mutate dependency trust inputs'
        fi
    done
    python3 - "${workflow}" "${EXPECTED_GITHUB_REPOSITORY}" <<'PY'
import re
import sys
from pathlib import Path

workflow = Path(sys.argv[1])
repository = sys.argv[2]
text = workflow.read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Unsafe CAS-IDP release workflow: {message}")


def canonical_mapping_keys(block: str, indent: int, description: str) -> list[str]:
    prefix = " " * indent
    keys: list[str] = []
    for line in block.splitlines():
        if not line.startswith(prefix):
            continue
        remainder = line[indent:]
        if not remainder or remainder[0].isspace() or remainder.startswith("#"):
            continue
        match = re.match(r"([A-Za-z0-9_-]+):(?:[ ]|$)", remainder)
        require(
            match is not None,
            f"{description} contains a non-canonical mapping line: {line!r}",
        )
        assert match is not None
        keys.append(match.group(1))
    return keys


def context_reference_count(block: str, context: str) -> int:
    return len(
        re.findall(
            rf"(?i)(?<![A-Za-z0-9_]){re.escape(context)}(?![A-Za-z0-9_])",
            block,
        )
    )


def github_token_reference_count(block: str) -> int:
    return len(
        re.findall(
            r"(?i)(?<![A-Za-z0-9_])github\s*(?:\.\s*token|"
            r"\[\s*['\"]token['\"]\s*\])",
            block,
        )
    )


def exposes_whole_github_context(block: str) -> bool:
    return bool(
        re.search(r"(?i)(?<![A-Za-z0-9_])tojson\s*\(\s*github\s*\)", block)
        or re.search(r"(?i)\$\{\{\s*github\s*\}\}", block)
    )


def mapping(block: str, indent: int, name: str) -> dict[str, str]:
    prefix = " " * indent
    child = " " * (indent + 2)
    require(
        len(re.findall(rf"(?m)^{prefix}{re.escape(name)}:", block)) == 1,
        f"block must contain exactly one {name} mapping",
    )
    match = re.search(
        rf"(?m)^{prefix}{re.escape(name)}:\n((?:^{child}[^\n]+\n)+)",
        block,
    )
    require(match is not None, f"block is missing {name}")
    assert match is not None
    values: dict[str, str] = {}
    for line in match.group(1).splitlines():
        key, separator, value = line.strip().partition(":")
        require(separator == ":" and key not in values, f"invalid {name} entry")
        values[key] = value.strip()
    return values


def split_steps(job: str, expected_names: list[str]) -> dict[str, str]:
    _, separator, body = job.partition("\n    steps:\n")
    require(separator, "job is missing its steps sequence")
    require(
        not re.search(r"(?m)^    [A-Za-z0-9_-]+:", body),
        "job-level mappings may not follow the steps sequence",
    )
    markers = list(re.finditer(r"(?m)^      - ", body))
    require(markers and markers[0].start() == 0, "steps sequence contains unparsed content")
    names: list[str] = []
    steps: dict[str, str] = {}
    for index, marker in enumerate(markers):
        end = markers[index + 1].start() if index + 1 < len(markers) else len(body)
        step = body[marker.start():end]
        first_line = step.splitlines()[0]
        match = re.fullmatch(r"      - name: (.+)", first_line)
        require(match is not None, "every step must use an explicit reviewed name")
        assert match is not None
        name = match.group(1)
        require(name not in steps, f"duplicate step name: {name}")
        names.append(name)
        steps[name] = step
    require(names == expected_names, f"unexpected step sequence: {names}")
    return steps


def require_step_shape(
    step: str,
    name: str,
    expected_keys: list[str],
    expected_action: str | None = None,
) -> None:
    keys = canonical_mapping_keys(step, 8, name)
    require(keys == expected_keys, f"{name} has unexpected step keys: {keys}")
    uses = re.findall(r"(?m)^        uses: (.+)$", step)
    runs = re.findall(r"(?m)^        run:", step)
    if expected_action is None:
        require(not uses and len(runs) == 1, f"{name} must be exactly one run step")
    else:
        require(uses == [expected_action] and not runs, f"{name} must use only {expected_action}")


def require_exact_run(step: str, name: str, expected_lines: list[str]) -> None:
    lines = step.rstrip().splitlines()
    run_indexes = [
        index for index, line in enumerate(lines) if line.startswith("        run:")
    ]
    require(len(run_indexes) == 1, f"{name} must contain exactly one run entry")
    run_index = run_indexes[0]
    run_line = lines[run_index]
    if run_line == "        run: |":
        body: list[str] = []
        for line in lines[run_index + 1 :]:
            require(
                not line or line.startswith("          "),
                f"{name} run body contains unexpected indentation",
            )
            body.append(line[10:] if line else "")
        while body and not body[-1]:
            body.pop()
    else:
        prefix = "        run: "
        require(run_line.startswith(prefix), f"{name} has an invalid run entry")
        require(
            run_index == len(lines) - 1,
            f"{name} scalar run entry has unexpected trailing content",
        )
        body = [run_line.removeprefix(prefix)]
    require(body == expected_lines, f"{name} run body is not on the reviewed allowlist")


def require_with_keys(step: str, name: str, expected_keys: list[str]) -> None:
    keys = canonical_mapping_keys(step, 10, f"{name} action inputs")
    require(keys == expected_keys, f"{name} has unexpected action inputs: {keys}")


def literal_block_lines(block: str, indent: int, name: str) -> list[str]:
    marker = f'{" " * indent}{name}: |'
    lines = block.rstrip().splitlines()
    indexes = [index for index, line in enumerate(lines) if line == marker]
    require(len(indexes) == 1, f"{name} must contain exactly one literal block")
    child = " " * (indent + 2)
    values: list[str] = []
    for line in lines[indexes[0] + 1 :]:
        require(
            not line or line.startswith(child),
            f"{name} literal block contains unexpected indentation",
        )
        values.append(line[indent + 2 :] if line else "")
    while values and not values[-1]:
        values.pop()
    return values


def archive_path_count(block: str, path: str) -> int:
    expected = f"            {path}"
    return sum(line in {expected, f"{expected} \\"} for line in block.splitlines())


checkout_action = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
download_action = (
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"
)
upload_action = (
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"
)
setup_java_action = "actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95 # v5.6.0"
setup_gradle_action = (
    "gradle/actions/setup-gradle@3f131e8634966bd73d06cc69884922b02e6faf92 # v6.2.0"
)
attest_provenance_action = (
    "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373 # v4.1.1"
)
attest_action = "actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1"


require("\t" not in text, "tabs are forbidden")
require(
    canonical_mapping_keys(text, 0, "workflow")
    == ["name", "on", "permissions", "jobs"],
    "top-level keys must be exactly name, on, permissions, and jobs",
)
require(
    text.splitlines()[0] == "name: CAS-IDP Fork Release",
    "workflow name must be exact",
)

on_parts = text.split("\non:\n")
require(len(on_parts) == 2, "must contain exactly one top-level on mapping")
on_block, separator, remainder = on_parts[1].partition("\npermissions:\n")
require(separator, "on mapping must be followed by top-level permissions")
events = canonical_mapping_keys(on_block, 2, "trigger mapping")
require(events == ["workflow_dispatch"], "workflow_dispatch must be the only trigger")

top_permissions, separator, jobs_text = remainder.partition("\njobs:\n")
require(separator, "must contain exactly one top-level jobs mapping")
require(
    top_permissions.strip().splitlines() == ["contents: read"],
    "top-level permissions must be contents: read only",
)
require(not re.search(r"(?m)^concurrency:", text), "top-level concurrency must not serialize dry runs")

markers = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\n", jobs_text))
require(
    [marker.group(1) for marker in markers] == ["candidate", "sign", "publish"],
    "jobs must be exactly candidate, sign, and publish",
)
require(
    canonical_mapping_keys(jobs_text, 2, "jobs mapping")
    == ["candidate", "sign", "publish"],
    "jobs mapping contains a non-canonical or unexpected job",
)
require(
    not re.search(r"(?m)^[A-Za-z0-9_-]+:", jobs_text),
    "unexpected top-level mapping follows jobs",
)
jobs: dict[str, str] = {}
for index, marker in enumerate(markers):
    end = markers[index + 1].start() if index + 1 < len(markers) else len(jobs_text)
    jobs[marker.group(1)] = jobs_text[marker.start():end]
require(set(jobs) == {"candidate", "sign", "publish"}, "unexpected release jobs")
expected_job_keys = {
    "candidate": [
        "name",
        "if",
        "runs-on",
        "timeout-minutes",
        "permissions",
        "outputs",
        "services",
    ],
    "sign": [
        "name",
        "needs",
        "if",
        "runs-on",
        "timeout-minutes",
        "environment",
        "permissions",
        "outputs",
    ],
    "publish": [
        "name",
        "needs",
        "if",
        "runs-on",
        "timeout-minutes",
        "environment",
        "concurrency",
        "permissions",
    ],
}
for job_name, block in jobs.items():
    header, separator, _ = block.partition("\n    steps:\n")
    require(separator, f"{job_name} is missing steps")
    keys = canonical_mapping_keys(header, 4, f"{job_name} job")
    require(
        keys == expected_job_keys[job_name],
        f"{job_name} has unexpected job-level keys: {keys}",
    )

candidate_header, _, _ = jobs["candidate"].partition("\n    steps:\n")
_, services_separator, services = candidate_header.partition("\n    services:\n")
require(services_separator, "candidate is missing its reviewed Redis service")
require(
    services.rstrip()
    == """      redis:
        image: redis:7.4.7-alpine@sha256:02f2cc4882f8bf87c79a220ac958f58c700bdec0dfb9b9ea61b62fb0e8f1bfcf
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 20""",
    "candidate Redis service is not on the reviewed allowlist",
)

checkout_sha = "          ref: ${{ github.sha }}"
for job_name in ("candidate", "sign", "publish"):
    block = jobs[job_name]
    expected_guard = f"    if: ${{{{ github.repository == '{repository}' "
    expected_guard += "&& github.ref_type == 'tag' "
    expected_guard += "&& github.ref_name == inputs.release_tag"
    if job_name in {"sign", "publish"}:
        expected_guard += " && inputs.dry_run == false"
    expected_guard += " }}"
    guards = re.findall(r"(?m)^    if: .+$", block)
    require(
        guards == [expected_guard],
        f"{job_name} is missing the exact repository/tag/mode guard",
    )
    require(block.count("inputs.release_tag") == 1, f"{job_name} may use release_tag only in its guard")
    require(
        block.count(f"uses: {checkout_action}") == 1,
        f"{job_name} must use one pinned checkout action",
    )
    require(block.count(checkout_sha) == 1, f"{job_name} checkout must use trusted github.sha")
    require(
        block.count("          persist-credentials: false") == 1,
        f"{job_name} checkout must not persist credentials",
    )
    refs = re.findall(r"(?m)^\s+ref:\s*(.+)$", block)
    require(refs == ["${{ github.sha }}"], f"{job_name} contains an untrusted checkout ref")
    require(
        block.count("          CASIDP_RELEASE_TAG: ${{ github.ref_name }}")
        == 1,
        f"{job_name} must derive the release tag only from github.ref_name",
    )
    require(
        not re.search(r"(?m)^    env:", block),
        f"{job_name} must not define job-level environment variables",
    )

candidate_names = [
    "Check out the trusted workflow-dispatch commit",
    "Download the exact Amazon Corretto 25.0.4.7.1 archive",
    "Set up the checksum-pinned JDK",
    "Verify the exact Java runtime",
    "Set up Gradle with a read-only dependency cache",
    "Build and audit the unsigned candidate",
    "Package the exact audited candidate",
    "Preserve the complete unsigned candidate",
]
sign_names = [
    "Check out the trusted workflow-dispatch commit",
    "Download the unsigned candidate produced by this run",
    "Verify and extract the exact unsigned candidate archive",
    "Sign the existing staged bytes without a publication token",
    "Attest the aggregate SHA-256 release manifest",
    "Attest the CycloneDX SBOM",
    "Attest the complete release manifest",
    "Package the exact signed candidate",
    "Preserve the complete signed candidate",
]
publish_names = [
    "Check out the trusted workflow-dispatch commit",
    "Download the signed candidate produced by this run",
    "Verify and extract the exact signed candidate archive",
    "Publish only the signed staged bytes",
    "Attest successful publication completion",
    "Preserve signed release evidence",
]
steps = {
    "candidate": split_steps(jobs["candidate"], candidate_names),
    "sign": split_steps(jobs["sign"], sign_names),
    "publish": split_steps(jobs["publish"], publish_names),
}

for job_name in steps:
    require_step_shape(
        steps[job_name]["Check out the trusted workflow-dispatch commit"],
        f"{job_name} checkout",
        ["uses", "with"],
        checkout_action,
    )
    require(
        mapping(
            steps[job_name]["Check out the trusted workflow-dispatch commit"],
            8,
            "with",
        )
        == {
            "ref": "${{ github.sha }}",
            "fetch-depth": "0",
            "fetch-tags": "true",
            "persist-credentials": "false",
        },
        f"{job_name} checkout is not bound to the immutable workflow SHA",
    )

require(
    mapping(jobs["candidate"], 4, "permissions") == {"contents": "read"},
    "candidate must have contents: read and no write permissions",
)
require("    concurrency:" not in jobs["candidate"], "candidate must not occupy the publication lock")
require("    environment:" not in jobs["candidate"], "candidate must not access a protected environment")
require(
    context_reference_count(jobs["candidate"], "secrets") == 0
    and context_reference_count(jobs["candidate"], "vars") == 0
    and github_token_reference_count(jobs["candidate"]) == 0
    and not exposes_whole_github_context(jobs["candidate"])
    and all(
        value not in jobs["candidate"]
        for value in (
            "PGP_PRIVATE_KEY",
            "PGP_PASSPHRASE",
            "CASIDP_SIGNING_FINGERPRINT",
            "CASIDP_TRUSTED_SIGNING_FINGERPRINT",
            "GITHUB_TOKEN",
            "GH_TOKEN",
        )
    ),
    "candidate must not receive release secrets or a publication token",
)
require(
    "    needs:" not in jobs["candidate"]
    and "    environment:" not in jobs["candidate"]
    and "    concurrency:" not in jobs["candidate"],
    "candidate must be independent of protected release state",
)
require(
    jobs["candidate"].count("./ci/casidp-release.sh --dry-run --unsigned") == 1,
    "candidate must run exactly one unsigned dry run",
)
require_exact_run(
    steps["candidate"][candidate_names[5]],
    candidate_names[5],
    [
        "set -Eeuo pipefail",
        "chmod +x ci/casidp-release.sh ci/casidp-supply-chain.py",
        "./ci/casidp-release.sh --dry-run --unsigned",
    ],
)
candidate_shapes = {
    candidate_names[1]: (["env", "run"], None),
    candidate_names[2]: (["uses", "with"], setup_java_action),
    candidate_names[3]: (["run"], None),
    candidate_names[4]: (["uses", "with"], setup_gradle_action),
    candidate_names[5]: (["env", "run"], None),
    candidate_names[6]: (["id", "env", "run"], None),
    candidate_names[7]: (["uses", "with"], upload_action),
}
for name, (keys, action) in candidate_shapes.items():
    require_step_shape(steps["candidate"][name], name, keys, action)

corretto_step = steps["candidate"][candidate_names[1]]
require(
    mapping(corretto_step, 8, "env")
    == {
        "CORRETTO_SHA256": (
            "1d03a3bd5091728492d92f0ef341aca7d8885ece9a150119558f3e3d62b58745"
        ),
        "CORRETTO_URL": (
            "https://corretto.aws/downloads/resources/25.0.4.7.1/"
            "amazon-corretto-25.0.4.7.1-linux-x64.tar.gz"
        ),
    },
    "candidate must download the exact reviewed Corretto archive",
)
require(
    corretto_step.count("sha256sum --check -") == 1,
    "candidate must verify the pinned Corretto archive checksum",
)
jdk_step = steps["candidate"][candidate_names[2]]
require(
    mapping(jdk_step, 8, "with")
    == {
        "distribution": "jdkfile",
        "java-version": "'25.0.4+7'",
        "architecture": "x64",
        "jdk-file": (
            "${{ runner.temp }}/amazon-corretto-25.0.4.7.1-linux-x64.tar.gz"
        ),
    },
    "candidate must install only the checksum-pinned Corretto JDK",
)
require(
    mapping(steps["candidate"][candidate_names[4]], 8, "with")
    == {"cache-read-only": "true", "validate-wrappers": "true"},
    "candidate Gradle setup inputs are not on the reviewed allowlist",
)
require(
    mapping(steps["candidate"][candidate_names[5]], 8, "env")
    == {"CASIDP_RELEASE_TAG": "${{ github.ref_name }}"},
    "candidate build must receive only the selected GitHub tag",
)
require(
    mapping(jobs["candidate"], 4, "outputs")
    == {
        "artifact_name": "${{ steps.package.outputs.artifact_name }}",
        "candidate_sha256": "${{ steps.package.outputs.candidate_sha256 }}",
    },
    "candidate must expose only the archive name and SHA-256",
)
require(
    mapping(steps["candidate"][candidate_names[6]], 8, "env")
    == {
        "CANDIDATE_ARTIFACT_NAME": (
            "casidp-release-candidate-${{ github.ref_name }}-${{ github.sha }}"
        )
    },
    "unsigned artifact name must bind the selected tag and workflow SHA",
)
candidate_package_step = steps["candidate"][candidate_names[6]]
require_exact_run(
    candidate_package_step,
    candidate_names[6],
    [
        "set -Eeuo pipefail",
        'archive="${RUNNER_TEMP}/${CANDIDATE_ARTIFACT_NAME}.tar"',
        "tar \\",
        "  --format=posix \\",
        "  --sort=name \\",
        '  --mtime="@$(git show -s --format=%ct HEAD)" \\',
        "  --owner=0 \\",
        "  --group=0 \\",
        "  --numeric-owner \\",
        '  -cf "${archive}" \\',
        "  .casidp-release/repository \\",
        "  .casidp-release/SHA256SUMS \\",
        "  .casidp-release/casidp-release-manifest.json \\",
        "  .casidp-release/casidp.cdx.json \\",
        "  .casidp-release/publish-task-graph.json \\",
        "  .casidp-release/publish-task-graph.log",
        'digest=$(sha256sum "${archive}" | awk \'{print $1}\')',
        'printf \'%s  %s\\n\' "${digest}" "$(basename "${archive}")" \\',
        '  > "${archive}.sha256"',
        'printf \'artifact_name=%s\\n\' "${CANDIDATE_ARTIFACT_NAME}" >> "${GITHUB_OUTPUT}"',
        'printf \'candidate_sha256=%s\\n\' "${digest}" >> "${GITHUB_OUTPUT}"',
        'printf \'Candidate archive SHA-256: %s\\n\' "${digest}"',
    ],
)
candidate_upload_step = steps["candidate"][candidate_names[7]]
require_with_keys(
    candidate_upload_step,
    candidate_names[7],
    ["name", "if-no-files-found", "retention-days", "compression-level", "path"],
)
require(
    all(
        candidate_upload_step.splitlines().count(line) == 1
        for line in (
            "          name: ${{ steps.package.outputs.artifact_name }}",
            "          if-no-files-found: error",
            "          retention-days: 14",
            "          compression-level: 0",
        )
    ),
    "unsigned artifact upload settings are not on the reviewed allowlist",
)
require(
    literal_block_lines(candidate_upload_step, 10, "path")
    == [
        "${{ runner.temp }}/${{ steps.package.outputs.artifact_name }}.tar",
        "${{ runner.temp }}/${{ steps.package.outputs.artifact_name }}.tar.sha256",
    ],
    "unsigned artifact upload paths must use only the candidate outputs",
)
for path in (
    ".casidp-release/repository",
    ".casidp-release/SHA256SUMS",
    ".casidp-release/casidp-release-manifest.json",
    ".casidp-release/casidp.cdx.json",
    ".casidp-release/publish-task-graph.json",
    ".casidp-release/publish-task-graph.log",
):
    require(
        archive_path_count(jobs["candidate"], path) == 1,
        f"candidate archive must contain exactly one {path}",
    )
require(
    mapping(jobs["sign"], 4, "permissions")
    == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    },
    "sign must have attestation permissions but no package write permission",
)
require(
    re.findall(r"(?m)^    needs: (.+)$", jobs["sign"]) == ["candidate"],
    "sign must depend only on candidate",
)
require(
    len(re.findall(r"(?m)^    environment: casidp-release-sign$", jobs["sign"])) == 1,
    "sign must use only the protected casidp-release-sign environment",
)
require("    concurrency:" not in jobs["sign"], "sign must not occupy the package lock")
require(
    all(
        value not in jobs["sign"]
        for value in (
            "packages: write",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "github.token",
            "actions/setup-java@",
            "gradle/actions/setup-gradle@",
            "./gradlew",
            "--publish",
        )
    ),
    "sign job mixes package credentials, build tooling, or publication",
)
require(
    context_reference_count(jobs["sign"], "secrets") == 3
    and context_reference_count(jobs["sign"], "vars") == 0
    and github_token_reference_count(jobs["sign"]) == 0
    and not exposes_whole_github_context(jobs["sign"])
    and jobs["sign"].count("PGP_PRIVATE_KEY") == 2
    and jobs["sign"].count("PGP_PASSPHRASE") == 2
    and jobs["sign"].count("CASIDP_SIGNING_FINGERPRINT") == 2,
    "sign job must reference exactly the three reviewed PGP secrets",
)
require(
    mapping(jobs["sign"], 4, "outputs")
    == {
        "signed_artifact_name": (
            "${{ steps.package_signed.outputs.signed_artifact_name }}"
        ),
        "signed_candidate_sha256": (
            "${{ steps.package_signed.outputs.signed_candidate_sha256 }}"
        ),
    },
    "sign must expose only the signed artifact name and SHA-256",
)
sign_shapes = {
    sign_names[1]: (["uses", "with"], download_action),
    sign_names[2]: (["env", "run"], None),
    sign_names[3]: (["env", "run"], None),
    sign_names[4]: (["uses", "with"], attest_provenance_action),
    sign_names[5]: (["uses", "with"], attest_action),
    sign_names[6]: (["uses", "with"], attest_action),
    sign_names[7]: (["id", "env", "run"], None),
    sign_names[8]: (["uses", "with"], upload_action),
}
for name, (keys, action) in sign_shapes.items():
    require_step_shape(steps["sign"][name], name, keys, action)
require(
    mapping(steps["sign"][sign_names[1]], 8, "with")
    == {
        "name": "${{ needs.candidate.outputs.artifact_name }}",
        "path": "${{ runner.temp }}/casidp-unsigned-candidate",
    },
    "sign must download only its candidate dependency artifact",
)
require(
    mapping(steps["sign"][sign_names[2]], 8, "env")
    == {
        "CANDIDATE_ARTIFACT_NAME": "${{ needs.candidate.outputs.artifact_name }}",
        "EXPECTED_CANDIDATE_SHA256": (
            "${{ needs.candidate.outputs.candidate_sha256 }}"
        ),
    },
    "sign must verify the candidate dependency name and digest",
)
require(
    steps["sign"][sign_names[2]].count(
        '[[ "${actual}" == "${EXPECTED_CANDIDATE_SHA256}" ]]'
    )
    == 1,
    "sign must compare the unsigned archive to the needs digest",
)
for reviewed_line in (
    'archive="${RUNNER_TEMP}/casidp-unsigned-candidate/${CANDIDATE_ARTIFACT_NAME}.tar"',
    'checksum="${archive}.sha256"',
    'actual=$(sha256sum "${archive}" | awk \'{print $1}\')',
    '[[ "$(awk \'{print $1}\' "${checksum}")" == "${EXPECTED_CANDIDATE_SHA256}" ]]',
    '[[ "$(awk \'{print $2}\' "${checksum}")" == "$(basename "${archive}")" ]]',
):
    require(
        steps["sign"][sign_names[2]].splitlines().count(f"          {reviewed_line}")
        == 1,
        f"sign archive verification is missing reviewed binding: {reviewed_line}",
    )
require(
    mapping(steps["sign"][sign_names[3]], 8, "env")
    == {
        "CASIDP_RELEASE_TAG": "${{ github.ref_name }}",
        "CASIDP_SIGNING_FINGERPRINT": "${{ secrets.CASIDP_SIGNING_FINGERPRINT }}",
        "PGP_PRIVATE_KEY": "${{ secrets.PGP_PRIVATE_KEY }}",
        "PGP_PASSPHRASE": "${{ secrets.PGP_PASSPHRASE }}",
    },
    "signing step must receive exactly the reviewed PGP inputs",
)
require(
    steps["sign"][sign_names[3]].count("./ci/casidp-release.sh --sign-existing") == 1,
    "sign must sign the existing candidate exactly once",
)
require_exact_run(
    steps["sign"][sign_names[3]],
    sign_names[3],
    [
        "set -Eeuo pipefail",
        "chmod +x ci/casidp-release.sh ci/casidp-supply-chain.py",
        "./ci/casidp-release.sh --sign-existing",
    ],
)
require(
    mapping(steps["sign"][sign_names[4]], 8, "with")
    == {"subject-path": ".casidp-release/SHA256SUMS"},
    "aggregate provenance attestation inputs are not on the reviewed allowlist",
)
require(
    mapping(steps["sign"][sign_names[5]], 8, "with")
    == {
        "subject-path": ".casidp-release/SHA256SUMS",
        "sbom-path": ".casidp-release/casidp.cdx.json",
    },
    "SBOM attestation inputs are not on the reviewed allowlist",
)
require(
    mapping(steps["sign"][sign_names[6]], 8, "with")
    == {
        "subject-path": ".casidp-release/SHA256SUMS",
        "predicate-type": (
            "https://github.com/SoooEZ/cas/attestations/"
            "casidp-release-manifest/v1"
        ),
        "predicate-path": ".casidp-release/casidp-release-manifest.json",
    },
    "release-manifest attestation inputs are not on the reviewed allowlist",
)
require(
    mapping(steps["sign"][sign_names[7]], 8, "env")
    == {
        "SIGNED_ARTIFACT_NAME": (
            "casidp-release-signed-${{ github.ref_name }}-${{ github.sha }}"
        )
    },
    "signed artifact name must bind the selected tag and workflow SHA",
)
signed_package_step = steps["sign"][sign_names[7]]
require_exact_run(
    signed_package_step,
    sign_names[7],
    [
        "set -Eeuo pipefail",
        'archive="${RUNNER_TEMP}/${SIGNED_ARTIFACT_NAME}.tar"',
        "tar \\",
        "  --format=posix \\",
        "  --sort=name \\",
        '  --mtime="@$(git show -s --format=%ct HEAD)" \\',
        "  --owner=0 \\",
        "  --group=0 \\",
        "  --numeric-owner \\",
        '  -cf "${archive}" \\',
        "  .casidp-release/repository \\",
        "  .casidp-release/SHA256SUMS \\",
        "  .casidp-release/SHA256SUMS.asc \\",
        "  .casidp-release/casidp-release-manifest.json \\",
        "  .casidp-release/casidp-release-manifest.json.asc \\",
        "  .casidp-release/casidp.cdx.json \\",
        "  .casidp-release/casidp.cdx.json.asc \\",
        "  .casidp-release/casidp-signing-public-key.asc \\",
        "  .casidp-release/publish-task-graph.json \\",
        "  .casidp-release/publish-task-graph.json.asc \\",
        "  .casidp-release/publish-task-graph.log \\",
        "  .casidp-release/publish-task-graph.log.asc",
        'digest=$(sha256sum "${archive}" | awk \'{print $1}\')',
        'printf \'%s  %s\\n\' "${digest}" "$(basename "${archive}")" \\',
        '  > "${archive}.sha256"',
        'printf \'signed_artifact_name=%s\\n\' "${SIGNED_ARTIFACT_NAME}" >> "${GITHUB_OUTPUT}"',
        'printf \'signed_candidate_sha256=%s\\n\' "${digest}" >> "${GITHUB_OUTPUT}"',
        'printf \'Signed candidate archive SHA-256: %s\\n\' "${digest}"',
    ],
)
signed_upload_step = steps["sign"][sign_names[8]]
require_with_keys(
    signed_upload_step,
    sign_names[8],
    ["name", "if-no-files-found", "retention-days", "compression-level", "path"],
)
require(
    all(
        signed_upload_step.splitlines().count(line) == 1
        for line in (
            "          name: ${{ steps.package_signed.outputs.signed_artifact_name }}",
            "          if-no-files-found: error",
            "          retention-days: 14",
            "          compression-level: 0",
        )
    ),
    "signed artifact upload settings are not on the reviewed allowlist",
)
require(
    literal_block_lines(signed_upload_step, 10, "path")
    == [
        "${{ runner.temp }}/${{ steps.package_signed.outputs.signed_artifact_name }}.tar",
        "${{ runner.temp }}/${{ steps.package_signed.outputs.signed_artifact_name }}.tar.sha256",
    ],
    "signed artifact upload paths must use only the sign outputs",
)
for path in (
    ".casidp-release/repository",
    ".casidp-release/SHA256SUMS",
    ".casidp-release/SHA256SUMS.asc",
    ".casidp-release/casidp-release-manifest.json",
    ".casidp-release/casidp-release-manifest.json.asc",
    ".casidp-release/casidp.cdx.json",
    ".casidp-release/casidp.cdx.json.asc",
    ".casidp-release/casidp-signing-public-key.asc",
    ".casidp-release/publish-task-graph.json",
    ".casidp-release/publish-task-graph.json.asc",
    ".casidp-release/publish-task-graph.log",
    ".casidp-release/publish-task-graph.log.asc",
):
    require(
        archive_path_count(steps["sign"][sign_names[7]], path) == 1,
        f"signed archive must contain exactly one {path}",
    )

require(
    re.findall(r"(?m)^    needs: (.+)$", jobs["publish"]) == ["sign"],
    "publish must depend only on sign",
)
require(
    mapping(jobs["publish"], 4, "permissions")
    == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    },
    "publish permissions do not match the reviewed least-privilege set",
)
require(
    len(re.findall(r"(?m)^    environment: casidp-release-publish$", jobs["publish"])) == 1,
    "publish must use only the protected casidp-release-publish environment",
)
require(
    mapping(jobs["publish"], 4, "concurrency")
    == {"group": "casidp-release-publish", "cancel-in-progress": "false"},
    "real publication must use one global, non-cancelling lock",
)
require(
    all(
        value not in jobs["publish"]
        for value in (
            "PGP_PRIVATE_KEY",
            "PGP_PASSPHRASE",
            "CASIDP_SIGNING_FINGERPRINT:",
            "GH_TOKEN",
            "actions/setup-java@",
            "gradle/actions/setup-gradle@",
            "./gradlew",
            "--sign-existing",
            "--detach-sign",
            "--local-user",
            "gpg ",
            "java-version:",
            "jdkFile:",
            "jdk-file:",
        )
    ),
    "publish job contains PGP material or build/JDK tooling",
)
require(
    github_token_reference_count(jobs["publish"]) == 1
    and not exposes_whole_github_context(jobs["publish"])
    and jobs["publish"].count("GITHUB_TOKEN") == 1
    and context_reference_count(jobs["publish"], "secrets") == 0
    and context_reference_count(jobs["publish"], "vars") == 1
    and jobs["publish"].count(
        "${{ vars.CASIDP_TRUSTED_SIGNING_FINGERPRINT }}"
    )
    == 1
    and jobs["publish"].count("CASIDP_TRUSTED_SIGNING_FINGERPRINT") == 2,
    "publish must expose only the package token and protected trusted public-key fingerprint",
)
publish_shapes = {
    publish_names[1]: (["uses", "with"], download_action),
    publish_names[2]: (["env", "run"], None),
    publish_names[3]: (["env", "run"], None),
    publish_names[4]: (["uses", "with"], attest_action),
    publish_names[5]: (["if", "uses", "with"], upload_action),
}
for name, (keys, action) in publish_shapes.items():
    require_step_shape(steps["publish"][name], name, keys, action)
require(
    mapping(steps["publish"][publish_names[1]], 8, "with")
    == {
        "name": "${{ needs.sign.outputs.signed_artifact_name }}",
        "path": "${{ runner.temp }}/casidp-signed-candidate",
    },
    "publish must download only its sign dependency artifact",
)
require(
    mapping(steps["publish"][publish_names[2]], 8, "env")
    == {
        "SIGNED_ARTIFACT_NAME": "${{ needs.sign.outputs.signed_artifact_name }}",
        "EXPECTED_SIGNED_CANDIDATE_SHA256": (
            "${{ needs.sign.outputs.signed_candidate_sha256 }}"
        ),
    },
    "publish must verify the signed dependency name and digest",
)
require(
    steps["publish"][publish_names[2]].count(
        '[[ "${actual}" == "${EXPECTED_SIGNED_CANDIDATE_SHA256}" ]]'
    )
    == 1,
    "publish must compare the signed archive to the needs digest",
)
for reviewed_line in (
    'archive="${RUNNER_TEMP}/casidp-signed-candidate/${SIGNED_ARTIFACT_NAME}.tar"',
    'checksum="${archive}.sha256"',
    'actual=$(sha256sum "${archive}" | awk \'{print $1}\')',
    '[[ "$(awk \'{print $1}\' "${checksum}")" == "${EXPECTED_SIGNED_CANDIDATE_SHA256}" ]]',
    '[[ "$(awk \'{print $2}\' "${checksum}")" == "$(basename "${archive}")" ]]',
):
    require(
        steps["publish"][publish_names[2]].splitlines().count(
            f"          {reviewed_line}"
        )
        == 1,
        f"publish archive verification is missing reviewed binding: {reviewed_line}",
    )
for path in (
    ".casidp-release/SHA256SUMS",
    ".casidp-release/SHA256SUMS.asc",
    ".casidp-release/casidp-release-manifest.json",
    ".casidp-release/casidp-release-manifest.json.asc",
    ".casidp-release/casidp.cdx.json",
    ".casidp-release/casidp.cdx.json.asc",
    ".casidp-release/casidp-signing-public-key.asc",
    ".casidp-release/publish-task-graph.json",
    ".casidp-release/publish-task-graph.json.asc",
    ".casidp-release/publish-task-graph.log",
    ".casidp-release/publish-task-graph.log.asc",
):
    require(
        steps["publish"][publish_names[2]].splitlines().count(
            f'              "{path}",'
        )
        == 1,
        f"publish extraction must require exactly one {path}",
    )
require(
    mapping(steps["publish"][publish_names[3]], 8, "env")
    == {
        "CASIDP_RELEASE_TAG": "${{ github.ref_name }}",
        "CASIDP_TRUSTED_SIGNING_FINGERPRINT": (
            "${{ vars.CASIDP_TRUSTED_SIGNING_FINGERPRINT }}"
        ),
        "GITHUB_ACTOR": "${{ github.actor }}",
        "GITHUB_TOKEN": "${{ github.token }}",
    },
    "publication step must receive exactly the GitHub package credentials",
)
require(
    steps["publish"][publish_names[3]].count("./ci/casidp-release.sh --publish") == 1,
    "publication step must directly upload the existing candidate exactly once",
)
require_exact_run(
    steps["publish"][publish_names[3]],
    publish_names[3],
    ["./ci/casidp-release.sh --publish"],
)
require(
    mapping(steps["publish"][publish_names[4]], 8, "with")
    == {
        "subject-path": ".casidp-release/SHA256SUMS",
        "predicate-type": (
            "https://github.com/SoooEZ/cas/attestations/casidp-publication/v1"
        ),
        "predicate-path": ".casidp-release/casidp-publication.json",
    },
    "publication-completion attestation inputs are not on the reviewed allowlist",
)
evidence_step = steps["publish"][publish_names[5]]
require_with_keys(
    evidence_step,
    publish_names[5],
    [
        "name",
        "if-no-files-found",
        "retention-days",
        "compression-level",
        "include-hidden-files",
        "path",
    ],
)
require(
    evidence_step.splitlines().count("        if: ${{ always() }}") == 1
    and all(
        evidence_step.splitlines().count(line) == 1
        for line in (
            "          name: casidp-release-evidence-${{ github.ref_name }}-${{ github.sha }}",
            "          if-no-files-found: warn",
            "          retention-days: 90",
            "          compression-level: 0",
            "          include-hidden-files: true",
        )
    ),
    "publication evidence upload settings are not on the reviewed allowlist",
)
require(
    literal_block_lines(evidence_step, 10, "path")
    == [
        ".casidp-release/SHA256SUMS",
        ".casidp-release/SHA256SUMS.asc",
        ".casidp-release/casidp-release-manifest.json",
        ".casidp-release/casidp-release-manifest.json.asc",
        ".casidp-release/casidp.cdx.json",
        ".casidp-release/casidp.cdx.json.asc",
        ".casidp-release/casidp-signing-public-key.asc",
        ".casidp-release/publish-task-graph.json",
        ".casidp-release/publish-task-graph.json.asc",
        ".casidp-release/publish-task-graph.log",
        ".casidp-release/publish-task-graph.log.asc",
        ".casidp-release/casidp-publication.json",
    ],
    "publication evidence upload paths are not on the reviewed allowlist",
)
PY
    python3 - "${ci_workflow}" "${EXPECTED_GITHUB_REPOSITORY}" <<'PY'
import re
import sys
from pathlib import Path

workflow = Path(sys.argv[1])
repository = sys.argv[2]
text = workflow.read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Unsafe CAS-IDP CI workflow: {message}")


require("\t" not in text, "tabs are forbidden")
require(
    re.findall(r"(?m)^([A-Za-z0-9_-]+):", text)
    == ["name", "on", "permissions", "concurrency", "jobs"],
    "top-level mappings are not on the reviewed allowlist",
)
require(text.splitlines()[0] == "name: CAS-IDP Fork CI", "workflow name must be exact")
on_parts = text.split("\non:\n")
require(len(on_parts) == 2, "must contain exactly one top-level on mapping")
on_block, separator, _ = on_parts[1].partition("\npermissions:\n")
require(separator, "trigger mapping must be followed by permissions")
require(
    re.findall(r"(?m)^  ([a-z_]+):", on_block)
    == ["push", "pull_request", "workflow_dispatch"],
    "triggers must be exactly push, pull_request, and workflow_dispatch",
)
required_branch = "      - casidp/issuance-generation-fence-8.0.1"
require(on_block.splitlines().count(required_branch) == 2, "CI branch boundary is not exact")
require(
    text.count("permissions:\n  contents: read") == 1
    and text.count("    permissions:\n      contents: read") == 1,
    "workflow and job permissions must both be contents: read only",
)
require(
    not any(
        value in text
        for value in (
            ": write",
            "pull_request_target:",
            "schedule:",
            "environment:",
            "${{ secrets.",
            "${{ vars.",
            "github.token",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "toJSON(github)",
        )
    ),
    "CI may not receive write permissions, release environments, or secrets",
)
jobs = text.split("\njobs:\n", 1)[1]
require(
    re.findall(r"(?m)^  ([A-Za-z0-9_-]+):$", jobs) == ["verify"],
    "CI must contain exactly one verify job",
)
require(
    jobs.count(f"    if: ${{{{ github.repository == '{repository}' }}}}") == 1,
    "verify job must use the exact fork repository guard",
)
require(jobs.count("    runs-on: ubuntu-24.04") == 1, "runner image must be exact")
require(jobs.count("    timeout-minutes: 360") == 1, "job timeout must be exact")
require(
    text.count("redis:7.4.7-alpine@sha256:02f2cc4882f8bf87c79a220ac958f58c700bdec0dfb9b9ea61b62fb0e8f1bfcf")
    == 1,
    "Redis service image must be digest pinned",
)
expected_actions = [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
    "actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95 # v5.6.0",
    "gradle/actions/setup-gradle@3f131e8634966bd73d06cc69884922b02e6faf92 # v6.2.0",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
]
require(
    re.findall(r"(?m)^\s+uses: (.+)$", text) == expected_actions,
    "action sequence or immutable action identities changed",
)
for required in (
    "          ref: ${{ github.sha }}",
    "          fetch-depth: 0",
    "          fetch-tags: true",
    "          persist-credentials: false",
    "          distribution: jdkfile",
    "          java-version: '25.0.4+7'",
    "          architecture: x64",
    "          jdk-file: ${{ runner.temp }}/amazon-corretto-25.0.4.7.1-linux-x64.tar.gz",
    "          cache-read-only: true",
    "          validate-wrappers: true",
    "        run: ./ci/casidp-release.sh --ci",
    "        if: ${{ always() }}",
    "          include-hidden-files: true",
):
    require(text.splitlines().count(required) == 1, f"missing exact contract line: {required}")
require(
    text.count("./ci/casidp-release.sh --ci") == 1
    and all(
        option not in text
        for option in ("--dry-run", "--verify-only", "--sign-existing", "--publish")
    ),
    "CI must invoke exactly one non-publishing driver mode",
)
for image in (
    "koalaman/shellcheck@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d",
    "rhysd/actionlint@sha256:887a259a5a534f3c4f36cb02dca341673c6089431057242cdc931e9f133147e9",
):
    require(text.count(image) == 1, f"lint image is not exact: {image}")
PY
    grep -Fq "github.repository == 'apereo/cas'" '.github/workflows/release.yml' \
        || die 'Official release workflow is not guarded against fork execution'
    grep -Fq "github.repository == 'apereo/cas'" '.github/workflows/publish.yml' \
        || die 'Official publish workflow is not guarded against fork execution'
}

reset_release_directory() {
    [[ ${RELEASE_DIR} == "${ROOT_DIR}/.casidp-release" ]] || die 'Unsafe release directory'
    rm -rf -- "${RELEASE_DIR}"
    mkdir -p -- "${STAGING_REPOSITORY}"
}

staging_url() {
    python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve().as_uri())' "${STAGING_REPOSITORY}"
}

require_redis_test_service() {
    python3 - <<'PY'
import socket

endpoint = ("127.0.0.1", 6379)
try:
    with socket.create_connection(endpoint, timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(b"*1\r\n$4\r\nPING\r\n")
        response = bytearray()
        while not response.endswith(b"\r\n") and len(response) <= 64:
            chunk = connection.recv(64)
            if not chunk:
                break
            response.extend(chunk)
except OSError as error:
    raise SystemExit(
        "CAS-IDP release requires the pinned Redis regression service on "
        f"127.0.0.1:6379: {error}"
    ) from None
if bytes(response) != b"+PONG\r\n":
    raise SystemExit(
        "CAS-IDP release Redis regression service returned an invalid PING "
        f"response: {bytes(response)!r}"
    )
print("Verified Redis regression service on 127.0.0.1:6379.")
PY
}

readonly GRADLE_COMMON_ARGUMENTS=(
    '--no-daemon'
    '--no-build-cache'
    '--no-configuration-cache'
    '--dependency-verification=strict'
    '--console=plain'
    '--stacktrace'
    '-Porg.gradle.java.installations.auto-download=false'
    '-Dorg.gradle.unsafe.isolated-projects=false'
    '-DPTS_ENABLED=false'
    '-DCI=true'
    '-DcasIdpForkPublish=true'
    '-DpublishMinimalArtifacts'
)

supply_chain_input_digest() {
    python3 - \
        gradle/verification-metadata.xml \
        gradle.lockfile \
        core/cas-server-core-web/gradle.lockfile \
        docs/cas-server-documentation-processor/gradle.lockfile \
        support/cas-server-support-palantir/gradle.lockfile \
        support/cas-server-support-redis-core/gradle.lockfile \
        support/cas-server-support-redis-ticket-registry/gradle.lockfile \
        support/cas-server-support-trusted-mfa-redis/gradle.lockfile \
        support/cas-server-support-webauthn-redis/gradle.lockfile \
        webapp/cas-server-webapp/gradle.lockfile \
        webapp/cas-server-webapp-native/gradle.lockfile \
        webapp/cas-server-webapp-jetty/gradle.lockfile \
        webapp/cas-server-webapp-tomcat/gradle.lockfile <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

digest = hashlib.sha256()
for value in sys.argv[1:]:
    path = pathlib.Path(value)
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        raise SystemExit(f"Missing immutable dependency trust input: {path}") from None
    if not stat.S_ISREG(mode):
        raise SystemExit(
            f"Immutable dependency trust input is not a regular file: {path}"
        )
    name = path.as_posix().encode("utf-8")
    payload = path.read_bytes()
    digest.update(len(name).to_bytes(4, "big"))
    digest.update(name)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
print(digest.hexdigest())
PY
}

capture_supply_chain_inputs() {
    [[ -z ${SUPPLY_CHAIN_INPUT_DIGEST} ]] \
        || die 'Dependency trust inputs were already captured'
    SUPPLY_CHAIN_INPUT_DIGEST=$(supply_chain_input_digest)
    [[ ${SUPPLY_CHAIN_INPUT_DIGEST} =~ ^[0-9a-f]{64}$ ]] \
        || die 'Unable to capture immutable dependency trust inputs'
}

verify_supply_chain_inputs_unchanged() {
    local actual
    [[ ${SUPPLY_CHAIN_INPUT_DIGEST} =~ ^[0-9a-f]{64}$ ]] \
        || die 'Immutable dependency trust inputs were not captured'
    actual=$(supply_chain_input_digest)
    [[ ${actual} == "${SUPPLY_CHAIN_INPUT_DIGEST}" ]] \
        || die 'A Gradle invocation mutated dependency locks or verification metadata'
}

audit_publication_graph() {
    local repository_url=$1
    local output_graph=${2:-${TASK_GRAPH}}
    local output_log=${3:-${TASK_LOG}}
    ./gradlew "${GRADLE_COMMON_ARGUMENTS[@]}" \
        "-DcasIdpForkRepositoryUrl=${repository_url}" \
        -DskipArtifactSigning \
        publishAllPublicationsToCasIdpForkRepository \
        --dry-run 2>&1 | tee "${output_log}"
    verify_supply_chain_inputs_unchanged

    python3 "${AUDITOR}" audit-task-graph \
        --log "${output_log}" \
        --settings settings.gradle \
        --output "${output_graph}"
}

build_candidate() {
    ./gradlew "${GRADLE_COMMON_ARGUMENTS[@]}" \
        clean \
        build \
        cyclonedxBom \
        validateCasIdpCycloneDxBom \
        --parallel
    verify_supply_chain_inputs_unchanged

    # Run the exact security regression inventory separately. Every --tests
    # option is deliberately adjacent to the Test task it configures; Gradle
    # binds task options to the preceding task rather than to the invocation.
    # Combining filters with `build` would also make the full-build evidence
    # ambiguous, so the unfiltered build remains a separate invocation.
    # The nested JVM class selector intentionally keeps its dollar sign literal.
    # shellcheck disable=SC2016
    ./gradlew "${GRADLE_COMMON_ARGUMENTS[@]}" \
        :api:cas-server-core-api-protocol:testCAS \
        --tests org.apereo.cas.protocol.ProtocolFinalResponsePolicyTests \
        --tests org.apereo.cas.protocol.ProtocolFinalResponseBundleTests \
        :api:cas-server-core-api-ticket:testTickets \
        --tests org.apereo.cas.ticket.registry.TicketIssuanceReadContextTests \
        --tests org.apereo.cas.ticket.registry.TicketIssuanceWriteContextTests \
        :core:cas-server-core-cookie-api:testCookie \
        --tests org.apereo.cas.web.support.mgmr.EncryptedCookieValueManagerTests \
        :core:cas-server-core-cookie:testCookie \
        --tests org.apereo.cas.web.support.CookieRetrievingCookieGeneratorTests \
        :core:cas-server-core-services-authentication:testAuthentication \
        --tests org.apereo.cas.authentication.principal.DefaultResponseTests \
        :core:cas-server-core-tickets-api:testTickets \
        --tests org.apereo.cas.ticket.registry.AbstractTicketRegistryIssuancePolicyTests \
        :core:cas-server-core-web:testUtility \
        --tests org.apereo.cas.web.support.WebUtilsTests \
        :core:cas-server-core-web:testWeb \
        --tests org.apereo.cas.config.CasCoreWebFinalResponsePolicyTests \
        :core:cas-server-core-webflow-api:testWebflowActions \
        --tests org.apereo.cas.web.flow.actions.CasProtocolFinalResponseDeliveryBuilderTests \
        :core:cas-server-core-webflow:testWebflowAuthenticationActions \
        --tests org.apereo.cas.web.flow.actions.BrowserStorageActionTests \
        :core:cas-server-core-webflow:testWebflowServiceActions \
        --tests org.apereo.cas.web.flow.actions.RedirectToServiceActionTests \
        :support:cas-server-support-actions:testWebflowActions \
        --tests org.apereo.cas.web.flow.SendTicketGrantingTicketActionTests \
        --tests org.apereo.cas.web.flow.FetchTicketGrantingTicketActionTests \
        :support:cas-server-support-redis-core:testRedis \
        --tests org.apereo.cas.redis.core.RedisAccountSecurityKeyCodecTests \
        --tests org.apereo.cas.redis.core.RedisAccountSecurityDeletionFenceTests \
        --tests org.apereo.cas.redis.core.RedisAccountSecurityDeletionFenceStoreVerifierTests \
        :support:cas-server-support-redis-ticket-registry:testRedis \
        --tests org.apereo.cas.ticket.registry.key.DigestingRedisLockRegistryTests \
        --tests org.apereo.cas.ticket.registry.RedisTicketRegistryWriteInterceptorTests \
        --tests org.apereo.cas.ticket.registry.sub.DefaultRedisTicketRegistryMessageListenerTests \
        --tests 'org.apereo.cas.ticket.registry.RedisServerTicketRegistryTests$WithoutRedisModulesTests' \
        :support:cas-server-support-redis-ticket-registry:testSimple \
        --tests org.apereo.cas.ticket.registry.RedisTicketRegistryWriteExecutorTests \
        :support:cas-server-support-trusted-mfa-redis:testRedis \
        --tests org.apereo.cas.trusted.authentication.storage.RedisMultifactorAuthenticationTrustStorageTests \
        --tests org.apereo.cas.trusted.authentication.storage.RedisTrustedMfaRecordLocatorTests \
        :support:cas-server-support-webauthn-redis:testRedis \
        --tests org.apereo.cas.webauthn.RedisWebAuthnCredentialRepositoryTests \
        --parallel
    verify_supply_chain_inputs_unchanged
    # The nested JVM class result path intentionally keeps its dollar sign literal.
    # shellcheck disable=SC2016
    python3 "${AUDITOR}" audit-test-results \
        --result 'api/cas-server-core-api-protocol/build/test-results/testCAS/TEST-org.apereo.cas.protocol.ProtocolFinalResponsePolicyTests.xml:6' \
        --result 'api/cas-server-core-api-protocol/build/test-results/testCAS/TEST-org.apereo.cas.protocol.ProtocolFinalResponseBundleTests.xml:10' \
        --result 'api/cas-server-core-api-ticket/build/test-results/testTickets/TEST-org.apereo.cas.ticket.registry.TicketIssuanceReadContextTests.xml:7' \
        --result 'api/cas-server-core-api-ticket/build/test-results/testTickets/TEST-org.apereo.cas.ticket.registry.TicketIssuanceWriteContextTests.xml:7' \
        --result 'core/cas-server-core-cookie-api/build/test-results/testCookie/TEST-org.apereo.cas.web.support.mgmr.EncryptedCookieValueManagerTests.xml:5' \
        --result 'core/cas-server-core-cookie/build/test-results/testCookie/TEST-org.apereo.cas.web.support.CookieRetrievingCookieGeneratorTests.xml:14' \
        --result 'core/cas-server-core-services-authentication/build/test-results/testAuthentication/TEST-org.apereo.cas.authentication.principal.DefaultResponseTests.xml:3' \
        --result 'core/cas-server-core-tickets-api/build/test-results/testTickets/TEST-org.apereo.cas.ticket.registry.AbstractTicketRegistryIssuancePolicyTests.xml:18' \
        --result 'core/cas-server-core-web/build/test-results/testWeb/TEST-org.apereo.cas.config.CasCoreWebFinalResponsePolicyTests.xml:2' \
        --result 'core/cas-server-core-web/build/test-results/testUtility/TEST-org.apereo.cas.web.support.WebUtilsTests.xml:6' \
        --result 'core/cas-server-core-webflow-api/build/test-results/testWebflowActions/TEST-org.apereo.cas.web.flow.actions.CasProtocolFinalResponseDeliveryBuilderTests.xml:20' \
        --result 'core/cas-server-core-webflow/build/test-results/testWebflowAuthenticationActions/TEST-org.apereo.cas.web.flow.actions.BrowserStorageActionTests.xml:10' \
        --result 'core/cas-server-core-webflow/build/test-results/testWebflowServiceActions/TEST-org.apereo.cas.web.flow.actions.RedirectToServiceActionTests.xml:5' \
        --result 'support/cas-server-support-actions/build/test-results/testWebflowActions/TEST-org.apereo.cas.web.flow.SendTicketGrantingTicketActionTests.xml:4' \
        --result 'support/cas-server-support-actions/build/test-results/testWebflowActions/TEST-org.apereo.cas.web.flow.FetchTicketGrantingTicketActionTests.xml:1' \
        --result 'support/cas-server-support-redis-core/build/test-results/testRedis/TEST-org.apereo.cas.redis.core.RedisAccountSecurityKeyCodecTests.xml:3' \
        --result 'support/cas-server-support-redis-core/build/test-results/testRedis/TEST-org.apereo.cas.redis.core.RedisAccountSecurityDeletionFenceTests.xml:2' \
        --result 'support/cas-server-support-redis-core/build/test-results/testRedis/TEST-org.apereo.cas.redis.core.RedisAccountSecurityDeletionFenceStoreVerifierTests.xml:2' \
        --result 'support/cas-server-support-redis-ticket-registry/build/test-results/testRedis/TEST-org.apereo.cas.ticket.registry.key.DigestingRedisLockRegistryTests.xml:1' \
        --result 'support/cas-server-support-redis-ticket-registry/build/test-results/testRedis/TEST-org.apereo.cas.ticket.registry.RedisTicketRegistryWriteInterceptorTests.xml:80' \
        --result 'support/cas-server-support-redis-ticket-registry/build/test-results/testRedis/TEST-org.apereo.cas.ticket.registry.RedisServerTicketRegistryTests$WithoutRedisModulesTests.xml:85' \
        --result 'support/cas-server-support-redis-ticket-registry/build/test-results/testSimple/TEST-org.apereo.cas.ticket.registry.RedisTicketRegistryWriteExecutorTests.xml:4' \
        --result 'support/cas-server-support-redis-ticket-registry/build/test-results/testRedis/TEST-org.apereo.cas.ticket.registry.sub.DefaultRedisTicketRegistryMessageListenerTests.xml:2' \
        --result 'support/cas-server-support-trusted-mfa-redis/build/test-results/testRedis/TEST-org.apereo.cas.trusted.authentication.storage.RedisMultifactorAuthenticationTrustStorageTests.xml:22' \
        --result 'support/cas-server-support-trusted-mfa-redis/build/test-results/testRedis/TEST-org.apereo.cas.trusted.authentication.storage.RedisTrustedMfaRecordLocatorTests.xml:11' \
        --result 'support/cas-server-support-webauthn-redis/build/test-results/testRedis/TEST-org.apereo.cas.webauthn.RedisWebAuthnCredentialRepositoryTests.xml:18'
}

normalize_resolved_sbom() {
    local sbom="${ROOT_DIR}/build/reports/cyclonedx/bom.json"
    python3 - "${sbom}" "${SOURCE_DATE_EPOCH}" <<'PY'
import datetime
import json
import pathlib
import sys

sbom_path = pathlib.Path(sys.argv[1]).absolute()
if sbom_path.is_symlink() or not sbom_path.is_file():
    raise SystemExit(f"Resolved CycloneDX SBOM is not a regular file: {sbom_path}")
epoch = int(sys.argv[2])
if epoch <= 0:
    raise SystemExit(f"Invalid SOURCE_DATE_EPOCH: {epoch}")
document = json.loads(sbom_path.read_text(encoding="utf-8"))
metadata = document.get("metadata")
if not isinstance(metadata, dict):
    raise SystemExit("Resolved CycloneDX SBOM metadata is missing")
metadata["timestamp"] = (
    datetime.datetime.fromtimestamp(epoch, datetime.UTC)
    .isoformat(timespec="seconds")
    .replace("+00:00", "Z")
)
temporary = sbom_path.with_name(f".{sbom_path.name}.normalized")
temporary.write_text(
    json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
temporary.replace(sbom_path)
PY
}

publish_to_staging() {
    local -a signing_arguments=()
    if [[ ${UNSIGNED} == true ]]; then
        signing_arguments+=('-DskipArtifactSigning')
    fi
    ./gradlew "${GRADLE_COMMON_ARGUMENTS[@]}" \
        "-DcasIdpForkRepositoryUrl=$(staging_url)" \
        "${signing_arguments[@]}" \
        publishAllPublicationsToCasIdpForkRepository \
        --parallel
    verify_supply_chain_inputs_unchanged
}

remove_mutable_maven_metadata() {
    python3 "${AUDITOR}" remove-mutable-maven-metadata \
        --repository "${STAGING_REPOSITORY}" \
        --task-graph "${TASK_GRAPH}" \
        --group "${PROJECT_GROUP}" \
        --version "${PROJECT_VERSION}"
}

audit_staging_repository() {
    local resolved_sbom=$1
    local require_signatures=${2:-false}
    # Keep the array non-empty: the Bash 3.2 shipped by macOS treats an
    # expansion of an empty array as an unbound variable under `set -u`.
    local -a command=(
        python3 "${AUDITOR}" audit-repository
        --repository "${STAGING_REPOSITORY}"
        --release-dir "${RELEASE_DIR}"
        --task-graph "${TASK_GRAPH}"
        --group "${PROJECT_GROUP}"
        --version "${PROJECT_VERSION}"
        --fork-commit "${FORK_COMMIT}"
        --upstream-version "${UPSTREAM_VERSION}"
        --upstream-commit "${UPSTREAM_COMMIT}"
        --fork-repository "${FORK_REPOSITORY}"
        --package-repository "${PACKAGE_REPOSITORY}"
        --resolved-sbom "${resolved_sbom}"
    )
    if [[ ${require_signatures} == true ]]; then
        command+=('--require-signatures')
    fi
    "${command[@]}"
}

verify_signature_by_expected_signer() {
    local signature=$1
    local payload=$2
    local status signer_fingerprint primary_fingerprint expected
    status=$(gpg --batch --status-fd=1 --verify "${signature}" "${payload}" 2>/dev/null) \
        || die "PGP signature verification failed for ${payload}"
    signer_fingerprint=$(printf '%s\n' "${status}" \
        | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print toupper($3); exit }')
    primary_fingerprint=$(printf '%s\n' "${status}" \
        | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print toupper($NF); exit }')
    expected=$(trusted_signing_fingerprint)
    [[ -n ${signer_fingerprint} \
        && (${signer_fingerprint} == "${expected}" || ${primary_fingerprint} == "${expected}") ]] \
        || die "File signer ${signer_fingerprint:-<none>} (primary ${primary_fingerprint:-<none>}) is not authorized by ${expected}"
}

sign_file() {
    local payload=$1
    local passphrase_file="${GNUPGHOME}/passphrase"
    local signature="${payload}.asc"
    [[ ! -e ${signature} ]] || die "Refusing to replace existing signature ${signature}"
    gpg --batch --yes --quiet --armor --detach-sign \
        --pinentry-mode loopback \
        --passphrase-file "${passphrase_file}" \
        --local-user "${CASIDP_SIGNING_FINGERPRINT}" \
        --output "${signature}" \
        "${payload}"
    verify_signature_by_expected_signer "${signature}" "${payload}"
}

sign_staged_artifacts() {
    local count=0 file
    [[ -z $(find "${STAGING_REPOSITORY}" -type f -name '*.asc' -print -quit) ]] \
        || die 'Unsigned candidate unexpectedly contains staged PGP signatures'
    while IFS= read -r -d '' file; do
        sign_file "${file}"
        ((count += 1))
    done < <(
        find "${STAGING_REPOSITORY}" -type f \
            \( -name '*.jar' -o -name '*.war' -o -name '*.pom' -o -name '*.module' \) \
            -print0
    )
    ((count > 0)) || die 'Unsigned candidate contains no Maven publication files'
    printf 'Signed and strictly verified %d staged Maven files.\n' "${count}"
}

verify_artifact_signatures() {
    local count=0 signature
    while IFS= read -r -d '' signature; do
        verify_signature_by_expected_signer "${signature}" "${signature%.asc}"
        ((count += 1))
    done < <(find "${STAGING_REPOSITORY}" -type f -name '*.asc' -print0)
    ((count > 0)) || die 'No staged PGP signatures were found'
    printf 'Strictly verified %d staged PGP signatures.\n' "${count}"
}

sign_release_metadata() {
    local file
    for file in \
        "${RELEASE_DIR}/SHA256SUMS" \
        "${RELEASE_DIR}/casidp-release-manifest.json" \
        "${RELEASE_DIR}/casidp.cdx.json" \
        "${TASK_GRAPH}" \
        "${TASK_LOG}"; do
        sign_file "${file}"
    done
}

verify_release_metadata_signatures() {
    local file
    for file in \
        "${RELEASE_DIR}/SHA256SUMS" \
        "${RELEASE_DIR}/casidp-release-manifest.json" \
        "${RELEASE_DIR}/casidp.cdx.json" \
        "${TASK_GRAPH}" \
        "${TASK_LOG}"; do
        verify_signature_by_expected_signer "${file}.asc" "${file}"
    done
}

export_signing_public_key() {
    local expected actual
    expected=$(trusted_signing_fingerprint)
    [[ ! -e ${SIGNING_PUBLIC_KEY} ]] \
        || die "Refusing to replace existing signing public key ${SIGNING_PUBLIC_KEY}"
    gpg --batch --quiet --armor --export "${expected}" > "${SIGNING_PUBLIC_KEY}"
    [[ -s ${SIGNING_PUBLIC_KEY} ]] || die 'Exported signing public key is empty'
    actual=$(inspect_public_key_fingerprint "${SIGNING_PUBLIC_KEY}")
    [[ ${actual} == "${expected}" ]] \
        || die "Exported public-key fingerprint ${actual} does not match ${expected}"
    python3 - "${RELEASE_DIR}/SHA256SUMS" "${SIGNING_PUBLIC_KEY}" <<'PY'
import hashlib
import pathlib
import re
import sys

checksums = pathlib.Path(sys.argv[1]).resolve()
public_key = pathlib.Path(sys.argv[2]).resolve()
entries: dict[str, str] = {}
for line in checksums.read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
    if not match or match.group(2) in entries:
        raise SystemExit(f"Malformed or duplicate SHA256SUMS entry: {line}")
    entries[match.group(2)] = match.group(1)
relative = public_key.name
if relative in entries:
    raise SystemExit(f"SHA256SUMS already contains {relative}")
digest = hashlib.sha256(public_key.read_bytes()).hexdigest()
entries[relative] = digest
checksums.write_text(
    "".join(f"{entries[path]}  {path}\n" for path in sorted(entries)),
    encoding="utf-8",
)
PY
}

require_github_credentials() {
    [[ -n ${PUBLISH_GITHUB_ACTOR} ]] || die 'GITHUB_ACTOR is required for GitHub Packages'
    [[ -n ${PUBLISH_GITHUB_TOKEN} ]] || die 'GITHUB_TOKEN is required for GitHub Packages'
}

verify_prepared_candidate() {
    python3 "${AUDITOR}" verify-candidate \
        --release-dir "${RELEASE_DIR}" \
        --group "${PROJECT_GROUP}" \
        --version "${PROJECT_VERSION}" \
        --fork-commit "${FORK_COMMIT}"
}

require_repository_matches_manifest() {
    python3 - "${RELEASE_DIR}/casidp-release-manifest.json" "${STAGING_REPOSITORY}" <<'PY'
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1]).resolve()
repository = pathlib.Path(sys.argv[2]).resolve()
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
expected = {item["path"] for item in manifest["artifacts"]}
actual = set()
checksum_suffixes = {".md5", ".sha1", ".sha256", ".sha512"}
for path in repository.rglob("*"):
    if path.is_symlink():
        raise SystemExit(f"Staged repository contains a symbolic link: {path}")
    if path.is_file() and path.suffix not in checksum_suffixes:
        actual.add(f"repository/{path.relative_to(repository).as_posix()}")
missing = sorted(expected - actual)
unexpected = sorted(actual - expected)
if missing or unexpected:
    raise SystemExit(
        f"Staged repository differs from its manifest: "
        f"missing={missing[:20]}, unexpected={unexpected[:20]}"
    )
PY
}

require_manifest_signing_state() {
    local expected=$1
    python3 - "${RELEASE_DIR}/casidp-release-manifest.json" "${expected}" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = sys.argv[2] == "true"
actual = manifest.get("publication", {}).get("signed")
if actual is not expected:
    raise SystemExit(
        f"Release manifest signing state is {actual!r}, expected {expected!r}"
    )
artifacts = {item["path"] for item in manifest.get("artifacts", [])}
if expected:
    primary_suffixes = {".jar", ".war", ".pom", ".module"}
    missing = sorted(
        f"{path}.asc"
        for path in artifacts
        if pathlib.PurePosixPath(path).suffix in primary_suffixes
        and f"{path}.asc" not in artifacts
    )
    if missing:
        raise SystemExit(f"Signed manifest omits artifact signatures: {missing[:20]}")
PY
}

sign_existing_candidate() {
    verify_prepared_candidate
    require_repository_matches_manifest
    require_manifest_signing_state false
    SBOM_TEMP=$(mktemp "${TMPDIR:-/tmp}/casidp-sbom.XXXXXX.json")
    cp -- "${RELEASE_DIR}/casidp.cdx.json" "${SBOM_TEMP}"
    sign_staged_artifacts
    audit_staging_repository "${SBOM_TEMP}" true
    rm -f -- "${SBOM_TEMP}"
    SBOM_TEMP=''
    verify_prepared_candidate
    require_repository_matches_manifest
    require_manifest_signing_state true
    verify_artifact_signatures
    export_signing_public_key
    verify_prepared_candidate
    sign_release_metadata
    verify_release_metadata_signatures
}

publish_existing_candidate() {
    require_github_credentials
    verify_prepared_candidate
    require_repository_matches_manifest
    require_manifest_signing_state true
    verify_artifact_signatures
    verify_release_metadata_signatures
    GITHUB_ACTOR="${PUBLISH_GITHUB_ACTOR}" \
    GITHUB_TOKEN="${PUBLISH_GITHUB_TOKEN}" \
    python3 "${AUDITOR}" publish-remote \
        --manifest "${RELEASE_DIR}/casidp-release-manifest.json" \
        --release-dir "${RELEASE_DIR}" \
        --repository-url "${PACKAGE_REPOSITORY}"
}

build_unsigned_candidate_once() {
    require_redis_test_service
    reset_release_directory
    [[ ! -e ${GRADLE_USER_HOME} ]] \
        || die "Candidate Gradle user home is not fresh: ${GRADLE_USER_HOME}"
    audit_publication_graph "$(staging_url)"
    build_candidate
    normalize_resolved_sbom
    publish_to_staging
    remove_mutable_maven_metadata
    audit_staging_repository "${ROOT_DIR}/build/reports/cyclonedx/bom.json" false
    verify_prepared_candidate
    require_repository_matches_manifest
    require_manifest_signing_state false
}

build_reproducible_unsigned_candidate() {
    REPRO_TEMP=$(mktemp -d "${TMPDIR:-/tmp}/casidp-reproducibility.XXXXXX")
    build_unsigned_candidate_once
    mkdir -p -- "${REPRO_TEMP}/repository"
    cp -R -- "${STAGING_REPOSITORY}/." "${REPRO_TEMP}/repository/"
    cp -- "${RELEASE_DIR}/SHA256SUMS" "${REPRO_TEMP}/SHA256SUMS"
    cp -- "${RELEASE_DIR}/casidp-release-manifest.json" \
        "${REPRO_TEMP}/casidp-release-manifest.json"
    cp -- "${RELEASE_DIR}/casidp.cdx.json" "${REPRO_TEMP}/casidp.cdx.json"
    cp -- "${TASK_GRAPH}" "${REPRO_TEMP}/publish-task-graph.json"

    build_unsigned_candidate_once
    diff -qr -- "${REPRO_TEMP}/repository" "${STAGING_REPOSITORY}" \
        || die 'Fresh-home builds produced different staged repository bytes'
    cmp -s -- "${REPRO_TEMP}/casidp.cdx.json" "${RELEASE_DIR}/casidp.cdx.json" \
        || die 'Fresh-home builds produced different CycloneDX SBOM bytes'
    cmp -s -- \
        "${REPRO_TEMP}/casidp-release-manifest.json" \
        "${RELEASE_DIR}/casidp-release-manifest.json" \
        || die 'Fresh-home builds produced different release manifest bytes'
    cmp -s -- "${REPRO_TEMP}/SHA256SUMS" "${RELEASE_DIR}/SHA256SUMS" \
        || die 'Fresh-home builds produced different aggregate checksum bytes'
    cmp -s -- "${REPRO_TEMP}/publish-task-graph.json" "${TASK_GRAPH}" \
        || die 'Fresh-home builds produced different publication task graphs'
    rm -rf -- "${REPRO_TEMP}"
    REPRO_TEMP=''
    printf 'Two fresh Gradle homes produced byte-identical candidate repositories and evidence.\n'
}

export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git show -s --format=%ct "${FORK_COMMIT}")
export TZ=UTC
export LC_ALL=C

if [[ ${MODE} == sign-existing ]]; then
    initialize_gpg
elif [[ ${MODE} == publish ]]; then
    initialize_trusted_public_key
fi
validate_metadata
capture_supply_chain_inputs
verify_release_tag
verify_workflow_boundary

case "${MODE}" in
    ci)
        require_redis_test_service
        reset_release_directory
        audit_publication_graph "$(staging_url)"
        build_candidate
        normalize_resolved_sbom
        printf 'CAS-IDP fork CI source, tests, SBOM, and publication task graph are valid.\n'
        ;;
    verify-only)
        reset_release_directory
        audit_publication_graph "$(staging_url)"
        printf 'CAS-IDP source and complete publication task graph are valid.\n'
        ;;
    dry-run)
        build_reproducible_unsigned_candidate
        printf 'CAS-IDP unsigned candidate is valid; no package was published.\n'
        ;;
    sign-existing)
        [[ -d ${STAGING_REPOSITORY} ]] \
            || die 'Extract the candidate artifact before --sign-existing'
        sign_existing_candidate
        printf 'Existing CAS-IDP candidate bytes are signed and re-audited; no package was published.\n'
        ;;
    publish)
        [[ -f ${RELEASE_DIR}/casidp-release-manifest.json ]] \
            || die 'Run --sign-existing on the downloaded candidate before --publish'
        publish_existing_candidate
        printf 'CAS-IDP release was published and read-back verified.\n'
        ;;
    *) die "Unsupported mode: ${MODE}" ;;
esac
