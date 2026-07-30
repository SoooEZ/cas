#!/usr/bin/env bash

# Independent, fail-closed release driver for the CAS-IDP CAS 8 fork.
# It never creates/deletes tags, pushes Git refs, or invokes ci/release.sh.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly EXPECTED_GROUP='io.github.soooez.cas'
readonly EXPECTED_UPSTREAM_VERSION='8.0.0'
readonly EXPECTED_UPSTREAM_COMMIT='87e190fbef25608b1c4d302c30448f267b345c6e'
readonly EXPECTED_FORK_REPOSITORY='https://github.com/SoooEZ/cas'
readonly EXPECTED_GITHUB_REPOSITORY='SoooEZ/cas'
readonly PACKAGE_REPOSITORY='https://maven.pkg.github.com/SoooEZ/cas'

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT_DIR
readonly RELEASE_DIR="${ROOT_DIR}/.casidp-release"
readonly STAGING_REPOSITORY="${RELEASE_DIR}/repository"
readonly TASK_LOG="${RELEASE_DIR}/publish-task-graph.log"
readonly TASK_GRAPH="${RELEASE_DIR}/publish-task-graph.json"
readonly AUDITOR="${ROOT_DIR}/ci/casidp-supply-chain.py"
export GRADLE_USER_HOME="${RELEASE_DIR}/gradle-user-home"

MODE='dry-run'
MODE_EXPLICIT=false
ALLOW_DIRTY=false
SKIP_TAG_VERIFICATION=false
UNSIGNED=false
GNUPG_TEMP=''

usage() {
    printf '%s\n' \
        'Usage: ci/casidp-release.sh [mode] [local-only options]' \
        '' \
        'Modes (exactly one):' \
        '  --dry-run       Build and audit a local Maven candidate; never publish (default).' \
        '  --prepare       Build/sign/audit a candidate and prove the remote version is unused.' \
        '  --publish       Publish an existing --prepare candidate, then read it back and hash it.' \
        '  --verify-only   Validate source metadata and the complete Gradle publication task graph.' \
        '' \
        'Local-only options (rejected by --prepare/--publish):' \
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
        --prepare) set_mode 'prepare' ;;
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

if [[ ${MODE} == prepare || ${MODE} == publish ]]; then
    [[ ${ALLOW_DIRTY} == false ]] || die '--allow-dirty is forbidden for a real release'
    [[ ${SKIP_TAG_VERIFICATION} == false ]] || die '--skip-tag-verification is forbidden for a real release'
    [[ ${UNSIGNED} == false ]] || die '--unsigned is forbidden for a real release'
fi

cleanup() {
    if [[ -n ${GNUPG_TEMP} && -d ${GNUPG_TEMP} ]]; then
        rm -rf -- "${GNUPG_TEMP}"
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

readonly PROJECT_GROUP=$(read_property 'group')
readonly PROJECT_VERSION=$(read_property 'version')
readonly UPSTREAM_VERSION=$(read_property 'casIdpUpstreamVersion')
readonly UPSTREAM_COMMIT=$(read_property 'casIdpUpstreamCommit')
readonly FORK_REPOSITORY=$(read_property 'casIdpForkRepository')
readonly FORK_COMMIT=$(git rev-parse --verify HEAD^{commit})
readonly RELEASE_TAG="v${PROJECT_VERSION}"

normalize_fingerprint() {
    printf '%s' "$1" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]'
}

initialize_gpg() {
    [[ -n ${PGP_PRIVATE_KEY:-} ]] || die 'PGP_PRIVATE_KEY is required for a signed release candidate'
    [[ -n ${PGP_PASSPHRASE:-} ]] || die 'PGP_PASSPHRASE is required for a signed release candidate'
    [[ -n ${CASIDP_SIGNING_FINGERPRINT:-} ]] || die 'CASIDP_SIGNING_FINGERPRINT is required'

    GNUPG_TEMP=$(mktemp -d "${TMPDIR:-/tmp}/casidp-gnupg.XXXXXX")
    export GNUPGHOME=${GNUPG_TEMP}
    chmod 700 "${GNUPGHOME}"
    printf '%s' "${PGP_PRIVATE_KEY}" | gpg --batch --quiet --import

    local expected actual
    expected=$(normalize_fingerprint "${CASIDP_SIGNING_FINGERPRINT}")
    actual=$(gpg --batch --with-colons --list-secret-keys "${expected}" \
        | awk -F: '$1 == "fpr" { print toupper($10); exit }')
    [[ ${actual} == "${expected}" ]] \
        || die "Imported signing key fingerprint ${actual:-<none>} does not match ${expected}"
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
    [[ ${PROJECT_VERSION} =~ ^8\.0\.0-casidp\.[1-9][0-9]*$ ]] \
        || die "Fork version must match 8.0.0-casidp.N, not ${PROJECT_VERSION}"
    [[ ${PROJECT_VERSION} != *-SNAPSHOT ]] || die 'Fork releases cannot be snapshots'

    if [[ -n ${GITHUB_REPOSITORY:-} ]]; then
        [[ ${GITHUB_REPOSITORY} == "${EXPECTED_GITHUB_REPOSITORY}" ]] \
            || die "This workflow is restricted to ${EXPECTED_GITHUB_REPOSITORY}"
    fi
    if [[ -n ${CASIDP_RELEASE_TAG:-} ]]; then
        [[ ${CASIDP_RELEASE_TAG} == "${RELEASE_TAG}" ]] \
            || die "Requested ref ${CASIDP_RELEASE_TAG} is not exact release tag ${RELEASE_TAG}"
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
    if [[ ${SKIP_TAG_VERIFICATION} == true ]]; then
        printf 'WARNING: signed tag verification was explicitly skipped for a local %s.\n' "${MODE}" >&2
        return
    fi

    [[ $(git cat-file -t "refs/tags/${RELEASE_TAG}") == tag ]] \
        || die "${RELEASE_TAG} must be an annotated, signed tag"
    [[ $(git rev-parse --verify "${RELEASE_TAG}^{commit}") == "${FORK_COMMIT}" ]] \
        || die "HEAD is not exactly ${RELEASE_TAG}"

    local status signer_fingerprint primary_fingerprint expected
    status=$(git verify-tag --raw "${RELEASE_TAG}" 2>&1) \
        || die "Git tag signature verification failed for ${RELEASE_TAG}"
    signer_fingerprint=$(printf '%s\n' "${status}" \
        | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print toupper($3); exit }')
    primary_fingerprint=$(printf '%s\n' "${status}" \
        | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print toupper($NF); exit }')
    expected=$(normalize_fingerprint "${CASIDP_SIGNING_FINGERPRINT:-}")
    [[ -n ${signer_fingerprint} \
        && (${signer_fingerprint} == "${expected}" || ${primary_fingerprint} == "${expected}") ]] \
        || die "Tag signer ${signer_fingerprint:-<none>} (primary ${primary_fingerprint:-<none>}) is not authorized by ${expected:-<none>}"
}

verify_workflow_boundary() {
    local workflow='.github/workflows/casidp-release.yml'
    [[ -f ${workflow} ]] || die "Missing ${workflow}"
    if grep -nE '^[[:space:]]*uses:[[:space:]]*[^#[:space:]]+@' "${workflow}" \
        | grep -vE '@[0-9a-f]{40}([[:space:]]|$)'; then
        die 'Every third-party action in the CAS-IDP workflow must be pinned to a full commit SHA'
    fi
    ! grep -Eq '(^|[[:space:]/])ci/release\.sh([[:space:]]|$)' "${workflow}" \
        || die 'CAS-IDP workflow must never call the upstream release script'
    grep -Fq "github.repository == '${EXPECTED_GITHUB_REPOSITORY}'" "${workflow}" \
        || die 'CAS-IDP workflow is missing its exact fork repository guard'
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

readonly GRADLE_COMMON_ARGUMENTS=(
    '--no-daemon'
    '--no-build-cache'
    '--no-configuration-cache'
    '--console=plain'
    '--stacktrace'
    '-Dorg.gradle.unsafe.isolated-projects=false'
    '-DcasIdpForkPublish=true'
    '-DpublishMinimalArtifacts'
)

audit_publication_graph() {
    local repository_url=$1
    local output_graph=${2:-${TASK_GRAPH}}
    local output_log=${3:-${TASK_LOG}}
    ./gradlew "${GRADLE_COMMON_ARGUMENTS[@]}" \
        "-DcasIdpForkRepositoryUrl=${repository_url}" \
        -DskipArtifactSigning \
        publishAllPublicationsToCasIdpForkRepository \
        --dry-run 2>&1 | tee "${output_log}"

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
        :api:cas-server-core-api-protocol:testCAS \
        :api:cas-server-core-api-ticket:testTickets \
        :core:cas-server-core-tickets-api:testTickets \
        :core:cas-server-core-web:testUtility \
        :core:cas-server-core-webflow:testWebflowServiceActions \
        :support:cas-server-support-actions:testWebflowActions \
        :support:cas-server-support-redis-ticket-registry:testRedis \
        --tests org.apereo.cas.protocol.ProtocolFinalResponsePolicyTests \
        --tests org.apereo.cas.protocol.ProtocolFinalResponseCommitPolicyTests \
        --tests org.apereo.cas.ticket.registry.TicketIssuanceReadContextTests \
        --tests org.apereo.cas.ticket.registry.TicketIssuanceWriteContextTests \
        --tests org.apereo.cas.ticket.registry.AbstractTicketRegistryIssuancePolicyTests \
        --tests org.apereo.cas.web.support.WebUtilsTests \
        --tests org.apereo.cas.web.flow.actions.RedirectToServiceActionTests \
        --tests org.apereo.cas.web.flow.SendTicketGrantingTicketActionTests \
        --tests org.apereo.cas.ticket.registry.RedisTicketRegistryWriteInterceptorTests \
        --tests org.apereo.cas.ticket.registry.sub.DefaultRedisTicketRegistryMessageListenerTests \
        --parallel
    python3 "${AUDITOR}" audit-test-results \
        --result 'api/cas-server-core-api-protocol/build/test-results/testCAS/TEST-org.apereo.cas.protocol.ProtocolFinalResponsePolicyTests.xml:4' \
        --result 'api/cas-server-core-api-protocol/build/test-results/testCAS/TEST-org.apereo.cas.protocol.ProtocolFinalResponseCommitPolicyTests.xml:10' \
        --result 'api/cas-server-core-api-ticket/build/test-results/testTickets/TEST-org.apereo.cas.ticket.registry.TicketIssuanceReadContextTests.xml:4' \
        --result 'api/cas-server-core-api-ticket/build/test-results/testTickets/TEST-org.apereo.cas.ticket.registry.TicketIssuanceWriteContextTests.xml:7' \
        --result 'core/cas-server-core-tickets-api/build/test-results/testTickets/TEST-org.apereo.cas.ticket.registry.AbstractTicketRegistryIssuancePolicyTests.xml:16' \
        --result 'core/cas-server-core-web/build/test-results/testUtility/TEST-org.apereo.cas.web.support.WebUtilsTests.xml:6' \
        --result 'core/cas-server-core-webflow/build/test-results/testWebflowServiceActions/TEST-org.apereo.cas.web.flow.actions.RedirectToServiceActionTests.xml:2' \
        --result 'support/cas-server-support-actions/build/test-results/testWebflowActions/TEST-org.apereo.cas.web.flow.SendTicketGrantingTicketActionTests.xml:1' \
        --result 'support/cas-server-support-redis-ticket-registry/build/test-results/testRedis/TEST-org.apereo.cas.ticket.registry.RedisTicketRegistryWriteInterceptorTests.xml:73' \
        --result 'support/cas-server-support-redis-ticket-registry/build/test-results/testRedis/TEST-org.apereo.cas.ticket.registry.sub.DefaultRedisTicketRegistryMessageListenerTests.xml:2'
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
}

audit_staging_repository() {
    local -a signature_argument=()
    if [[ ${UNSIGNED} == false ]]; then
        signature_argument+=('--require-signatures')
    fi
    python3 "${AUDITOR}" audit-repository \
        --repository "${STAGING_REPOSITORY}" \
        --release-dir "${RELEASE_DIR}" \
        --task-graph "${TASK_GRAPH}" \
        --group "${PROJECT_GROUP}" \
        --version "${PROJECT_VERSION}" \
        --fork-commit "${FORK_COMMIT}" \
        --upstream-version "${UPSTREAM_VERSION}" \
        --upstream-commit "${UPSTREAM_COMMIT}" \
        --fork-repository "${FORK_REPOSITORY}" \
        --package-repository "${PACKAGE_REPOSITORY}" \
        --resolved-sbom "${ROOT_DIR}/build/reports/cyclonedx/bom.json" \
        "${signature_argument[@]}"
}

verify_artifact_signatures() {
    [[ ${UNSIGNED} == false ]] || return
    local count=0 signature
    while IFS= read -r -d '' signature; do
        gpg --batch --quiet --verify "${signature}" "${signature%.asc}"
        ((count += 1))
    done < <(find "${STAGING_REPOSITORY}" -type f -name '*.asc' -print0)
    ((count > 0)) || die 'No staged PGP signatures were found'
    printf 'Verified %d staged PGP signatures.\n' "${count}"
}

sign_release_metadata() {
    [[ ${UNSIGNED} == false ]] || return
    local passphrase_file="${GNUPGHOME}/passphrase"
    printf '%s' "${PGP_PASSPHRASE}" > "${passphrase_file}"
    chmod 600 "${passphrase_file}"
    local file
    for file in \
        "${RELEASE_DIR}/SHA256SUMS" \
        "${RELEASE_DIR}/casidp-release-manifest.json" \
        "${RELEASE_DIR}/casidp.cdx.json" \
        "${TASK_GRAPH}"; do
        gpg --batch --yes --quiet --armor --detach-sign \
            --pinentry-mode loopback \
            --passphrase-file "${passphrase_file}" \
            --local-user "${CASIDP_SIGNING_FINGERPRINT}" \
            --output "${file}.asc" \
            "${file}"
        gpg --batch --quiet --verify "${file}.asc" "${file}"
    done
}

require_github_credentials() {
    [[ -n ${GITHUB_ACTOR:-} ]] || die 'GITHUB_ACTOR is required for GitHub Packages'
    [[ -n ${GITHUB_TOKEN:-} ]] || die 'GITHUB_TOKEN is required for GitHub Packages'
}

check_remote_absent() {
    require_github_credentials
    python3 "${AUDITOR}" check-remote-absent \
        --manifest "${RELEASE_DIR}/casidp-release-manifest.json" \
        --repository-url "${PACKAGE_REPOSITORY}" \
        --actor "${GITHUB_ACTOR}" \
        --token "${GITHUB_TOKEN}"
}

verify_prepared_candidate() {
    python3 "${AUDITOR}" verify-candidate \
        --release-dir "${RELEASE_DIR}" \
        --group "${PROJECT_GROUP}" \
        --version "${PROJECT_VERSION}" \
        --fork-commit "${FORK_COMMIT}"
    local file
    if [[ ${UNSIGNED} == false ]]; then
        for file in \
            "${RELEASE_DIR}/SHA256SUMS" \
            "${RELEASE_DIR}/casidp-release-manifest.json" \
            "${RELEASE_DIR}/casidp.cdx.json" \
            "${TASK_GRAPH}"; do
            gpg --batch --quiet --verify "${file}.asc" "${file}"
        done
    fi
}

publish_to_github_packages() {
    require_github_credentials
    ./gradlew "${GRADLE_COMMON_ARGUMENTS[@]}" \
        "-DcasIdpForkRepositoryUrl=${PACKAGE_REPOSITORY}" \
        publishAllPublicationsToCasIdpForkRepository \
        --parallel
}

verify_github_packages() {
    python3 "${AUDITOR}" verify-remote \
        --manifest "${RELEASE_DIR}/casidp-release-manifest.json" \
        --repository-url "${PACKAGE_REPOSITORY}" \
        --actor "${GITHUB_ACTOR}" \
        --token "${GITHUB_TOKEN}"
}

export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git show -s --format=%ct "${FORK_COMMIT}")
export TZ=UTC
export LC_ALL=C

if [[ ${UNSIGNED} == false ]]; then
    initialize_gpg
fi
validate_metadata
verify_release_tag
verify_workflow_boundary

case "${MODE}" in
    verify-only)
        reset_release_directory
        audit_publication_graph "$(staging_url)"
        printf 'CAS-IDP source and complete publication task graph are valid.\n'
        ;;
    dry-run|prepare)
        reset_release_directory
        audit_publication_graph "$(staging_url)"
        build_candidate
        publish_to_staging
        audit_staging_repository
        verify_artifact_signatures
        sign_release_metadata
        verify_prepared_candidate
        if [[ ${MODE} == prepare ]]; then
            check_remote_absent
            printf 'Signed CAS-IDP candidate is prepared; no package has been published yet.\n'
        else
            printf 'CAS-IDP dry-run candidate is valid; no package was published.\n'
        fi
        ;;
    publish)
        [[ -f ${RELEASE_DIR}/casidp-release-manifest.json ]] \
            || die 'Run --prepare in this checkout before --publish'
        verify_prepared_candidate
        verify_artifact_signatures
        audit_publication_graph \
            "${PACKAGE_REPOSITORY}" \
            "${RELEASE_DIR}/publish-task-graph.current.json" \
            "${RELEASE_DIR}/publish-task-graph.current.log"
        cmp --silent "${TASK_GRAPH}" "${RELEASE_DIR}/publish-task-graph.current.json" \
            || die 'Remote publication task graph differs from the audited candidate graph'
        check_remote_absent
        publish_to_github_packages
        verify_github_packages
        python3 -c \
            'import hashlib,json,pathlib,sys; p=pathlib.Path(sys.argv[1]); m=pathlib.Path(sys.argv[2]); value={"schemaVersion":1,"publicationVerified":True,"forkCommit":sys.argv[3],"version":sys.argv[4],"repository":sys.argv[5],"releaseManifestSha256":hashlib.sha256(m.read_bytes()).hexdigest(),"checksumManifestSha256":hashlib.sha256(p.read_bytes()).hexdigest(),"workflowRunId":sys.argv[6]}; pathlib.Path(sys.argv[7]).write_text(json.dumps(value,indent=2,sort_keys=True)+"\\n",encoding="utf-8")' \
            "${RELEASE_DIR}/SHA256SUMS" \
            "${RELEASE_DIR}/casidp-release-manifest.json" \
            "${FORK_COMMIT}" \
            "${PROJECT_VERSION}" \
            "${PACKAGE_REPOSITORY}" \
            "${GITHUB_RUN_ID:-local}" \
            "${RELEASE_DIR}/casidp-publication.json"
        printf 'CAS-IDP release was published and read-back verified.\n'
        ;;
    *) die "Unsupported mode: ${MODE}" ;;
esac
