# CAS-IDP fork release

This fork has an independent, fail-closed release path. Never run
`ci/release.sh` here: that script is the upstream Apereo release process and can
create/delete tags and force-push branches. The upstream release, snapshot, and
documentation publishing workflows are hard-gated to `apereo/cas`; the fork
workflow is hard-gated to `SoooEZ/cas`.

## Immutable release identity

The release driver rejects a build unless all of these values match:

- Maven group: `io.github.soooez.cas`
- version form: `8.0.1-casidp.N`, where `N` is a positive integer
- upstream tag/version: `v8.0.1` / `8.0.1`
- upstream commit: `ca02a58b41ddd65d3b43270d01c854b845d5e1dc`
- fork repository: `https://github.com/SoooEZ/cas`
- fork release tag: the existing annotated, approved-key-signed `v<version>`

The pinned upstream commit must be an ancestor of the fork release commit. A
real release also requires a completely clean checkout whose `HEAD` is exactly
the signed release tag. The tooling never creates, deletes, or pushes a tag.

## Repository setup

Create two protected GitHub environments named `casidp-release-sign` and
`casidp-release-publish`. Require reviewer approval for each one and restrict
both to protected tags matching `v8.0.1-casidp.*`.

Configure only these secrets in `casidp-release-sign`:

- `PGP_PRIVATE_KEY`: armored artifact/tag signing private key
- `PGP_PASSPHRASE`: that key's passphrase
- `CASIDP_SIGNING_FINGERPRINT`: full, uppercase primary-key fingerprint

Keep those three values exclusively at the `casidp-release-sign` environment
scope; do not duplicate them as repository, organization, or publication
environment secrets.

Do not configure any PGP secret in `casidp-release-publish`. Configure only the
environment variable `CASIDP_TRUSTED_SIGNING_FINGERPRINT` there, with the same
reviewed full, uppercase primary-key fingerprint. Keeping the public
fingerprint in a protected environment variable, rather than reusing a signing
secret, lets the publication job verify the archived public key and signatures
without gaining access to the signing environment or its private material.

Protect the release tag pattern against deletion or update. Keep GitHub Actions
package permission disabled by default. The candidate job always runs first,
explicitly receives only `contents: read`, does not enter either protected
release environment, and receives neither PGP material nor a package token. It
produces one tar archive containing exactly the staged Maven repository,
aggregate checksums, release manifest, CycloneDX SBOM, audited publication
graph, and publication-graph log. The job publishes the archive's SHA-256 as a
job output and uploads the archive without rebuilding it.

The protected signing and publication phases are separate jobs, protected
environments, GitHub job tokens, and permission sets. The `sign` job has only
`contents: read`, `id-token: write`, and `attestations: write`; it has no package
permission and the workflow contains no package-token reference anywhere in
that job. It downloads the unsigned candidate from the same run, verifies the
candidate job's SHA-256 output, imports the PGP private key, verifies the release
tag, signs the existing bytes, and records the provenance/SBOM/manifest
attestations. It exports only the corresponding public key, adds that public key
to signed `SHA256SUMS`, and uploads a complete signed-candidate tar whose name
and digest are job outputs bound to the selected tag and `github.sha`.

The later `publish` job depends only on `sign`. It has `contents: read`,
`packages: write`, and only the OIDC/attestation permissions needed for the
publication-completion attestation. It contains no private key, passphrase,
signing command, JDK setup, or Gradle setup/invocation. After verifying the
signed-candidate digest from `needs.sign`, it imports the candidate public key
into a temporary keyring and requires its exact primary fingerprint to match
`CASIDP_TRUSTED_SIGNING_FINGERPRINT`. Before any upload, it re-verifies the tag,
every Maven signature, and the signatures for `SHA256SUMS`, manifest, SBOM,
task graph, and task-graph log. Only its direct-upload step receives
`GITHUB_ACTOR`, the short-lived `GITHUB_TOKEN`, and the trusted public-key
fingerprint. The token is inherited through the environment rather than
exposed in a Python command line. The release driver immediately removes the
actor and token from its exported environment, performs every candidate and
signature check without passing them to child processes, and restores them
only in the direct uploader subprocess after all checks succeed.

Neither protected job sets up or invokes a JDK or Gradle. The signing and
publication jobs use `casidp-release-sign` and `casidp-release-publish`,
respectively, so the publication job never enters an environment containing a
private key or passphrase. GitHub issues separate job tokens, and the workflow
boundary audit enforces the complete step allowlist, each job's exact
permissions, and its exact environment reference. The two protected jobs may
therefore require separate approvals.

Real publications share one non-cancelling, repository-wide concurrency lock,
so two fork versions cannot update GitHub Packages metadata concurrently. The
workflow does not accept a repository URL or package token from workflow input.

The candidate runner downloads the fixed Amazon Corretto
`25.0.4.7.1` Linux x64 archive from its immutable resource URL, verifies the
reviewed SHA-256 before installation, and registers it as JDK runtime version
`25.0.4+7`. A floating major-version JDK selector is forbidden. Every Gradle
invocation uses `--dependency-verification=strict`, fixes the upstream `CI`
build mode, and disables Java toolchain auto-download. This makes local
candidate checks and GitHub runners use the installed JDK instead of silently
selecting the development-only JetBrains toolchain. The formal workflow
supplies the checksum-pinned Corretto runtime above.
`gradle/verification-metadata.xml` is therefore a reviewed release input; the
workflow never generates or updates it.

The documentation processor, Palantir release-SBOM graph, and exact
core-web/Redis security-test graphs have unavoidable WebJars dependencies whose
upstream metadata uses semantic-version ranges. The root aggregate Javadoc/SBOM
graph, the assembled CAS web application, its native-image variant, and the
deployable Jetty and Tomcat WAR variants also consume those ranges. In fork
release mode, exactly the root project, `:core:cas-server-core-web`,
`:docs:cas-server-documentation-processor`,
`:support:cas-server-support-palantir`,
`:support:cas-server-support-redis-core`,
`:support:cas-server-support-redis-ticket-registry`,
`:support:cas-server-support-trusted-mfa-redis`,
`:support:cas-server-support-webauthn-redis`,
`:webapp:cas-server-webapp`, `:webapp:cas-server-webapp-native`,
`:webapp:cas-server-webapp-jetty`, and
`:webapp:cas-server-webapp-tomcat` therefore activate Gradle STRICT dependency
locking; every other fork project continues to use
`failOnNonReproducibleResolution()`. Their reviewed lockfiles are required
release inputs:

- `gradle.lockfile`
- `core/cas-server-core-web/gradle.lockfile`
- `docs/cas-server-documentation-processor/gradle.lockfile`
- `support/cas-server-support-palantir/gradle.lockfile`
- `support/cas-server-support-redis-core/gradle.lockfile`
- `support/cas-server-support-redis-ticket-registry/gradle.lockfile`
- `support/cas-server-support-trusted-mfa-redis/gradle.lockfile`
- `support/cas-server-support-webauthn-redis/gradle.lockfile`
- `webapp/cas-server-webapp/gradle.lockfile`
- `webapp/cas-server-webapp-native/gradle.lockfile`
- `webapp/cas-server-webapp-jetty/gradle.lockfile`
- `webapp/cas-server-webapp-tomcat/gradle.lockfile`

The release driver audits exactly those twelve paths and rejects a missing,
non-regular, or symbolic-link lockfile; non-UTF-8 or non-LF bytes; a missing
final newline; non-canonical Gradle headers or `empty=` footers; duplicate GAVs
or configurations; empty versions; snapshots; and dynamic/range selectors. It
also fails if the formal workflow or release driver contains any full or
selective dependency-lock update or dependency-verification metadata/key
generation flag.

Lock updates belong in a separate dependency review, never in a candidate job.
The `--write-locks` bootstrap selects the same reproducible dependency and
plugin graph as `-DcasIdpForkPublish=true`, while publication repositories,
credentials, and signing remain controlled only by that explicit system
property. Gradle writes an incidental, settings-scoped
`settings-gradle.lockfile`; it is outside the reviewed twelve-graph boundary
and must not be committed. The canonical update helper removes it after each
pass, resolves all twelve graphs together plus the root CycloneDX plugin's
plugin-only `cyclonedxBom` configuration with strict dependency verification,
disables build/configuration caches and Java toolchain auto-download, then
generates the locks a second time and requires byte-identical output. Before
Gradle starts it rejects any pre-existing lock that is not a regular in-tree
file. It also snapshots dependency verification metadata and fails after either
pass if those reviewed bytes changed. Run only:

```bash
./ci/casidp-update-locks.sh
```

The fourth comment line in each generated lockfile is Gradle's project-specific
shorthand. It is retained as the canonical generated-file header for auditing,
but maintainers must use the helper above so all twelve lock states are updated
and compared as one reviewed change, including the plugin-only SBOM
configuration in the root lock. The helper resolves that configuration directly;
it does not generate 426 module BOMs, which remains the formal candidate
build's responsibility. The helper rejects any dependency verification metadata
mutation; add missing checksums separately after verifying the dependency and
repository identity.

The CycloneDX plugin's wall-clock metadata timestamp is normalized to the
pinned source commit epoch before audit so the two SBOM byte streams are
reproducible; all resolved components and dependency edges remain the plugin's
output.

Gradle also writes artifact-root `maven-metadata.xml` indexes whose
`lastUpdated` field is wall-clock based and whose path must be replaced by a
later `casidp.N` version. These mutable indexes are deliberately outside the
immutable candidate. After staging, the auditor validates the complete
publication task graph, requires exactly one such index for every authorized
artifact, rejects every unknown non-version file, and only then removes those
indexes and their generated checksums. Every exact-version POM, Gradle module,
JAR, WAR, and signature remains in the create-only manifest. Consumers must
request the fixed `8.0.1-casidp.N` version; the direct publisher never uploads
mutable Maven version indexes.

## Release procedure

1. Commit and review all fork changes. Run any environment-specific upstream
   integration matrix required by the touched modules before proposing the tag.
   The release gate runs the repository's complete default `build` lifecycle
   and then runs the exact security suites in a separate filtered invocation;
   it does not claim to exercise every optional external-service integration.
2. Create and push the signed annotated tag manually. Its name must exactly be
   `v<gradle.properties version>`.
3. In **CAS-IDP Fork Release**, select the signed tag itself in GitHub's **Use
   workflow from** selector, enter the exact same tag in `release_tag`, and use
   `dry_run: true`. A branch-selected dispatch or a mismatched input is rejected
   before checkout. The secretless candidate job checks out the immutable
   `github.sha`, proves that it is exactly the selected annotated tag and that
   the tag object contains an OpenPGP signature block,
   compiles the release candidate, runs the full default Gradle build, then
   separately runs the pinned issuance-policy, protocol-boundary, Webflow, and
   Redis regression suites, stages every Gradle
   publication in a local Maven repository, and audits it unsigned. It then
   deletes the complete Gradle user home and release staging directory, repeats
   the entire candidate build with a second fresh Gradle home, and fails unless
   the staged repository, CycloneDX SBOM, release manifest, aggregate checksums,
   and audited publication graph are byte-identical. Because the candidate job
   deliberately has no signing key, cryptographic verification of the tag
   signer occurs later inside the protected signing step. This gate must not be
   described as proof that optional upstream integration matrices passed.
4. Download the unsigned candidate tar, verify the SHA-256 printed in the job
   summary/log, and review its task graph, CycloneDX SBOM, release manifest, and
   `SHA256SUMS`. The complete archive is retained for 14 days.
5. Re-run from the same selected workflow tag with the identical `release_tag`
   and `dry_run: false`, then approve the protected signing job. The workflow
   still runs the same secretless candidate job first. The signing job downloads
   that exact unsigned archive and checks its digest, cryptographically verifies
   the release tag with the approved key, signs each already-staged POM, Gradle
   module, JAR, and WAR, regenerates and validates the signed manifest and
   checksums, exports the matching public key, records the release attestations,
   and uploads one digest-bound signed-candidate archive. This job has no package
   permission or publication token and runs no Gradle command.
6. Approve the separate protected publication job if required. It downloads only
   the signed artifact named by `needs.sign`, verifies its exact digest and
   trusted public-key fingerprint, and re-verifies the tag and every release
   signature. The standard-library direct uploader then checks that the version
   is unused, uploads only the exact files named by the signed manifest, and
   downloads and SHA-256-verifies every remote file. It never rebuilds or signs
   the candidate. A successful read-back creates the publication-completion
   predicate, which is attested in the final step. Review both protected jobs'
   evidence and the completion attestation.

GitHub Packages publication is multi-module and is not transactional. If any
remote upload or read-back check fails, the version is permanently burned: do
not retry or overwrite it. Diagnose the cause, increment `casidp.N`, create a
new signed tag, and release that new version. A consumer must treat the custom
`casidp-publication/v1` completion attestation as the gate that proves the full
manifest was successfully read back.

The raw conditional-PUT behavior of GitHub Packages remains an external
production gate: before the first real release, run the direct uploader's live
contract suite against a dedicated, isolated, disposable package repository and
prove absent upload, identical replay, conflict rejection, redirect handling,
and complete read-back. Unit tests and mocked HTTP responses do not establish
that service-level contract, and the live test must never target the production
coordinates.

The audited graph requires exactly one Maven publication per publishable Gradle
project. It includes the BOM, normal JARs, deployable WARs, every POM, and Gradle
`.module` metadata. The audit rejects duplicate Java/WAR publications for one
GAV, missing projects, unsigned files, `org.apereo.cas`/fork mixed dependency
coordinates, sensitive build-host/user provenance, or a binary not bound to the
fork commit.

Each required JUnit XML suite is also bound to an exact reviewed test count.
Missing suites, added or removed tests, skips, failures, and errors all stop the
release. An intentional suite change therefore requires an explicit review and
count update in `ci/casidp-release.sh`. The current exact inventory contains 26
suites and 348 tests. It includes the Redis account-security key codec,
deletion fence and shared-store verifier, WebAuthn and trusted-MFA terminal-fence integration,
the trusted-MFA crash-safe record locator, ticket-registry write
admission/persistence fencing, the complete non-Redis-Modules ticket-registry integration suite,
and the existing protocol,
cookie, issuance-policy, Webflow, and Redis regressions.

Dependency verification failures are never repaired in the release workflow.
Resolve them in a separate review: confirm the dependency and repository
identity, update `gradle/verification-metadata.xml` intentionally, review the
exact added checksums/signing keys, and repeat the candidate gate from a clean
tag. Treat any strict dependency-lock failure the same way: update the
affected lockfile only in the separate review described above. Do not weaken
strict mode, generate locks in CI, or enable automatic toolchain downloads.
The driver rejects full or selective lock updates and dependency-verification
metadata/key generation. It also hashes all twelve lockfiles plus
`gradle/verification-metadata.xml` before the first Gradle invocation and
requires the same combined byte identity after every build, task-graph, and
publication invocation.

## Compatibility boundary

Adopting the Redis ticket-authority codec, rebuilt principal index, and principal
mutation fence requires a full-stop cutover. Stop every old CAS writer, deploy
only the new release, wait for the current schema READY rebuild, and only then
reopen traffic; a mixed-version rollout can write through fences and leave an
incomplete authority index. The transition reader/deleter recognizes both the
new exact-identity digest and the previous mapping. This is sufficient for this
overlay's canonical UUID principal identifiers, but intentionally never merges
case-distinct identities in the generic public fork.

The first deployment of the trusted-MFA Redis `record-index-schema-v2` is a
separate full-stop compatibility boundary. Its global READY state proves that a
current node completed the existing-principal inventory; it does not make an
older writer compatible with the per-principal index or terminal fence. No old
CAS pod, retrying workload, maintenance process, or autoscaled replacement may
write a legacy trusted-device bucket from before the adopter starts through the
READY transition, and old writers must remain stopped afterward. A write during
inventory can land behind the scan cursor and escape the completed inventory.
A rolling, percentage, or mixed-version upgrade against one writable Redis
authority is not supported.

Use this order for the first trusted-MFA schema adoption:

1. **Preflight:** inventory every CAS and administrative process with write
   access to the trusted-MFA Redis authority; disable automatic restart and
   scale-up of the old deployment; verify the new release against a restored
   copy; and prepare a restorable, whole-dataset snapshot. Do not create, copy,
   or edit the schema READY key independently of its records and index state.
2. **Cut over:** close login and administrative write traffic, stop and verify
   the absence of every old writer, and take the final quiesced snapshot. Start
   one current node with ingress still closed. Wait for
   `record-index-schema-v2` inventory READY and investigate any lease timeout,
   capacity, deserialization, or ownership error instead of bypassing it. Then
   start only current-version peers, exercise representative principal reads
   and removals, and reopen traffic. Never restart an old pod after READY.
3. **Roll back:** close traffic and stop every current writer before changing
   binaries. Restore the complete pre-cutover Redis snapshot, or switch an
   isolated blue-green deployment back to its untouched old dataset, and only
   then start old-version nodes. Deleting READY or restoring only marker/index
   keys is not a rollback: a current node may already have migrated legacy
   buckets or accepted current-format writes. Snapshot rollback discards trusted
   decisions created after cutover; if that loss is unacceptable, keep traffic
   closed and roll forward with a corrected current release.

After schema adoption, normal trusted-device save, principal login lookup, and
record-key removal use the per-principal index and do not issue a Redis
database-wide `SCAN`. The one-time schema adoption uses a leased global `SCAN`
to inventory existing principals; a first access may also perform a bounded
principal-pattern scan to migrate that principal. The result cardinality is
bounded, but Redis may still traverse its database cursor to satisfy `SCAN
MATCH`; pre-warm known legacy principals before peak traffic. Database-cursor
scans remain reserved for schema adoption, transitional rebuild, and explicit
administrative inventory, ID lookup, or expiration cleanup, and must not be
placed on the steady login/removal path.
See the [Redis trusted-device storage guide](../docs/cas-server-documentation/mfa/Multifactor-TrustedDevice-Authentication-Storage-Redis.md)
for the operational form of this procedure.

The fork intentionally converts ticket-registry public entry points into final
template methods so admission, persistence completion, and generation-aware
reads cannot be bypassed by a subclass. This is a source and binary compatibility
break for third-party `TicketRegistry` implementations that override those
entry points. Such implementations must be rebuilt against the fork and move
their storage logic to the protected template hooks. The built-in registries are
compiled in this repository, but that does not prove compatibility for external
registry extensions.

The new context-aware interface overloads also fail closed for external
registries that have not opted in: explicit writes are rejected, and an
intent-aware read is rejected instead of silently degrading to an ordinary
read. The standard read context retains the legacy delegation behavior.

The current protocol release gate covers the CAS browser service-ticket redirect
and ticket-granting-ticket cookie/browser-storage admission boundaries. REST,
OAuth/OIDC, SAML, proxy, and any custom response endpoint require their own
final-response integration and tests before an overlay may claim a complete
generation-fenced protocol surface.

## Local checks

The safe default is a non-publishing dry run. During development only, explicit
bypass flags allow task-graph validation of an uncommitted, untagged checkout:

```bash
./ci/casidp-release.sh --verify-only \
  --allow-dirty --skip-tag-verification --unsigned
```

For a full unsigned local candidate (still no remote writes):

```bash
docker run --detach --rm \
  --name casidp-fork-release-redis \
  --publish 127.0.0.1:6379:6379 \
  redis:7.4.7-alpine@sha256:02f2cc4882f8bf87c79a220ac958f58c700bdec0dfb9b9ea61b62fb0e8f1bfcf
./ci/casidp-release.sh --dry-run \
  --allow-dirty --skip-tag-verification --unsigned
docker stop casidp-fork-release-redis
```

The dry-run checks Redis with the RESP `PING` command before each fresh-home
candidate build. This prevents the port-conditioned Redis regression class from
being silently skipped after an otherwise expensive build. The formal GitHub
candidate job supplies the same digest-pinned Redis image as a healthy service.

`--sign-existing` is intentionally not a build command. It accepts only a
previously extracted unsigned candidate, refuses `GITHUB_TOKEN`, signs the
existing staged publication files, rebuilds the manifest/checksum evidence, and
strictly verifies every signature against `CASIDP_SIGNING_FINGERPRINT`.
`--publish` accepts only that signed candidate, refuses all PGP inputs, never
calls Gradle or signs anything, and requires
`CASIDP_TRUSTED_SIGNING_FINGERPRINT`. It imports the archived public key into a
temporary verification-only keyring, re-verifies the tag and every detached
signature, and only then invokes `publish-remote` with the manifest, release
directory, and fixed GitHub Packages URL. The uploader reads `GITHUB_ACTOR` and
`GITHUB_TOKEN` only from its own subprocess environment; verification children
do not inherit either value.

`--allow-dirty`, `--skip-tag-verification`, and `--unsigned` are rejected by
`--sign-existing` and `--publish`.

After release, verify the aggregate checksum subject and its attestations with
GitHub CLI, then compare package files to the hashes embedded in the attested
release manifest:

```bash
gh attestation verify .casidp-release/SHA256SUMS --repo SoooEZ/cas
```
