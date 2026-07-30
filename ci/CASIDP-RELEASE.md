# CAS-IDP fork release

This fork has an independent, fail-closed release path. Never run
`ci/release.sh` here: that script is the upstream Apereo release process and can
create/delete tags and force-push branches. The upstream release, snapshot, and
documentation publishing workflows are hard-gated to `apereo/cas`; the fork
workflow is hard-gated to `SoooEZ/cas`.

## Immutable release identity

The release driver rejects a build unless all of these values match:

- Maven group: `io.github.soooez.cas`
- version form: `8.0.0-casidp.N`, where `N` is a positive integer
- upstream tag/version: `v8.0.0` / `8.0.0`
- upstream commit: `87e190fbef25608b1c4d302c30448f267b345c6e`
- fork repository: `https://github.com/SoooEZ/cas`
- fork release tag: the existing annotated, approved-key-signed `v<version>`

The pinned upstream commit must be an ancestor of the fork release commit. A
real release also requires a completely clean checkout whose `HEAD` is exactly
the signed release tag. The tooling never creates, deletes, or pushes a tag.

## Repository setup

Create a protected GitHub environment named `casidp-release`, require reviewer
approval, and restrict deployment to protected tags matching
`v8.0.0-casidp.*`. Configure these environment secrets:

- `PGP_PRIVATE_KEY`: armored artifact/tag signing private key
- `PGP_PASSPHRASE`: that key's passphrase
- `CASIDP_SIGNING_FINGERPRINT`: full, uppercase primary-key fingerprint

Protect the release tag pattern against deletion or update. Keep GitHub Actions
package permission at write only for the fork release environment. The workflow
uses its short-lived `GITHUB_TOKEN`; it does not accept a repository URL or
package token from workflow input.

## Release procedure

1. Commit and review all fork changes. Run the upstream test matrix appropriate
   to every touched registry/protocol module before proposing the tag; the
   release gate below is deliberately narrower than the complete upstream CAS
   matrix.
2. Create and push the signed annotated tag manually. Its name must exactly be
   `v<gradle.properties version>`.
3. Run **CAS-IDP Fork Release** with that tag and `dry_run: true`. This compiles
   the release candidate, runs the pinned issuance-policy, protocol-boundary,
   Webflow, and Redis regression suites, stages every Gradle publication in a
   local Maven repository, and audits it without publishing packages or
   attestations. It must not be described as proof that the complete upstream
   CAS test matrix passed.
4. Review the task graph, CycloneDX SBOM, release manifest, PGP signatures, and
   `SHA256SUMS` attached to the workflow run.
5. Re-run the same workflow/tag with `dry_run: false` and approve the protected
   environment. The job prepares the same signed candidate, checks that no POM
   for the version exists remotely, records provenance/SBOM/manifest
   attestations, publishes all modules to GitHub Packages, then downloads and
   SHA-256-verifies every published file.

GitHub Packages publication is multi-module and is not transactional. If any
remote upload or read-back check fails, the version is permanently burned: do
not retry or overwrite it. Diagnose the cause, increment `casidp.N`, create a
new signed tag, and release that new version. A consumer must treat the custom
`casidp-publication/v1` completion attestation as the gate that proves the full
manifest was successfully read back.

The audited graph requires exactly one Maven publication per publishable Gradle
project. It includes the BOM, normal JARs, deployable WARs, every POM, and Gradle
`.module` metadata. The audit rejects duplicate Java/WAR publications for one
GAV, missing projects, unsigned files, `org.apereo.cas`/fork mixed dependency
coordinates, sensitive build-host/user provenance, or a binary not bound to the
fork commit.

Each required JUnit XML suite is also bound to an exact reviewed test count.
Missing suites, added or removed tests, skips, failures, and errors all stop the
release. An intentional suite change therefore requires an explicit review and
count update in `ci/casidp-release.sh`.

## Compatibility boundary

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
./ci/casidp-release.sh --dry-run \
  --allow-dirty --skip-tag-verification --unsigned
```

`--allow-dirty`, `--skip-tag-verification`, and `--unsigned` are rejected by
`--prepare` and `--publish`.

After release, verify the aggregate checksum subject and its attestations with
GitHub CLI, then compare package files to the hashes embedded in the attested
release manifest:

```bash
gh attestation verify .casidp-release/SHA256SUMS --repo SoooEZ/cas
```
