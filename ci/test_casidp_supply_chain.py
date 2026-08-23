#!/usr/bin/env python3
"""Unit tests for the CAS-IDP supply-chain release auditor."""

from __future__ import annotations

import argparse
import email.message
import hashlib
import importlib.util
import io
import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from unittest import mock


AUDITOR_PATH = Path(__file__).with_name("casidp-supply-chain.py")
RELEASE_DRIVER_PATH = Path(__file__).with_name("casidp-release.sh")
UPDATE_LOCKS_PATH = Path(__file__).with_name("casidp-update-locks.sh")
AUDITOR_SPEC = importlib.util.spec_from_file_location("casidp_supply_chain", AUDITOR_PATH)
if AUDITOR_SPEC is None or AUDITOR_SPEC.loader is None:
    raise RuntimeError(f"Unable to load supply-chain auditor from {AUDITOR_PATH}")
AUDITOR = importlib.util.module_from_spec(AUDITOR_SPEC)
sys.modules[AUDITOR_SPEC.name] = AUDITOR
AUDITOR_SPEC.loader.exec_module(AUDITOR)


class ReleaseDriverSourceTests(unittest.TestCase):
    """Keep security-sensitive Gradle orchestration from silently regressing."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = RELEASE_DRIVER_PATH.read_text(encoding="utf-8")

    def test_default_build_is_not_combined_with_test_filters(self) -> None:
        build_block = self.source.split("build_candidate() {", 1)[1].split(
            "\nnormalize_resolved_sbom() {", 1
        )[0]
        full_build, exact_tests = build_block.split(
            "# Run the exact security regression inventory separately.", 1
        )

        self.assertIn("\n        build \\\n", full_build)
        self.assertNotIn("--tests", full_build)
        self.assertIn("--tests org.apereo.cas.protocol", exact_tests)
        self.assertNotIn("\n        build \\\n", exact_tests)

    def test_core_web_compatibility_regression_is_in_exact_inventory(self) -> None:
        build_block = self.source.split("build_candidate() {", 1)[1].split(
            "\nnormalize_resolved_sbom() {", 1
        )[0]
        self.assertEqual(
            1,
            build_block.count(":core:cas-server-core-web:testWeb \\\n"),
        )
        self.assertEqual(
            1,
            build_block.count(
                "--tests org.apereo.cas.config."
                "CasCoreWebFinalResponsePolicyTests \\\n"
            ),
        )
        self.assertIn(
            "testWeb/TEST-org.apereo.cas.config."
            "CasCoreWebFinalResponsePolicyTests.xml:2",
            build_block,
        )

    def test_redis_lock_key_privacy_regression_is_in_exact_inventory(self) -> None:
        build_block = self.source.split("build_candidate() {", 1)[1].split(
            "\nnormalize_resolved_sbom() {", 1
        )[0]
        self.assertEqual(
            1,
            build_block.count(
                "--tests org.apereo.cas.ticket.registry.key."
                "DigestingRedisLockRegistryTests \\\n"
            ),
        )
        self.assertIn(
            "testRedis/TEST-org.apereo.cas.ticket.registry.key."
            "DigestingRedisLockRegistryTests.xml:1",
            build_block,
        )

    def test_mutable_maven_metadata_is_removed_before_repository_audit(self) -> None:
        candidate_block = self.source.split(
            "build_unsigned_candidate_once() {", 1
        )[1].split("\n}", 1)[0]
        self.assertIn(
            "publish_to_staging\n    remove_mutable_maven_metadata\n"
            "    audit_staging_repository",
            candidate_block,
        )

    def test_unsigned_repository_audit_is_portable_under_bash_nounset(self) -> None:
        audit_block = self.source.split(
            "audit_staging_repository() {", 1
        )[1].split("\n}", 1)[0]
        self.assertIn("local -a command=(", audit_block)
        self.assertIn("python3 \"${AUDITOR}\" audit-repository", audit_block)
        self.assertIn("command+=('--require-signatures')", audit_block)
        self.assertIn('"${command[@]}"', audit_block)
        self.assertNotIn("signature_argument", audit_block)

    def test_each_candidate_build_requires_the_live_redis_regression_service(
        self,
    ) -> None:
        candidate_block = self.source.split(
            "build_unsigned_candidate_once() {", 1
        )[1].split("\n}", 1)[0]
        self.assertEqual(1, candidate_block.count("require_redis_test_service"))
        self.assertLess(
            candidate_block.index("require_redis_test_service"),
            candidate_block.index("reset_release_directory"),
        )
        redis_preflight = self.source.split(
            "require_redis_test_service() {", 1
        )[1].split("\n}", 1)[0]
        self.assertIn('endpoint = ("127.0.0.1", 6379)', redis_preflight)
        self.assertIn('connection.sendall(b"*1\\r\\n$4\\r\\nPING\\r\\n")', redis_preflight)
        self.assertIn('bytes(response) != b"+PONG\\r\\n"', redis_preflight)

    def test_every_gradle_phase_rechecks_dependency_trust_inputs(self) -> None:
        self.assertEqual(
            5,
            self.source.count("verify_supply_chain_inputs_unchanged"),
        )
        self.assertIn(
            "validate_metadata\ncapture_supply_chain_inputs\nverify_release_tag",
            self.source,
        )
        digest_function = self.source.split(
            "supply_chain_input_digest() {", 1
        )[1].split("\n}", 1)[0]
        digest_arguments = [
            line.strip().removesuffix("\\").strip().split(" <<", 1)[0]
            for line in digest_function.splitlines()
        ]
        for path in (
            "gradle/verification-metadata.xml",
            "gradle.lockfile",
            "core/cas-server-core-web/gradle.lockfile",
            "docs/cas-server-documentation-processor/gradle.lockfile",
            "support/cas-server-support-palantir/gradle.lockfile",
            "support/cas-server-support-redis-ticket-registry/gradle.lockfile",
            "webapp/cas-server-webapp/gradle.lockfile",
            "webapp/cas-server-webapp-native/gradle.lockfile",
            "webapp/cas-server-webapp-jetty/gradle.lockfile",
            "webapp/cas-server-webapp-tomcat/gradle.lockfile",
        ):
            self.assertEqual(
                1,
                digest_arguments.count(path),
            )

    def test_all_gradle_dependency_trust_mutation_flags_are_forbidden(self) -> None:
        for construction in (
            "'%s%s' '--write' '-locks'",
            "'%s%s' '--update' '-locks'",
            "'%s%s' '--write-verification' '-metadata'",
            "'%s%s' '--export' '-keys'",
        ):
            self.assertIn(construction, self.source)

    def test_release_gradle_uses_ci_toolchain_contract(self) -> None:
        common_arguments = self.source.split(
            "readonly GRADLE_COMMON_ARGUMENTS=(", 1
        )[1].split("\n)", 1)[0]
        self.assertEqual(1, common_arguments.count("'-DCI=true'"))
        self.assertIn(
            "'-Porg.gradle.java.installations.auto-download=false'",
            common_arguments,
        )

    def test_root_sbom_configuration_is_a_required_lock_state(self) -> None:
        self.assertIn(
            '":": {"aggregateJavadocClasspath", "cyclonedxBom"}',
            self.source,
        )

    def test_exact_web_security_runtime_is_a_required_lock_state(self) -> None:
        self.assertIn(
            '":core:cas-server-core-web": {"testRuntimeClasspath"}',
            self.source,
        )

    def test_exact_redis_security_runtime_is_a_required_lock_state(self) -> None:
        self.assertIn(
            '":support:cas-server-support-redis-ticket-registry":'
            '{"testRuntimeClasspath"}',
            self.source.replace("\n", "").replace(" ", ""),
        )

    def test_palantir_release_runtime_is_a_required_lock_state(self) -> None:
        self.assertIn(
            '":support:cas-server-support-palantir":{"runtimeClasspath"}',
            self.source.replace("\n", "").replace(" ", ""),
        )


class LockUpdateHelperTests(unittest.TestCase):
    @staticmethod
    def create_fixture(root: Path, gradlew_body: str) -> Path:
        for directory in (
            root / "ci",
            root / "gradle",
            root / "core/cas-server-core-web",
            root / "docs/cas-server-documentation-processor",
            root / "support/cas-server-support-palantir",
            root / "support/cas-server-support-redis-ticket-registry",
            root / "webapp/cas-server-webapp",
            root / "webapp/cas-server-webapp-native",
            root / "webapp/cas-server-webapp-jetty",
            root / "webapp/cas-server-webapp-tomcat",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        helper = root / "ci/casidp-update-locks.sh"
        helper.write_bytes(UPDATE_LOCKS_PATH.read_bytes())
        (root / "gradle/verification-metadata.xml").write_text(
            "<verification-metadata/>\n", encoding="utf-8"
        )
        gradlew = root / "gradlew"
        gradlew.write_text(gradlew_body, encoding="utf-8")
        gradlew.chmod(0o755)
        return helper

    @staticmethod
    def run_helper(root: Path, helper: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(helper)],
            cwd=root,
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )

    def test_stable_generation_resolves_sbom_and_removes_settings_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repository"
            root.mkdir()
            helper = self.create_fixture(
                root,
                """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> gradle-arguments.log
for path in \\
    gradle.lockfile \\
    core/cas-server-core-web/gradle.lockfile \\
    docs/cas-server-documentation-processor/gradle.lockfile \\
    support/cas-server-support-palantir/gradle.lockfile \\
    support/cas-server-support-redis-ticket-registry/gradle.lockfile \\
    webapp/cas-server-webapp/gradle.lockfile \\
    webapp/cas-server-webapp-native/gradle.lockfile \\
    webapp/cas-server-webapp-jetty/gradle.lockfile \\
    webapp/cas-server-webapp-tomcat/gradle.lockfile; do
    printf 'stable-lock\\n' > "$path"
done
printf 'incidental-settings-lock\\n' > settings-gradle.lockfile
""",
            )

            result = self.run_helper(root, helper)

            self.assertEqual(0, result.returncode, result.stderr)
            invocations = (root / "gradle-arguments.log").read_text(
                encoding="utf-8"
            ).splitlines()
            self.assertEqual(4, len(invocations))
            sbom_invocations = [
                line for line in invocations if "cyclonedxBom" in line
            ]
            graph_invocations = [
                line for line in invocations if "cyclonedxBom" not in line
            ]
            self.assertEqual(2, len(sbom_invocations))
            self.assertEqual(2, len(graph_invocations))
            self.assertTrue(
                all(
                    ":support:cas-server-support-palantir:dependencies"
                    in line
                    and ":support:cas-server-support-redis-ticket-registry:dependencies"
                    in line
                    for line in graph_invocations
                )
            )
            self.assertTrue(
                all(
                    "-DcasIdpResolveCycloneDxLock=true" in line
                    and "--configuration cyclonedxBom" in line
                    for line in sbom_invocations
                )
            )
            self.assertFalse((root / "settings-gradle.lockfile").exists())
            self.assertIn(
                "All nine strict dependency locks are byte-stable.", result.stdout
            )

    def test_preflight_rejects_lock_symlink_before_gradle_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            root = temporary_root / "repository"
            root.mkdir()
            helper = self.create_fixture(
                root,
                """#!/usr/bin/env bash
set -euo pipefail
touch gradle-ran
""",
            )
            outside = temporary_root / "outside.lock"
            outside.write_text("outside\n", encoding="utf-8")
            (root / "gradle.lockfile").symlink_to(outside)

            result = self.run_helper(root, helper)

            self.assertNotEqual(0, result.returncode)
            self.assertIn("unsafe pre-existing dependency lock", result.stderr)
            self.assertFalse((root / "gradle-ran").exists())
            self.assertEqual("outside\n", outside.read_text(encoding="utf-8"))

    def test_metadata_mutation_fails_after_first_gradle_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repository"
            root.mkdir()
            helper = self.create_fixture(
                root,
                """#!/usr/bin/env bash
set -euo pipefail
for path in \\
    gradle.lockfile \\
    core/cas-server-core-web/gradle.lockfile \\
    docs/cas-server-documentation-processor/gradle.lockfile \\
    support/cas-server-support-palantir/gradle.lockfile \\
    support/cas-server-support-redis-ticket-registry/gradle.lockfile \\
    webapp/cas-server-webapp/gradle.lockfile \\
    webapp/cas-server-webapp-native/gradle.lockfile \\
    webapp/cas-server-webapp-jetty/gradle.lockfile \\
    webapp/cas-server-webapp-tomcat/gradle.lockfile; do
    printf 'stable-lock\\n' > "$path"
done
printf '<mutated/>\\n' > gradle/verification-metadata.xml
printf 'incidental-settings-lock\\n' > settings-gradle.lockfile
""",
            )

            result = self.run_helper(root, helper)

            self.assertNotEqual(0, result.returncode)
            self.assertIn(
                "Dependency verification metadata changed during lock generation",
                result.stderr,
            )
            self.assertFalse((root / "settings-gradle.lockfile").exists())


class MutableMavenMetadataTests(unittest.TestCase):
    @staticmethod
    @contextmanager
    def fixture() -> Iterator[tuple[Path, Path, Path]]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            repository = root / "repository"
            artifact_root = repository / "io/github/soooez/cas/module"
            version_root = artifact_root / "8.0.0-casidp.2"
            version_root.mkdir(parents=True)
            (version_root / "module-8.0.0-casidp.2.pom").write_text(
                "<project/>\n", encoding="utf-8"
            )
            metadata = artifact_root / "maven-metadata.xml"
            metadata.write_text("<metadata/>\n", encoding="utf-8")
            metadata.with_name("maven-metadata.xml.sha256").write_text(
                "0" * 64 + "\n", encoding="utf-8"
            )
            graph = root / "publish-task-graph.json"
            graph.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "projectCount": 1,
                        "projects": [
                            {
                                "path": ":module",
                                "artifactId": "module",
                                "publication": "MavenJava",
                                "task": (
                                    ":module:publishMavenJavaPublicationTo"
                                    "CasIdpForkRepository"
                                ),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            yield repository, graph, metadata

    @staticmethod
    def arguments(repository: Path, graph: Path) -> argparse.Namespace:
        return argparse.Namespace(
            repository=str(repository),
            task_graph=str(graph),
            group="io.github.soooez.cas",
            version="8.0.0-casidp.2",
        )

    def test_removes_only_artifact_root_metadata_and_checksums(self) -> None:
        with self.fixture() as (repository, graph, metadata):
            pom = (
                metadata.parent
                / "8.0.0-casidp.2/module-8.0.0-casidp.2.pom"
            )

            AUDITOR.remove_mutable_maven_metadata(
                self.arguments(repository, graph)
            )

            self.assertFalse(metadata.exists())
            self.assertFalse(
                metadata.with_name("maven-metadata.xml.sha256").exists()
            )
            self.assertEqual("<project/>\n", pom.read_text(encoding="utf-8"))

    def test_unknown_non_version_file_fails_before_any_removal(self) -> None:
        with self.fixture() as (repository, graph, metadata):
            unknown = metadata.parent / "unexpected.xml"
            unknown.write_text("unexpected\n", encoding="utf-8")

            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.remove_mutable_maven_metadata(
                    self.arguments(repository, graph)
                )

            self.assertTrue(metadata.exists())
            self.assertTrue(unknown.exists())

    def test_missing_authorized_metadata_fails_closed(self) -> None:
        with self.fixture() as (repository, graph, metadata):
            metadata.unlink()

            with self.assertRaises(AUDITOR.AuditError):
                AUDITOR.remove_mutable_maven_metadata(
                    self.arguments(repository, graph)
                )

            self.assertTrue(
                metadata.with_name("maven-metadata.xml.sha256").exists()
            )


def manifest_document(
    artifacts: list[dict[str, Any]],
    repository_url: str,
    *,
    commit: str = "1" * 40,
    project_count: int = 1,
    version: str = "8.0.0-casidp.2",
) -> dict[str, Any]:
    return {
        "artifacts": artifacts,
        "coordinates": {
            "group": AUDITOR.EXPECTED_FORK_GROUP,
            "version": version,
        },
        "publication": {
            "atomic": False,
            "partialFailurePolicy": AUDITOR.EXPECTED_PARTIAL_FAILURE_POLICY,
            "projectCount": project_count,
            "repository": repository_url,
            "signed": True,
        },
        "sbom": {
            "format": "CycloneDX-1.6",
            "path": AUDITOR.SBOM_NAME,
            "sha256": "b" * 64,
        },
        "schemaVersion": 1,
        "source": {
            "forkCommit": commit,
            "forkRepository": AUDITOR.EXPECTED_FORK_REPOSITORY,
            "releaseTag": f"v{version}",
            "upstreamCommit": AUDITOR.EXPECTED_UPSTREAM_COMMIT,
            "upstreamTag": f"v{AUDITOR.EXPECTED_UPSTREAM_VERSION}",
            "upstreamVersion": AUDITOR.EXPECTED_UPSTREAM_VERSION,
        },
        "taskGraph": {
            "path": AUDITOR.TASK_GRAPH_NAME,
            "sha256": "a" * 64,
        },
    }


@contextmanager
def running_server(
    handler: type[BaseHTTPRequestHandler],
) -> Iterator[tuple[LocalThreadingHTTPServer, str]]:
    server = LocalThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield server, f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class SilentRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *args: Any) -> None:
        pass


class LocalThreadingHTTPServer(ThreadingHTTPServer):
    """Avoid a reverse-DNS lookup while binding isolated loopback test servers."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port


class TaskGraphAuditTests(unittest.TestCase):
    def test_cross_project_duplicate_artifact_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            log = root / "tasks.log"
            settings = root / "settings.gradle"
            output = root / "task-graph.json"
            log.write_text(
                "\n".join(
                    (
                        ":first:shared:publishMavenJavaPublicationToCasIdpForkRepository SKIPPED",
                        ":second:shared:publishMavenJavaPublicationToCasIdpForkRepository SKIPPED",
                    )
                ),
                encoding="utf-8",
            )
            settings.write_text(
                'include "first:shared", "second:shared"\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                AUDITOR.AuditError,
                "same GitHub Packages artifactId/GAV",
            ):
                AUDITOR.audit_task_graph(
                    argparse.Namespace(log=log, settings=settings, output=output)
                )

            self.assertFalse(output.exists())

    def test_consumed_task_graph_with_duplicate_artifact_id_is_rejected(self) -> None:
        graph = {
            "schemaVersion": 1,
            "projectCount": 2,
            "projects": [
                {
                    "path": ":first:shared",
                    "artifactId": "shared",
                    "publication": "MavenJava",
                    "task": (
                        ":first:shared:publishMavenJavaPublication"
                        "ToCasIdpForkRepository"
                    ),
                },
                {
                    "path": ":second:shared",
                    "artifactId": "shared",
                    "publication": "MavenWeb",
                    "task": (
                        ":second:shared:publishMavenWebPublication"
                        "ToCasIdpForkRepository"
                    ),
                },
            ],
        }

        with self.assertRaisesRegex(
            AUDITOR.AuditError,
            "multiple projects to the same artifactId/GAV",
        ):
            AUDITOR.validate_task_graph(graph)


class RepositoryAuditTests(unittest.TestCase):
    def test_broken_symlink_in_version_tree_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory) / "repository"
            version_directory = repository / "com" / "example" / "module" / "1.0"
            version_directory.mkdir(parents=True)
            (version_directory / "module-1.0.pom").symlink_to(
                version_directory / "missing-target.pom"
            )

            with self.assertRaisesRegex(AUDITOR.AuditError, "Symbolic links are forbidden"):
                AUDITOR.version_files(repository, "com.example", "1.0")

    def test_duplicate_staged_maven_gav_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            repository = root / "repository"
            version_directory = repository / "com" / "example" / "module" / "1.0"
            version_directory.mkdir(parents=True)
            pom = """\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>module</artifactId>
  <version>1.0</version>
</project>
"""
            (version_directory / "module-1.0.pom").write_text(pom, encoding="utf-8")
            (version_directory / "duplicate.pom").write_text(pom, encoding="utf-8")
            task_graph = root / "task-graph.json"
            task_graph.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "projectCount": 1,
                        "projects": [
                            {
                                "path": ":module",
                                "artifactId": "module",
                                "publication": "MavenJava",
                                "task": (
                                    ":module:publishMavenJavaPublication"
                                    "ToCasIdpForkRepository"
                                ),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                AUDITOR.AuditError,
                "same Maven GAV",
            ):
                AUDITOR.audit_repository(
                    argparse.Namespace(
                        repository=repository,
                        release_dir=root / "release",
                        task_graph=task_graph,
                        group="com.example",
                        version="1.0",
                        fork_commit="fork-commit",
                        upstream_version="8.0.0",
                        upstream_commit="upstream-commit",
                        fork_repository="https://github.com/example/cas",
                        package_repository="https://maven.pkg.github.com/example/cas",
                        resolved_sbom=root / "sbom.json",
                        require_signatures=False,
                    )
                )


class RemoteReadTests(unittest.TestCase):
    def test_manifest_artifact_path_must_be_canonical_and_confined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            manifest = Path(temporary_directory) / "manifest.json"
            for unsafe_path in (
                "repository/../outside.pom",
                "repository//module.pom",
                "repository/./module.pom",
                "repository\\module.pom",
                "/repository/module.pom",
            ):
                manifest.write_text(
                    json.dumps(
                        manifest_document(
                            [
                                {
                                    "path": unsafe_path,
                                    "sha256": "a" * 64,
                                    "size": 1,
                                }
                            ],
                            "https://maven.pkg.github.com/SoooEZ/cas",
                        )
                    ),
                    encoding="utf-8",
                )
                with self.subTest(path=unsafe_path):
                    with self.assertRaisesRegex(
                        AUDITOR.AuditError,
                        "unsafe artifact path",
                    ):
                        AUDITOR.load_manifest_artifacts(manifest)

    def test_manifest_schema_rejects_duplicate_and_unexpected_fields(self) -> None:
        artifact = {
            "path": (
                "repository/io/github/soooez/cas/module/8.0.0-casidp.2/"
                "module-8.0.0-casidp.2.pom"
            ),
            "sha256": "a" * 64,
            "size": 1,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            manifest_path = Path(temporary_directory) / "manifest.json"
            value = manifest_document(
                [artifact],
                "https://maven.pkg.github.com/SoooEZ/cas",
            )
            duplicate_json = json.dumps(value)[:-1] + ',"schemaVersion":1}'
            manifest_path.write_text(duplicate_json, encoding="utf-8")
            with self.assertRaisesRegex(AUDITOR.AuditError, "duplicate object key"):
                AUDITOR.load_manifest_artifacts(manifest_path)

            value["artifacts"][0]["unexpected"] = True
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(AUDITOR.AuditError, "unexpected"):
                AUDITOR.load_manifest_artifacts(manifest_path)

    def test_manifest_filename_must_match_exact_maven_identity(self) -> None:
        unsafe_identity = (
            "repository/io/github/soooez/cas/module/8.0.0-casidp.2/other.pom"
        )
        with self.assertRaisesRegex(AUDITOR.AuditError, "artifact filename"):
            AUDITOR.manifest_artifact_coordinates(
                unsafe_identity,
                AUDITOR.EXPECTED_FORK_GROUP,
                "8.0.0-casidp.2",
            )

    def test_response_is_hashed_in_bounded_chunks_and_exact_size_is_enforced(self) -> None:
        contents = b"a" * (AUDITOR.REMOTE_READ_CHUNK_SIZE + 17)

        class RecordingResponse:
            def __init__(self, body: bytes, include_length: bool = True) -> None:
                self.body = body
                self.offset = 0
                self.read_sizes: list[int] = []
                self.headers = {"Content-Length": str(len(body))} if include_length else {}

            def read(self, size: int) -> bytes:
                self.read_sizes.append(size)
                chunk = self.body[self.offset : self.offset + size]
                self.offset += len(chunk)
                return chunk

        response = RecordingResponse(contents)
        digest, size = AUDITOR.stream_remote_digest(response, len(contents))

        self.assertEqual(hashlib.sha256(contents).hexdigest(), digest)
        self.assertEqual(len(contents), size)
        self.assertGreaterEqual(len(response.read_sizes), 3)
        self.assertEqual(
            {AUDITOR.REMOTE_READ_CHUNK_SIZE},
            set(response.read_sizes),
        )

        truncated = RecordingResponse(contents[:-1], include_length=False)
        with self.assertRaisesRegex(AUDITOR.AuditError, "size disagrees"):
            AUDITOR.stream_remote_digest(truncated, len(contents))

    def test_same_origin_authenticated_redirect_is_allowed(self) -> None:
        body = b"published artifact"
        seen_authorization: list[str | None] = []

        class Handler(SilentRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/artifact")
                    self.end_headers()
                    return
                seen_authorization.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with running_server(Handler) as (_server, base_url):
            digest, size = AUDITOR.request_remote_digest(
                f"{base_url}/redirect",
                "release-actor",
                "release-token",
                1,
                len(body),
            )

        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        self.assertEqual(len(body), size)
        self.assertEqual(
            [AUDITOR.authorization_header("release-actor", "release-token")],
            seen_authorization,
        )

    def test_cross_origin_authenticated_redirect_is_rejected_before_request(self) -> None:
        target_requests: list[str | None] = []

        class TargetHandler(SilentRequestHandler):
            def do_GET(self) -> None:
                target_requests.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        with running_server(TargetHandler) as (_target_server, target_url):

            class RedirectHandler(SilentRequestHandler):
                def do_GET(self) -> None:
                    self.send_response(302)
                    self.send_header("Location", f"{target_url}/capture")
                    self.end_headers()

            with running_server(RedirectHandler) as (_source_server, source_url):
                with self.assertRaisesRegex(
                    AUDITOR.AuditError,
                    "across origins",
                ):
                    AUDITOR.request_remote_digest(
                        f"{source_url}/redirect",
                        "release-actor",
                        "release-token",
                        1,
                        0,
                    )

        self.assertEqual([], target_requests)


class RemoteStateAndRetryTests(unittest.TestCase):
    def test_all_five_remote_publication_states_are_distinct(self) -> None:
        cases = (
            ({"a": "MISSING", "b": "MISSING"}, AUDITOR.RemotePublicationState.ABSENT),
            ({"a": "EXACT", "b": "EXACT"}, AUDITOR.RemotePublicationState.COMPLETE_EXACT),
            ({"a": "EXACT", "b": "MISSING"}, AUDITOR.RemotePublicationState.PARTIAL),
            ({"a": "CONFLICT", "b": "MISSING"}, AUDITOR.RemotePublicationState.CONFLICT),
            (
                {"a": "INDETERMINATE", "b": "MISSING"},
                AUDITOR.RemotePublicationState.INDETERMINATE,
            ),
        )
        for statuses, expected in cases:
            with self.subTest(expected=expected.value):
                state, _details = AUDITOR.publication_state(statuses, {})
                self.assertEqual(expected, state)

    def test_retry_after_and_contextual_404_are_honored(self) -> None:
        body = b"eventually available"
        retry_requests = 0

        class Handler(SilentRequestHandler):
            def do_GET(self) -> None:
                nonlocal retry_requests
                if self.path == "/retry":
                    retry_requests += 1
                    if retry_requests == 1:
                        self.send_response(429)
                        self.send_header("Retry-After", "3")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.send_header("Retry-After", "2")
                self.send_header("Content-Length", "0")
                self.end_headers()

        delays: list[float] = []
        with (
            running_server(Handler) as (_server, base_url),
            mock.patch.object(AUDITOR, "SLEEP", delays.append),
            mock.patch.object(AUDITOR, "JITTER_SOURCE", lambda: 0.0),
        ):
            digest, size = AUDITOR.request_remote_digest(
                f"{base_url}/retry",
                "actor",
                "token",
                2,
                len(body),
            )
            self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
            self.assertEqual(len(body), size)

            with self.assertRaises(AUDITOR.RemoteTransientError):
                AUDITOR.authenticated_request(
                    f"{base_url}/missing",
                    "actor",
                    "token",
                    2,
                    True,
                    lambda response: response.read(),
                    missing_policy=AUDITOR.MissingResponsePolicy.KNOWN_PRESENT,
                )
            immediate = AUDITOR.authenticated_request(
                f"{base_url}/missing",
                "actor",
                "token",
                2,
                True,
                lambda response: response.read(),
                missing_policy=AUDITOR.MissingResponsePolicy.IMMEDIATE,
            )

        self.assertIsNone(immediate)
        self.assertEqual([3.0, 2.0], delays)

    def test_exponential_retry_uses_bounded_jitter(self) -> None:
        delays: list[float] = []
        with (
            mock.patch.object(AUDITOR, "SLEEP", delays.append),
            mock.patch.object(AUDITOR, "JITTER_SOURCE", lambda: 0.5),
        ):
            AUDITOR.wait_before_retry(2)
            AUDITOR.wait_before_retry(20, 99.0)
        self.assertEqual([1.125, 8.125], delays)


class PublicationCandidateVerificationTests(unittest.TestCase):
    commit = "1" * 40
    token = "candidate-token-that-must-not-reach-subprocesses"
    version = "8.0.0-casidp.2"

    def gpg(self, home: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["GNUPGHOME"] = str(home)
        return subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--no-options",
                "--homedir",
                str(home),
                *arguments,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
            timeout=60,
        )

    def create_signed_candidate(self, root: Path) -> tuple[Path, Path, str]:
        release_dir = root / "release"
        signing_home = root / "signing-home"
        release_dir.mkdir()
        signing_home.mkdir()
        os.chmod(signing_home, 0o700)
        self.gpg(
            signing_home,
            "--passphrase",
            "",
            "--quick-generate-key",
            "CAS-IDP test signer <casidp@example.invalid>",
            "rsa2048",
            "sign",
            "1d",
        )
        secret_listing = self.gpg(
            signing_home,
            "--with-colons",
            "--list-secret-keys",
        ).stdout
        fingerprint = next(
            line.split(":")[9].upper()
            for line in secret_listing.splitlines()
            if line.startswith("fpr:")
        )
        public_key = release_dir / AUDITOR.SIGNING_PUBLIC_KEY_NAME
        self.gpg(
            signing_home,
            "--armor",
            "--output",
            str(public_key),
            "--export",
            fingerprint,
        )

        artifact_prefix = (
            "repository/io/github/soooez/cas/module/"
            f"{self.version}/module-{self.version}"
        )
        primary_contents = {
            f"{artifact_prefix}.jar": b"audited jar bytes\n",
            f"{artifact_prefix}.module": b'{"formatVersion":"1.1"}\n',
            f"{artifact_prefix}.pom": b"<project/>\n",
        }
        artifact_paths: list[str] = []
        for relative_path, contents in sorted(primary_contents.items()):
            payload = release_dir / relative_path
            payload.parent.mkdir(parents=True, exist_ok=True)
            payload.write_bytes(contents)
            signature = Path(f"{payload}.asc")
            self.gpg(
                signing_home,
                "--armor",
                "--detach-sign",
                "--local-user",
                fingerprint,
                "--output",
                str(signature),
                str(payload),
            )
            artifact_paths.extend((relative_path, f"{relative_path}.asc"))

        task_graph_path = release_dir / AUDITOR.TASK_GRAPH_NAME
        task_graph_path.write_text(
            json.dumps(
                {
                    "projectCount": 1,
                    "projects": [
                        {
                            "artifactId": "module",
                            "path": ":module",
                            "publication": "MavenJava",
                            "task": (
                                ":module:publishMavenJavaPublication"
                                "ToCasIdpForkRepository"
                            ),
                        }
                    ],
                    "schemaVersion": 1,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        root_reference = f"pkg:maven/{AUDITOR.EXPECTED_FORK_GROUP}/cas-server-fork@{self.version}"
        module_reference = f"pkg:maven/{AUDITOR.EXPECTED_FORK_GROUP}/module@{self.version}"
        sbom_path = release_dir / AUDITOR.SBOM_NAME
        sbom_path.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "components": [
                        {
                            "bom-ref": module_reference,
                            "group": AUDITOR.EXPECTED_FORK_GROUP,
                            "name": "module",
                            "version": self.version,
                        }
                    ],
                    "dependencies": [
                        {"dependsOn": [module_reference], "ref": root_reference},
                        {"dependsOn": [], "ref": module_reference},
                    ],
                    "metadata": {
                        "component": {
                            "bom-ref": root_reference,
                            "group": AUDITOR.EXPECTED_FORK_GROUP,
                            "name": "cas-server-fork",
                            "version": self.version,
                        },
                        "tools": {
                            "components": [
                                {
                                    "name": "cyclonedx-gradle-plugin",
                                    "version": "3.3.0",
                                }
                            ]
                        },
                    },
                    "specVersion": "1.6",
                    "version": 1,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (release_dir / AUDITOR.TASK_LOG_NAME).write_text(
            ":module:publishMavenJavaPublicationToCasIdpForkRepository SKIPPED\n",
            encoding="utf-8",
        )

        artifacts = [
            {
                "path": relative_path,
                "sha256": AUDITOR.sha256_file(release_dir / relative_path),
                "size": (release_dir / relative_path).stat().st_size,
            }
            for relative_path in sorted(artifact_paths)
        ]
        repository_url = "http://127.0.0.1:12345/packages"
        manifest_value = manifest_document(
            artifacts,
            repository_url,
            commit=self.commit,
            version=self.version,
        )
        manifest_value["taskGraph"]["sha256"] = AUDITOR.sha256_file(task_graph_path)
        manifest_value["sbom"]["sha256"] = AUDITOR.sha256_file(sbom_path)
        manifest_path = release_dir / AUDITOR.RELEASE_MANIFEST_NAME
        manifest_path.write_text(
            json.dumps(manifest_value, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        checksum_paths = set(artifact_paths) | {
            AUDITOR.RELEASE_MANIFEST_NAME,
            AUDITOR.SBOM_NAME,
            AUDITOR.TASK_GRAPH_NAME,
            AUDITOR.SIGNING_PUBLIC_KEY_NAME,
        }
        (release_dir / AUDITOR.CHECKSUMS_NAME).write_text(
            "".join(
                f"{AUDITOR.sha256_file(release_dir / path)}  {path}\n"
                for path in sorted(checksum_paths)
            ),
            encoding="ascii",
        )
        for metadata_name in AUDITOR.SIGNED_METADATA_NAMES:
            payload = release_dir / metadata_name
            self.gpg(
                signing_home,
                "--armor",
                "--detach-sign",
                "--local-user",
                fingerprint,
                "--output",
                f"{payload}.asc",
                str(payload),
            )
        return release_dir.resolve(), manifest_path.resolve(), fingerprint

    def identity_environment(self, fingerprint: str) -> dict[str, str]:
        return {
            "CASIDP_SIGNING_FINGERPRINT": "",
            "CASIDP_TRUSTED_SIGNING_FINGERPRINT": fingerprint.lower(),
            "GITHUB_ACTIONS": "false",
            "GITHUB_ACTOR": "release-actor",
            "GITHUB_REF": f"refs/tags/v{self.version}",
            "GITHUB_REF_NAME": f"v{self.version}",
            "GITHUB_REPOSITORY": "SoooEZ/cas",
            "GITHUB_SHA": self.commit,
            "GITHUB_TOKEN": self.token,
            "PGP_PASSPHRASE": "",
            "PGP_PRIVATE_KEY": "",
        }

    def test_release_tag_is_annotated_commit_bound_and_signed_by_trusted_key(self) -> None:
        fingerprint = "A" * 40
        source = {
            "forkCommit": self.commit,
            "releaseTag": f"v{self.version}",
        }
        valid_status = (
            f"[GNUPG:] VALIDSIG {fingerprint} 2026-08-01 1 0 4 0 1 10 00 "
            f"{fingerprint}\n"
        )
        results = [
            subprocess.CompletedProcess([], 0, stdout="tag\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=f"{self.commit}\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=f"{self.commit}\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=valid_status),
        ]
        with mock.patch.object(
            AUDITOR,
            "run_verification_command",
            side_effect=results,
        ) as run:
            AUDITOR.verify_release_tag(source, fingerprint, {})

        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(5, len(commands))
        self.assertIn(f"refs/tags/v{self.version}", commands[0])
        self.assertIn("verify-tag", commands[-1])
        self.assertNotIn(self.token, [argument for command in commands for argument in command])

    def test_full_signed_candidate_is_verified_and_token_is_scrubbed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            release_dir, manifest_path, fingerprint = self.create_signed_candidate(
                Path(temporary_directory)
            )
            manifest, artifacts = AUDITOR.load_manifest_artifacts(manifest_path)
            repository_url = manifest["publication"]["repository"]
            commands: list[list[str]] = []
            original_run = subprocess.run

            untrusted_environment = self.identity_environment("A" * 40)
            with (
                mock.patch.dict(os.environ, untrusted_environment, clear=False),
                mock.patch.object(AUDITOR, "verify_release_tag") as verify_tag,
                mock.patch.object(AUDITOR, "validate_task_graph_against_source"),
                self.assertRaisesRegex(
                    AUDITOR.AuditError,
                    "does not match trusted fingerprint",
                ),
            ):
                AUDITOR.verify_publication_candidate(
                    manifest_path,
                    release_dir,
                    manifest,
                    artifacts,
                )
            verify_tag.assert_not_called()

            def recording_run(command: list[str], **kwargs: Any) -> Any:
                commands.append(command)
                self.assertNotIn(self.token, command)
                self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                return original_run(command, **kwargs)

            with (
                mock.patch.dict(
                    os.environ,
                    self.identity_environment(fingerprint),
                    clear=False,
                ),
                mock.patch.object(AUDITOR, "verify_release_tag") as verify_tag,
                mock.patch.object(AUDITOR, "validate_task_graph_against_source"),
                mock.patch.object(AUDITOR.subprocess, "run", side_effect=recording_run),
            ):
                AUDITOR.validate_publish_manifest(manifest, artifacts, repository_url)
                evidence = AUDITOR.verify_publication_candidate(
                    manifest_path,
                    release_dir,
                    manifest,
                    artifacts,
                )
                verify_tag.assert_called_once()

            self.assertGreaterEqual(len(commands), 10)
            self.assertIn(release_dir / AUDITOR.SBOM_NAME, evidence)
            self.assertIn(release_dir / f"{AUDITOR.SBOM_NAME}.asc", evidence)

            sbom_path = release_dir / AUDITOR.SBOM_NAME
            sbom_path.write_bytes(sbom_path.read_bytes() + b" ")
            with (
                mock.patch.dict(
                    os.environ,
                    self.identity_environment(fingerprint),
                    clear=False,
                ),
                mock.patch.object(AUDITOR, "verify_release_tag") as verify_tag,
                mock.patch.object(AUDITOR, "validate_task_graph_against_source"),
                self.assertRaisesRegex(AUDITOR.AuditError, "signature verification"),
            ):
                AUDITOR.verify_publication_candidate(
                    manifest_path,
                    release_dir,
                    manifest,
                    artifacts,
                )
            verify_tag.assert_not_called()


class ExactBytesPublisherTests(unittest.TestCase):
    actor = "release-actor"
    commit = "1" * 40
    token = "release-token-that-must-never-appear-in-argv"
    version = "8.0.0-casidp.2"

    def setUp(self) -> None:
        sleep_patcher = mock.patch.object(AUDITOR, "SLEEP", lambda _delay: None)
        jitter_patcher = mock.patch.object(AUDITOR, "JITTER_SOURCE", lambda: 0.0)
        candidate_patcher = mock.patch.object(
            AUDITOR,
            "verify_publication_candidate",
            return_value={},
        )
        sleep_patcher.start()
        jitter_patcher.start()
        candidate_patcher.start()
        self.addCleanup(sleep_patcher.stop)
        self.addCleanup(jitter_patcher.stop)
        self.addCleanup(candidate_patcher.stop)

    def create_candidate(
        self,
        root: Path,
        repository_url: str,
        artifact_contents: dict[str, bytes] | None = None,
    ) -> tuple[Path, Path, dict[str, bytes]]:
        release_dir = root / "release"
        contents = artifact_contents or {
            (
                "repository/io/github/soooez/cas/module/"
                f"{self.version}/module-{self.version}.pom"
            ): b"<project/>\n",
            (
                "repository/io/github/soooez/cas/module/"
                f"{self.version}/module-{self.version}.module"
            ): b'{"formatVersion":"1.1"}\n',
        }
        artifacts: list[dict[str, Any]] = []
        for path, body in sorted(contents.items()):
            local_path = release_dir / path
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(body)
            artifacts.append(
                {
                    "path": path,
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "size": len(body),
                }
            )
        manifest = release_dir / "casidp-release-manifest.json"
        manifest.write_text(
            json.dumps(
                manifest_document(
                    artifacts,
                    repository_url,
                    commit=self.commit,
                    version=self.version,
                )
            ),
            encoding="utf-8",
        )
        (release_dir / "SHA256SUMS").write_text(
            "".join(
                f"{artifact['sha256']}  {artifact['path']}\n"
                for artifact in artifacts
            ),
            encoding="utf-8",
        )
        return release_dir, manifest, contents

    def publish_args(
        self,
        release_dir: Path,
        manifest: Path,
        repository_url: str,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            manifest=manifest,
            release_dir=release_dir,
            repository_url=repository_url,
            workers=2,
            attempts=1,
        )

    def remote_paths(
        self,
        contents: dict[str, bytes],
    ) -> dict[str, bytes]:
        return {
            f"/packages/{path.removeprefix('repository/')}": body
            for path, body in contents.items()
        }

    def package_handler(
        self,
        store: dict[str, bytes],
        put_requests: list[dict[str, Any]],
    ) -> type[BaseHTTPRequestHandler]:
        class Handler(SilentRequestHandler):
            def do_GET(self) -> None:
                body = store.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_PUT(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                put_requests.append(
                    {
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                        "if_none_match": self.headers.get("If-None-Match"),
                        "body": body,
                    }
                )
                if self.path in store:
                    self.send_response(412)
                elif self.headers.get("If-None-Match") != "*":
                    self.send_response(428)
                else:
                    store[self.path] = body
                    self.send_response(201)
                self.send_header("Content-Length", "0")
                self.end_headers()

        return Handler

    def credential_environment(self) -> dict[str, str]:
        return {
            "CASIDP_RELEASE_TAG": f"v{self.version}",
            "GITHUB_ACTIONS": "false",
            "GITHUB_ACTOR": self.actor,
            "GITHUB_REF": f"refs/tags/v{self.version}",
            "GITHUB_REF_NAME": f"v{self.version}",
            "GITHUB_REPOSITORY": "SoooEZ/cas",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_RUN_ID": "123456789",
            "GITHUB_SHA": self.commit,
            "GITHUB_TOKEN": self.token,
            "GITHUB_WORKFLOW_REF": (
                "SoooEZ/cas/.github/workflows/casidp-release.yml"
                f"@refs/tags/v{self.version}"
            ),
        }

    def test_absent_publication_uploads_exact_files_with_environment_credentials(self) -> None:
        store: dict[str, bytes] = {}
        put_requests: list[dict[str, Any]] = []
        handler = self.package_handler(store, put_requests)
        with tempfile.TemporaryDirectory() as temporary_directory, running_server(
            handler
        ) as (_server, base_url):
            repository_url = f"{base_url}/packages"
            release_dir, manifest, contents = self.create_candidate(
                Path(temporary_directory),
                repository_url,
            )
            argv = [
                str(AUDITOR_PATH),
                "publish-remote",
                "--manifest",
                str(manifest),
                "--release-dir",
                str(release_dir),
                "--repository-url",
                repository_url,
                "--workers",
                "2",
                "--attempts",
                "1",
            ]
            parsed = AUDITOR.parser().parse_args(argv[1:])
            self.assertFalse(hasattr(parsed, "actor"))
            self.assertFalse(hasattr(parsed, "token"))
            self.assertNotIn(self.token, argv)
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.dict(os.environ, self.credential_environment(), clear=False),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(0, AUDITOR.main())
            predicate = json.loads(
                (release_dir / "casidp-publication.json").read_text(encoding="utf-8")
            )
            manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            checksums_digest = hashlib.sha256(
                (release_dir / "SHA256SUMS").read_bytes()
            ).hexdigest()

        self.assertEqual(self.remote_paths(contents), store)
        self.assertEqual("COMPLETE_EXACT", predicate["publication"]["state"])
        self.assertEqual(str(len(contents)), str(predicate["publication"]["artifactCount"]))
        self.assertEqual("123456789", predicate["workflow"]["runId"])
        self.assertEqual(
            manifest_digest,
            predicate["evidence"]["releaseManifest"]["sha256"],
        )
        self.assertEqual(
            checksums_digest,
            predicate["evidence"]["sha256Sums"]["sha256"],
        )
        self.assertEqual(len(contents), len(put_requests))
        self.assertEqual(
            {"*"},
            {request["if_none_match"] for request in put_requests},
        )
        self.assertEqual(
            {AUDITOR.authorization_header(self.actor, self.token)},
            {request["authorization"] for request in put_requests},
        )
        self.assertEqual(
            store,
            {request["path"]: request["body"] for request in put_requests},
        )

    def test_complete_exact_publication_is_an_idempotent_replay_without_puts(self) -> None:
        put_requests: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store: dict[str, bytes] = {}
            handler = self.package_handler(store, put_requests)
            with running_server(handler) as (_server, base_url):
                repository_url = f"{base_url}/packages"
                release_dir, manifest, contents = self.create_candidate(
                    root,
                    repository_url,
                )
                store.update(self.remote_paths(contents))
                with (
                    mock.patch.dict(os.environ, self.credential_environment(), clear=False),
                    redirect_stdout(io.StringIO()),
                ):
                    AUDITOR.publish_remote(
                        self.publish_args(
                            release_dir,
                            manifest,
                            repository_url,
                        )
                    )
                predicate_exists = (release_dir / "casidp-publication.json").is_file()

        self.assertEqual([], put_requests)
        self.assertTrue(predicate_exists)

    def test_partial_remote_publication_fails_closed_without_uploading_missing_paths(self) -> None:
        put_requests: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store: dict[str, bytes] = {}
            handler = self.package_handler(store, put_requests)
            with running_server(handler) as (_server, base_url):
                repository_url = f"{base_url}/packages"
                release_dir, manifest, contents = self.create_candidate(root, repository_url)
                first_path, first_body = next(iter(self.remote_paths(contents).items()))
                store[first_path] = first_body
                with (
                    mock.patch.dict(os.environ, self.credential_environment(), clear=False),
                    self.assertRaisesRegex(AUDITOR.AuditError, "PARTIAL"),
                ):
                    AUDITOR.publish_remote(
                        self.publish_args(release_dir, manifest, repository_url)
                    )
                predicate_exists = (release_dir / "casidp-publication.json").exists()

        self.assertEqual([], put_requests)
        self.assertFalse(predicate_exists)

    def test_conflicting_remote_publication_fails_closed_without_any_put(self) -> None:
        put_requests: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store: dict[str, bytes] = {}
            handler = self.package_handler(store, put_requests)
            with running_server(handler) as (_server, base_url):
                repository_url = f"{base_url}/packages"
                release_dir, manifest, contents = self.create_candidate(root, repository_url)
                remote = self.remote_paths(contents)
                store.update(remote)
                first_path = next(iter(remote))
                store[first_path] = b"conflicting bytes"
                with (
                    mock.patch.dict(os.environ, self.credential_environment(), clear=False),
                    self.assertRaisesRegex(AUDITOR.AuditError, "CONFLICT"),
                ):
                    AUDITOR.publish_remote(
                        self.publish_args(release_dir, manifest, repository_url)
                    )
                predicate_exists = (release_dir / "casidp-publication.json").exists()

        self.assertEqual([], put_requests)
        self.assertFalse(predicate_exists)

    def test_indeterminate_preflight_fails_closed_without_any_put(self) -> None:
        put_paths: list[str] = []

        class Handler(SilentRequestHandler):
            def do_GET(self) -> None:
                self.send_response(503)
                self.send_header("Retry-After", "0")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_PUT(self) -> None:
                put_paths.append(self.path)
                self.send_response(201)
                self.send_header("Content-Length", "0")
                self.end_headers()

        with tempfile.TemporaryDirectory() as temporary_directory, running_server(
            Handler
        ) as (_server, base_url):
            repository_url = f"{base_url}/packages"
            release_dir, manifest, _contents = self.create_candidate(
                Path(temporary_directory),
                repository_url,
            )
            arguments = self.publish_args(release_dir, manifest, repository_url)
            arguments.attempts = 2
            with (
                mock.patch.dict(os.environ, self.credential_environment(), clear=False),
                self.assertRaisesRegex(AUDITOR.AuditError, "INDETERMINATE"),
            ):
                AUDITOR.publish_remote(arguments)

        self.assertEqual([], put_paths)

    def test_candidate_verification_failure_precedes_credentials_and_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            repository_url = "http://127.0.0.1:12345/packages"
            release_dir, manifest, _contents = self.create_candidate(root, repository_url)
            with (
                mock.patch.dict(os.environ, self.credential_environment(), clear=False),
                mock.patch.object(
                    AUDITOR,
                    "verify_publication_candidate",
                    side_effect=AUDITOR.AuditError("untrusted candidate"),
                ),
                mock.patch.object(AUDITOR, "github_credentials") as credentials,
                mock.patch.object(AUDITOR, "preflight_remote_publication") as preflight,
                self.assertRaisesRegex(AUDITOR.AuditError, "untrusted candidate"),
            ):
                AUDITOR.publish_remote(
                    self.publish_args(release_dir, manifest, repository_url)
                )
            credentials.assert_not_called()
            preflight.assert_not_called()

    def test_successful_put_with_persistent_404_is_indeterminate_and_stops(self) -> None:
        put_paths: list[str] = []

        class Handler(SilentRequestHandler):
            def do_GET(self) -> None:
                self.send_response(404)
                self.send_header("Retry-After", "0")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_PUT(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                put_paths.append(self.path)
                self.send_response(201)
                self.send_header("Content-Length", "0")
                self.end_headers()

        with tempfile.TemporaryDirectory() as temporary_directory, running_server(
            Handler
        ) as (_server, base_url):
            repository_url = f"{base_url}/packages"
            release_dir, manifest, _contents = self.create_candidate(
                Path(temporary_directory),
                repository_url,
            )
            arguments = self.publish_args(release_dir, manifest, repository_url)
            arguments.attempts = 2
            with (
                mock.patch.dict(os.environ, self.credential_environment(), clear=False),
                self.assertRaisesRegex(AUDITOR.AuditError, "state=INDETERMINATE"),
            ):
                AUDITOR.publish_remote(arguments)
            predicate_exists = (release_dir / "casidp-publication.json").exists()

        self.assertEqual(1, len(put_paths))
        self.assertFalse(predicate_exists)

    def test_cross_origin_put_redirect_is_rejected_without_forwarding_credentials(self) -> None:
        target_requests: list[str | None] = []

        class TargetHandler(SilentRequestHandler):
            def do_PUT(self) -> None:
                target_requests.append(self.headers.get("Authorization"))
                self.send_response(201)
                self.send_header("Content-Length", "0")
                self.end_headers()

        with running_server(TargetHandler) as (_target_server, target_url):

            class RedirectHandler(SilentRequestHandler):
                def do_GET(self) -> None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

                def do_PUT(self) -> None:
                    length = int(self.headers.get("Content-Length", "0"))
                    self.rfile.read(length)
                    self.send_response(307)
                    self.send_header("Location", f"{target_url}/capture")
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            with tempfile.TemporaryDirectory() as temporary_directory, running_server(
                RedirectHandler
            ) as (_source_server, source_url):
                repository_url = f"{source_url}/packages"
                release_dir, manifest, _contents = self.create_candidate(
                    Path(temporary_directory),
                    repository_url,
                    {
                        (
                            "repository/io/github/soooez/cas/module/"
                            f"{self.version}/module-{self.version}.pom"
                        ): b"<project/>\n"
                    },
                )
                with (
                    mock.patch.dict(os.environ, self.credential_environment(), clear=False),
                    self.assertRaisesRegex(AUDITOR.AuditError, "across origins"),
                ):
                    AUDITOR.publish_remote(
                        self.publish_args(release_dir, manifest, repository_url)
                    )
                predicate_exists = (release_dir / "casidp-publication.json").exists()

        self.assertEqual([], target_requests)
        self.assertFalse(predicate_exists)

    def test_same_origin_307_replays_the_exact_put_body_and_credentials(self) -> None:
        store: dict[str, bytes] = {}
        put_requests: list[dict[str, Any]] = []

        class RedirectHandler(SilentRequestHandler):
            def storage_path(self) -> str:
                return self.path.replace("/packages/", "/storage/", 1)

            def do_GET(self) -> None:
                if self.path.startswith("/packages/"):
                    self.send_response(302)
                    self.send_header("Location", self.storage_path())
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = store.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_PUT(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                put_requests.append(
                    {
                        "authorization": self.headers.get("Authorization"),
                        "body": body,
                        "if_none_match": self.headers.get("If-None-Match"),
                        "path": self.path,
                    }
                )
                if self.path.startswith("/packages/"):
                    self.send_response(307)
                    self.send_header("Location", self.storage_path())
                elif self.path in store:
                    self.send_response(412)
                else:
                    store[self.path] = body
                    self.send_response(201)
                self.send_header("Content-Length", "0")
                self.end_headers()

        with tempfile.TemporaryDirectory() as temporary_directory, running_server(
            RedirectHandler
        ) as (_server, base_url):
            repository_url = f"{base_url}/packages"
            release_dir, manifest, contents = self.create_candidate(
                Path(temporary_directory),
                repository_url,
                {
                    (
                        "repository/io/github/soooez/cas/module/"
                        f"{self.version}/module-{self.version}.pom"
                    ): b"<project/>\n"
                },
            )
            with (
                mock.patch.dict(os.environ, self.credential_environment(), clear=False),
                redirect_stdout(io.StringIO()),
            ):
                AUDITOR.publish_remote(
                    self.publish_args(release_dir, manifest, repository_url)
                )

        expected_body = next(iter(contents.values()))
        self.assertEqual(2, len(put_requests))
        self.assertEqual({expected_body}, {request["body"] for request in put_requests})
        self.assertEqual({"*"}, {request["if_none_match"] for request in put_requests})
        self.assertEqual(
            {AUDITOR.authorization_header(self.actor, self.token)},
            {request["authorization"] for request in put_requests},
        )


if __name__ == "__main__":
    unittest.main()
