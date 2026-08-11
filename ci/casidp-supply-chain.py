#!/usr/bin/env python3
"""Fail-closed supply-chain checks for the CAS-IDP CAS 8 fork.

The script intentionally uses only the Python standard library so the release
workflow does not need to download and execute another package manager's code.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime
import enum
import email.utils
import hashlib
import http.client
import json
import math
import os
import random
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar


MAVEN_NAMESPACE = "http://maven.apache.org/POM/4.0.0"
OFFICIAL_CAS_GROUP = "org.apereo.cas"
EXCLUDED_PROJECT_NAMES = {
    "api",
    "core",
    "docs",
    "support",
    "webapp",
    "cas-server-documentation",
    "cas-server-documentation-processor",
    "cas-server-support-shell",
}
PUBLICATION_TASK = re.compile(
    r"^(?:> Task )?(:[^\s]+):publish(MavenJava|MavenWeb)PublicationToCasIdpForkRepository(?:\s|$)",
    re.MULTILINE,
)
PRIMARY_SUFFIXES = {".jar", ".war", ".pom", ".module"}
CHECKSUM_SUFFIXES = {".md5", ".sha1", ".sha256", ".sha512"}
REQUIRED_ARTIFACTS = {
    "cas-server-support-bom",
    "cas-server-core-api-ticket",
    "cas-server-support-redis-ticket-registry",
    "cas-server-webapp-tomcat",
}
REMOTE_READ_CHUNK_SIZE = 1024 * 1024
RETRYABLE_HTTP_STATUS_CODES = {404, 408, 429, 500, 502, 503, 504}
RETRYABLE_UPLOAD_STATUS_CODES = {408, 429, 500, 502, 503, 504}
MAX_REMOTE_ATTEMPTS = 10
MAX_REMOTE_WORKERS = 32
MAX_RETRY_AFTER_SECONDS = 8.0
PREFLIGHT_DELAY_SECONDS = 0.25
RETRY_JITTER_SECONDS = 0.25
EXPECTED_FORK_GROUP = "io.github.soooez.cas"
EXPECTED_FORK_REPOSITORY = "https://github.com/SoooEZ/cas"
EXPECTED_PACKAGE_REPOSITORY = "https://maven.pkg.github.com/SoooEZ/cas"
EXPECTED_UPSTREAM_COMMIT = "87e190fbef25608b1c4d302c30448f267b345c6e"
EXPECTED_UPSTREAM_VERSION = "8.0.0"
EXPECTED_PARTIAL_FAILURE_POLICY = (
    "Burn the version; never overwrite it; release the next casidp.N version."
)
RELEASE_MANIFEST_NAME = "casidp-release-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
SBOM_NAME = "casidp.cdx.json"
TASK_GRAPH_NAME = "publish-task-graph.json"
TASK_LOG_NAME = "publish-task-graph.log"
SIGNING_PUBLIC_KEY_NAME = "casidp-signing-public-key.asc"
SIGNED_METADATA_NAMES = (
    CHECKSUMS_NAME,
    RELEASE_MANIFEST_NAME,
    SBOM_NAME,
    TASK_GRAPH_NAME,
    TASK_LOG_NAME,
)
SLEEP: Callable[[float], None] = time.sleep
JITTER_SOURCE: Callable[[], float] = random.random
_RESPONSE_VALUE = TypeVar("_RESPONSE_VALUE")


class AuditError(RuntimeError):
    """A release invariant was violated."""


class RemoteContentConflict(AuditError):
    """A remote path exists but its representation is not the manifest artifact."""


class RemoteTransientError(AuditError):
    """A bounded remote request exhausted only retryable outcomes."""


class KnownPresentArtifactError(AuditError):
    """A conditional PUT proved a path exists but its exact bytes are unknown."""

    def __init__(self, path: str, state: str, detail: str | None) -> None:
        self.path = path
        self.state = state
        self.detail = detail
        super().__init__(f"{path} is known-present but {state}: {detail}")


class MissingResponsePolicy(enum.Enum):
    """Context-sensitive meaning of an authenticated 404 response."""

    IMMEDIATE = "IMMEDIATE"
    RETRY_MISSING = "RETRY_MISSING"
    KNOWN_PRESENT = "KNOWN_PRESENT"


class RemotePublicationState(enum.Enum):
    """Fail-closed aggregate state for every path in a release manifest."""

    ABSENT = "ABSENT"
    COMPLETE_EXACT = "COMPLETE_EXACT"
    PARTIAL = "PARTIAL"
    CONFLICT = "CONFLICT"
    INDETERMINATE = "INDETERMINATE"


def fail(message: str) -> None:
    raise AuditError(message)


def require_exact_keys(value: dict[str, Any], expected: set[str], description: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(
            f"{description} has an invalid schema: "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
        )


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON document contains a duplicate object key: {key}")
        result[key] = value
    return result


def load_json_strict(path: Path, description: str) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=lambda value: fail(
                f"{description} contains a non-finite JSON number: {value}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Invalid {description} {path}: {error}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def stable_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            dir=path.parent,
            encoding="utf-8",
            prefix=f".{path.name}.",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(
                json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def expected_project_paths(settings_file: Path) -> set[str]:
    contents = settings_file.read_text(encoding="utf-8")
    paths: set[str] = set()
    for match in re.finditer(r"(?m)^\s*include\s+(.+?)\s*$", contents):
        for project_match in re.finditer(r"[\"']([^\"']+)[\"']", match.group(1)):
            project_path = project_match.group(1)
            if project_path.rsplit(":", 1)[-1] not in EXCLUDED_PROJECT_NAMES:
                paths.add(f":{project_path}")
    if not paths:
        fail(f"No included Gradle projects found in {settings_file}")
    return paths


def audit_task_graph(args: argparse.Namespace) -> None:
    log_path = Path(args.log).resolve()
    settings_path = Path(args.settings).resolve()
    output_path = Path(args.output).resolve()
    log = log_path.read_text(encoding="utf-8", errors="replace")

    publications: dict[str, set[str]] = defaultdict(set)
    for match in PUBLICATION_TASK.finditer(log):
        project_path, publication = match.groups()
        publications[project_path].add(publication)

    if not publications:
        fail("Gradle dry-run exposed no CAS-IDP GitHub Packages publication tasks")

    duplicates = {
        project_path: sorted(kinds)
        for project_path, kinds in publications.items()
        if len(kinds) != 1
    }
    if duplicates:
        fail(
            "A project has more than one publication for the same GitHub Packages GAV; "
            f"publishing would overwrite artifacts: {duplicates}"
        )

    projects_by_artifact: dict[str, list[str]] = defaultdict(list)
    for project_path in publications:
        projects_by_artifact[project_path.rsplit(":", 1)[-1]].append(project_path)
    duplicate_artifacts = {
        artifact: sorted(paths)
        for artifact, paths in projects_by_artifact.items()
        if len(paths) > 1
    }
    if duplicate_artifacts:
        fail(
            "Multiple Gradle projects resolve to the same GitHub Packages artifactId/GAV; "
            f"publishing would overwrite artifacts: {duplicate_artifacts}"
        )

    expected = expected_project_paths(settings_path)
    actual = set(publications)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        fail(
            "Fork publication graph does not exactly cover publishable Gradle projects; "
            f"missing={missing}, unexpected={unexpected}"
        )

    required_paths = {
        ":support:cas-server-support-bom",
        ":api:cas-server-core-api-ticket",
        ":support:cas-server-support-redis-ticket-registry",
        ":webapp:cas-server-webapp-tomcat",
    }
    absent_required = sorted(required_paths - actual)
    if absent_required:
        fail(f"Required release publications are absent: {absent_required}")

    graph = {
        "schemaVersion": 1,
        "projectCount": len(actual),
        "projects": [
            {
                "path": project_path,
                "artifactId": project_path.rsplit(":", 1)[-1],
                "publication": next(iter(publications[project_path])),
                "task": (
                    f"{project_path}:publish"
                    f"{next(iter(publications[project_path]))}PublicationToCasIdpForkRepository"
                ),
            }
            for project_path in sorted(actual)
        ],
    }
    stable_json(output_path, graph)
    print(f"Audited {len(actual)} fork publication projects")


def xml_text(element: ET.Element | None, name: str) -> str | None:
    if element is None:
        return None
    child = element.find(f"{{{MAVEN_NAMESPACE}}}{name}")
    if child is None or child.text is None:
        return None
    return child.text.strip()


def resolve_property(value: str | None, properties: dict[str, str]) -> str | None:
    if value is None:
        return None
    resolved = value
    for _ in range(10):
        updated = re.sub(
            r"\$\{([^}]+)}",
            lambda match: properties.get(match.group(1), match.group(0)),
            resolved,
        )
        if updated == resolved:
            break
        resolved = updated
    return resolved


def parse_pom(path: Path) -> dict[str, Any]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as error:
        fail(f"Invalid Maven POM {path}: {error}")

    parent = root.find(f"{{{MAVEN_NAMESPACE}}}parent")
    group = xml_text(root, "groupId") or xml_text(parent, "groupId")
    artifact = xml_text(root, "artifactId")
    version = xml_text(root, "version") or xml_text(parent, "version")
    packaging = xml_text(root, "packaging") or "jar"

    properties: dict[str, str] = {
        "project.groupId": group or "",
        "pom.groupId": group or "",
        "project.artifactId": artifact or "",
        "pom.artifactId": artifact or "",
        "project.version": version or "",
        "pom.version": version or "",
    }
    properties_element = root.find(f"{{{MAVEN_NAMESPACE}}}properties")
    if properties_element is not None:
        for child in properties_element:
            if child.text:
                properties[child.tag.rsplit("}", 1)[-1]] = child.text.strip()

    dependencies: set[tuple[str, str, str]] = set()
    for dependency in root.findall(f".//{{{MAVEN_NAMESPACE}}}dependency"):
        dep_group = resolve_property(xml_text(dependency, "groupId"), properties)
        dep_artifact = resolve_property(xml_text(dependency, "artifactId"), properties)
        dep_version = resolve_property(xml_text(dependency, "version"), properties)
        if dep_group and dep_artifact:
            dependencies.add((dep_group, dep_artifact, dep_version or ""))

    repositories: list[tuple[str, bool]] = []
    for repository in root.findall(
        f"./{{{MAVEN_NAMESPACE}}}repositories/{{{MAVEN_NAMESPACE}}}repository"
    ):
        url = xml_text(repository, "url") or ""
        snapshots = repository.find(f"{{{MAVEN_NAMESPACE}}}snapshots")
        snapshots_enabled = (xml_text(snapshots, "enabled") or "false").lower() == "true"
        repositories.append((url, snapshots_enabled))

    return {
        "group": group,
        "artifact": artifact,
        "version": version,
        "packaging": packaging,
        "dependencies": sorted(dependencies),
        "repositories": sorted(repositories),
    }


def version_files(repository: Path, group: str, version: str) -> list[Path]:
    group_root = repository.joinpath(*group.split("."))
    if not group_root.is_dir():
        fail(f"Staged repository has no group path for {group}")

    files: list[Path] = []
    for path in sorted(repository.rglob("*")):
        if path.is_symlink():
            fail(
                "Symbolic links are forbidden in the staged repository; "
                f"found {path.relative_to(repository)}"
            )
        if not path.is_file():
            continue
        try:
            relative_group_path = path.relative_to(group_root)
        except ValueError:
            fail(f"Staged repository contains a foreign group/path: {path.relative_to(repository)}")
        if version in relative_group_path.parts:
            files.append(path)
    if not files:
        fail(f"Staged repository contains no files for version {version}")
    return files


def find_sensitive_git_properties(
    path: Path,
    fork_commit: str,
    group: str,
    version: str,
    fork_repository: str,
    upstream_version: str,
    upstream_commit: str,
) -> int:
    matches = 0
    if path.suffix not in {".jar", ".war"}:
        return matches
    try:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not name.endswith("git.properties"):
                    continue
                matches += 1
                contents = archive.read(name).decode("utf-8", errors="replace")
                properties: dict[str, str] = {}
                for line in contents.splitlines():
                    if "=" in line and not line.lstrip().startswith("#"):
                        key, value = line.split("=", 1)
                        properties[key.strip()] = value.strip()
                sensitive = sorted(
                    key
                    for key in properties
                    if key == "git.build.host" or key.startswith("git.build.user.")
                )
                if sensitive:
                    fail(f"{path} leaks non-reproducible build identity fields: {sensitive}")
                if properties.get("git.commit.id") != fork_commit:
                    fail(f"{path}!/{name} is not bound to fork commit {fork_commit}")
                if properties.get("project.group") != group:
                    fail(f"{path}!/{name} has the wrong project.group")
                if properties.get("project.version") != version:
                    fail(f"{path}!/{name} has the wrong project.version")
                expected_provenance = {
                    "cas-idp.fork.repository": fork_repository,
                    "cas-idp.upstream.version": upstream_version,
                    "cas-idp.upstream.commit": upstream_commit,
                }
                for key, expected in expected_provenance.items():
                    if properties.get(key) != expected:
                        fail(f"{path}!/{name} has wrong or missing {key}")
    except zipfile.BadZipFile as error:
        fail(f"Invalid archive {path}: {error}")
    return matches


def module_has_official_group(value: Any) -> bool:
    if isinstance(value, dict):
        if value.get("group") == OFFICIAL_CAS_GROUP:
            return True
        return any(module_has_official_group(child) for child in value.values())
    if isinstance(value, list):
        return any(module_has_official_group(child) for child in value)
    return False


def module_has_snapshot_version(value: Any) -> bool:
    if isinstance(value, dict):
        version = value.get("version")
        if isinstance(version, str) and version.upper().endswith("-SNAPSHOT"):
            return True
        return any(module_has_snapshot_version(child) for child in value.values())
    if isinstance(value, list):
        return any(module_has_snapshot_version(child) for child in value)
    return False


def validate_resolved_sbom(
    sbom: Any,
    group: str,
    version: str,
    expected_artifacts: set[str],
) -> None:
    """Validate the identity and graph of the official CycloneDX plugin output."""
    if not isinstance(sbom, dict):
        fail("Resolved SBOM must be a JSON object")
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6":
        fail("Resolved SBOM must be CycloneDX JSON using schema version 1.6")
    if type(sbom.get("version")) is not int or sbom["version"] < 1:
        fail("Resolved SBOM has an invalid document version")

    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict):
        fail("Resolved SBOM metadata is missing")
    root_component = metadata.get("component")
    if not isinstance(root_component, dict):
        fail("Resolved SBOM root component is missing")
    expected_root = {"group": group, "name": "cas-server-fork", "version": version}
    actual_root = {key: root_component.get(key) for key in expected_root}
    if actual_root != expected_root:
        fail(f"Resolved SBOM has wrong root component: {actual_root}")

    tools = metadata.get("tools", {})
    tool_components = tools.get("components", []) if isinstance(tools, dict) else []
    if not any(
        isinstance(tool, dict)
        and tool.get("name") == "cyclonedx-gradle-plugin"
        and tool.get("version") == "3.3.0"
        for tool in tool_components
    ):
        fail("Resolved SBOM was not produced by the pinned CycloneDX Gradle plugin 3.3.0")

    components = sbom.get("components")
    dependencies = sbom.get("dependencies")
    if not isinstance(components, list) or not components:
        fail("Resolved SBOM contains no resolved components")
    if not isinstance(dependencies, list) or not dependencies:
        fail("Resolved SBOM contains no dependency graph")
    if module_has_official_group(sbom):
        fail("Official CAS coordinates leaked into the resolved fork SBOM")
    if module_has_snapshot_version(sbom):
        fail("Snapshot coordinates leaked into the resolved fork SBOM")

    fork_components = {
        component.get("name")
        for component in components
        if isinstance(component, dict) and component.get("group") == group
    }
    escaped_modules = sorted(
        component.get("name")
        for component in components
        if isinstance(component, dict)
        and str(component.get("name", "")).startswith("cas-server-")
        and component.get("group") != group
    )
    if escaped_modules:
        fail(f"CAS modules escaped the fork group in the resolved SBOM: {escaped_modules[:20]}")
    missing_modules = sorted(expected_artifacts - fork_components)
    if missing_modules:
        fail(f"Resolved SBOM omits fork modules: {missing_modules[:20]}")

    references = {
        component.get("bom-ref")
        for component in [root_component, *components]
        if isinstance(component, dict) and component.get("bom-ref")
    }
    dangling: set[str] = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict) or not isinstance(dependency.get("ref"), str):
            fail("Resolved SBOM contains a malformed dependency entry")
        if dependency["ref"] not in references:
            dangling.add(dependency["ref"])
        depends_on = dependency.get("dependsOn", [])
        if not isinstance(depends_on, list) or not all(isinstance(item, str) for item in depends_on):
            fail("Resolved SBOM contains a malformed dependency edge")
        dangling.update(item for item in depends_on if item not in references)
    if dangling:
        fail(f"Resolved SBOM contains dangling dependency references: {sorted(dangling)[:20]}")


def audit_resolved_sbom(
    source: Path,
    destination: Path,
    group: str,
    version: str,
    expected_artifacts: set[str],
) -> None:
    """Audit and preserve the official CycloneDX Gradle plugin output."""
    sbom = load_json_strict(source, "resolved CycloneDX JSON")
    validate_resolved_sbom(sbom, group, version, expected_artifacts)

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def validate_task_graph(graph: Any) -> list[dict[str, Any]]:
    if not isinstance(graph, dict):
        fail("Publication task graph has an invalid schema")
    require_exact_keys(
        graph,
        {"schemaVersion", "projectCount", "projects"},
        "Publication task graph",
    )
    if type(graph.get("schemaVersion")) is not int or graph["schemaVersion"] != 1:
        fail("Publication task graph has an invalid schemaVersion")
    projects = graph.get("projects")
    project_count = graph.get("projectCount")
    if not isinstance(projects, list) or not projects:
        fail("Publication task graph contains no projects")
    if type(project_count) is not int or project_count != len(projects):
        fail("Publication task graph projectCount does not match its project list")

    project_paths: set[str] = set()
    projects_by_artifact: dict[str, list[str]] = defaultdict(list)
    for project in projects:
        if not isinstance(project, dict):
            fail("Publication task graph contains a malformed project")
        require_exact_keys(
            project,
            {"path", "artifactId", "publication", "task"},
            "Publication task graph project",
        )
        project_path = project.get("path")
        artifact = project.get("artifactId")
        publication = project.get("publication")
        task = project.get("task")
        if (
            not isinstance(project_path, str)
            or not re.fullmatch(r"(?::[A-Za-z0-9][A-Za-z0-9_.-]*)+", project_path)
            or not isinstance(artifact, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", artifact)
            or publication not in {"MavenJava", "MavenWeb"}
            or not isinstance(task, str)
            or not task
        ):
            fail("Publication task graph contains invalid project coordinates")
        if artifact != project_path.rsplit(":", 1)[-1]:
            fail(
                "Publication task graph artifactId does not match its Gradle project path: "
                f"{project_path} -> {artifact}"
            )
        expected_task = (
            f"{project_path}:publish{publication}PublicationToCasIdpForkRepository"
        )
        if task != expected_task:
            fail(
                "Publication task graph contains a task that is not bound to its project "
                f"and publication: {task} != {expected_task}"
            )
        if project_path in project_paths:
            fail(f"Publication task graph repeats a Gradle project path: {project_path}")
        project_paths.add(project_path)
        projects_by_artifact[artifact].append(project_path)

    sorted_paths = sorted(project_paths)
    if [project["path"] for project in projects] != sorted_paths:
        fail("Publication task graph projects are not in canonical path order")

    duplicate_artifacts = {
        artifact: sorted(paths)
        for artifact, paths in projects_by_artifact.items()
        if len(paths) > 1
    }
    if duplicate_artifacts:
        fail(
            "Publication task graph maps multiple projects to the same artifactId/GAV: "
            f"{duplicate_artifacts}"
        )
    return projects


def audit_repository(args: argparse.Namespace) -> None:
    repository_argument = Path(args.repository).absolute()
    if repository_argument.is_symlink():
        fail(f"Staged Maven repository must not be a symbolic link: {repository_argument}")
    repository = repository_argument.resolve()
    release_dir = Path(args.release_dir).resolve()
    task_graph_path = Path(args.task_graph).resolve()
    if not repository.is_dir():
        fail(f"Staged Maven repository does not exist: {repository}")

    graph = load_json_strict(task_graph_path, "publication task graph JSON")
    projects = validate_task_graph(graph)
    expected_artifacts = {project["artifactId"] for project in projects}
    files = version_files(repository, args.group, args.version)

    pom_paths = [path for path in files if path.suffix == ".pom"]
    poms: list[dict[str, Any]] = []
    actual_artifacts: set[str] = set()
    pom_paths_by_gav: dict[tuple[str, str, str], list[Path]] = defaultdict(list)
    for pom_path in pom_paths:
        pom = parse_pom(pom_path)
        relative = pom_path.relative_to(repository)
        if pom["group"] != args.group or pom["version"] != args.version:
            fail(f"Wrong fork coordinates in {relative}: {pom['group']}:{pom['version']}")
        expected_artifact = relative.parts[-3]
        if pom["artifact"] != expected_artifact:
            fail(f"Artifact/path mismatch in {relative}: {pom['artifact']} != {expected_artifact}")
        for dependency_group, dependency_artifact, _ in pom["dependencies"]:
            if dependency_group == OFFICIAL_CAS_GROUP:
                fail(
                    f"Mixed official/fork graph in {relative}: "
                    f"{dependency_group}:{dependency_artifact}"
                )
            if dependency_artifact.startswith("cas-server-") and dependency_group != args.group:
                fail(
                    f"CAS module dependency escaped fork group in {relative}: "
                    f"{dependency_group}:{dependency_artifact}"
                )
        snapshot_dependencies = sorted(
            f"{dependency_group}:{dependency_artifact}:{dependency_version}"
            for dependency_group, dependency_artifact, dependency_version in pom["dependencies"]
            if dependency_version.upper().endswith("-SNAPSHOT")
        )
        if snapshot_dependencies:
            fail(f"Snapshot dependencies are forbidden in {relative}: {snapshot_dependencies[:20]}")
        unsafe_repositories = sorted(
            url for url, snapshots_enabled in pom["repositories"]
            if snapshots_enabled or "snapshot" in url.lower()
        )
        if unsafe_repositories:
            fail(f"Snapshot repositories are forbidden in {relative}: {unsafe_repositories}")
        gav = (pom["group"], pom["artifact"], pom["version"])
        pom_paths_by_gav[gav].append(relative)
        poms.append(pom)
        actual_artifacts.add(pom["artifact"])

    duplicate_gavs = {
        ":".join(gav): sorted(str(path) for path in paths)
        for gav, paths in pom_paths_by_gav.items()
        if len(paths) > 1
    }
    if duplicate_gavs:
        fail(f"Multiple staged POMs declare the same Maven GAV: {duplicate_gavs}")

    missing = sorted(expected_artifacts - actual_artifacts)
    unexpected = sorted(actual_artifacts - expected_artifacts)
    if missing or unexpected:
        fail(f"Staged POM graph is incomplete; missing={missing}, unexpected={unexpected}")
    absent_required = sorted(REQUIRED_ARTIFACTS - actual_artifacts)
    if absent_required:
        fail(f"Required artifacts are absent from staging: {absent_required}")

    group_root = repository.joinpath(*args.group.split("."))
    main_binaries: set[Path] = set()
    for project in projects:
        artifact = project["artifactId"]
        artifact_directory = group_root / artifact / args.version
        required_files = [
            artifact_directory / f"{artifact}-{args.version}.pom",
            artifact_directory / f"{artifact}-{args.version}.module",
        ]
        if project["publication"] == "MavenWeb":
            main_binary = artifact_directory / f"{artifact}-{args.version}.war"
            required_files.append(main_binary)
            main_binaries.add(main_binary)
        elif artifact != "cas-server-support-bom":
            main_binary = artifact_directory / f"{artifact}-{args.version}.jar"
            required_files.append(main_binary)
            main_binaries.add(main_binary)
        missing_files = [str(path.relative_to(repository)) for path in required_files if not path.is_file()]
        if missing_files:
            fail(f"Incomplete POM/module/binary publication for {artifact}: {missing_files}")

    for module_path in (path for path in files if path.suffix == ".module"):
        try:
            module = json.loads(module_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            fail(f"Invalid Gradle module metadata {module_path}: {error}")
        component = module.get("component", {})
        if component.get("group") != args.group or component.get("version") != args.version:
            fail(f"Wrong component coordinates in {module_path.relative_to(repository)}")
        if module_has_official_group(module):
            fail(f"Official CAS group leaked into {module_path.relative_to(repository)}")
        if module_has_snapshot_version(module):
            fail(f"Snapshot version leaked into {module_path.relative_to(repository)}")

    publication_files = [path for path in files if path.suffix in PRIMARY_SUFFIXES]
    unexpected_binaries = sorted(
        str(path.relative_to(repository))
        for path in publication_files
        if path.suffix in {".jar", ".war"} and path not in main_binaries
    )
    if unexpected_binaries:
        fail(
            "Fork releases must contain only the audited main binary for each module; "
            f"unexpected classified archives={unexpected_binaries[:20]}"
        )
    if args.require_signatures:
        unsigned = [
            str(path.relative_to(repository))
            for path in publication_files
            if not Path(f"{path}.asc").is_file()
        ]
        if unsigned:
            fail(f"Unsigned Maven publication files: {unsigned[:20]}")

    for path in sorted(main_binaries):
        git_properties_count = find_sensitive_git_properties(
            path,
            args.fork_commit,
            args.group,
            args.version,
            args.fork_repository,
            args.upstream_version,
            args.upstream_commit,
        )
        if git_properties_count == 0:
            fail(
                "Every main binary must contain commit-bound git.properties; missing in "
                f"{path.relative_to(repository)}"
            )

    artifact_hashes: dict[str, dict[str, Any]] = {}
    for path in files:
        if path.suffix in CHECKSUM_SUFFIXES:
            continue
        relative = f"repository/{path.relative_to(repository).as_posix()}"
        artifact_hashes[relative] = {
            "path": relative,
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }

    sbom_path = release_dir / SBOM_NAME
    audit_resolved_sbom(
        Path(args.resolved_sbom).resolve(),
        sbom_path,
        args.group,
        args.version,
        expected_artifacts,
    )

    manifest_path = release_dir / RELEASE_MANIFEST_NAME
    manifest = {
        "schemaVersion": 1,
        "coordinates": {"group": args.group, "version": args.version},
        "source": {
            "forkRepository": args.fork_repository,
            "forkCommit": args.fork_commit,
            "releaseTag": f"v{args.version}",
            "upstreamVersion": args.upstream_version,
            "upstreamTag": f"v{args.upstream_version}",
            "upstreamCommit": args.upstream_commit,
        },
        "publication": {
            "repository": args.package_repository,
            "projectCount": graph["projectCount"],
            "signed": bool(args.require_signatures),
            "atomic": False,
            "partialFailurePolicy": EXPECTED_PARTIAL_FAILURE_POLICY,
        },
        "taskGraph": {
            "path": task_graph_path.name,
            "sha256": sha256_file(task_graph_path),
        },
        "sbom": {"path": sbom_path.name, "sha256": sha256_file(sbom_path), "format": "CycloneDX-1.6"},
        "artifacts": [artifact_hashes[key] for key in sorted(artifact_hashes)],
    }
    stable_json(manifest_path, manifest)

    checksum_entries = {
        **{key: value["sha256"] for key, value in artifact_hashes.items()},
        task_graph_path.name: sha256_file(task_graph_path),
        sbom_path.name: sha256_file(sbom_path),
        manifest_path.name: sha256_file(manifest_path),
    }
    checksums_path = release_dir / CHECKSUMS_NAME
    checksums_path.write_text(
        "".join(f"{checksum_entries[path]}  {path}\n" for path in sorted(checksum_entries)),
        encoding="utf-8",
    )
    print(
        f"Audited {len(actual_artifacts)} staged modules and "
        f"{len(artifact_hashes)} immutable release files"
    )


def verify_candidate(args: argparse.Namespace) -> None:
    release_dir = Path(args.release_dir).resolve()
    manifest_path = release_dir / RELEASE_MANIFEST_NAME
    checksums_path = release_dir / CHECKSUMS_NAME
    manifest, manifest_artifact_entries = load_manifest_artifacts(manifest_path)

    expected_source = manifest["source"]
    if expected_source["forkCommit"] != args.fork_commit:
        fail("Prepared candidate belongs to another fork commit")
    if manifest["coordinates"] != {"group": args.group, "version": args.version}:
        fail("Prepared candidate belongs to another Maven coordinate/version")

    expected_checksums: dict[str, str] = {}
    for line in checksums_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            fail(f"Malformed SHA256SUMS line: {line}")
        expected_checksums[match.group(2)] = match.group(1)

    for relative, expected_hash in expected_checksums.items():
        path = release_dir / relative
        if not path.is_file():
            fail(f"Prepared candidate file is missing: {relative}")
        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            fail(f"Prepared candidate changed after audit: {relative}")

    manifest_artifacts = {
        item["path"]: item["sha256"] for item in manifest_artifact_entries
    }
    for path, digest in manifest_artifacts.items():
        if expected_checksums.get(path) != digest:
            fail(f"Manifest/checksum disagreement for {path}")
    print(f"Verified immutable candidate with {len(manifest_artifacts)} release files")


def audit_test_results(args: argparse.Namespace) -> None:
    total = 0
    for specification in args.result:
        path_text, expected_text = specification.rsplit(":", 1)
        path = Path(path_text).resolve()
        expected = int(expected_text)
        if expected <= 0:
            fail(f"Expected test count must be positive for {path_text}")
        if not path.is_file():
            fail(f"Required test result is missing (task may have been skipped): {path_text}")
        try:
            suite = ET.parse(path).getroot()
        except ET.ParseError as error:
            fail(f"Invalid JUnit XML {path_text}: {error}")
        counts = {
            name: int(suite.attrib.get(name, "0"))
            for name in ("tests", "skipped", "failures", "errors")
        }
        if counts["tests"] != expected:
            fail(
                f"Required test suite {path_text} ran {counts['tests']} tests; "
                f"expected exactly {expected}"
            )
        if counts["skipped"] or counts["failures"] or counts["errors"]:
            fail(f"Required test suite {path_text} is not clean: {counts}")
        total += counts["tests"]
    print(f"Verified {len(args.result)} required test suites containing {total} tests")


def authorization_header(actor: str, token: str) -> str:
    encoded = base64.b64encode(f"{actor}:{token}".encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def github_credentials() -> tuple[str, str]:
    """Load short-lived package credentials without ever accepting them in argv."""
    actor = os.environ.get("GITHUB_ACTOR", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not actor:
        fail("GITHUB_ACTOR is required for authenticated package requests")
    if not token:
        fail("GITHUB_TOKEN is required for authenticated package requests")
    if ":" in actor or any(character in actor for character in "\r\n\0"):
        fail("GITHUB_ACTOR contains characters that are unsafe in HTTP Basic authentication")
    if any(character in token for character in "\r\n\0"):
        fail("GITHUB_TOKEN contains characters that are unsafe in an HTTP header")
    return actor, token


def require_remote_limits(attempts: int, workers: int | None = None) -> None:
    if attempts <= 0 or attempts > MAX_REMOTE_ATTEMPTS:
        fail(
            "Authenticated package request attempts must be between 1 and "
            f"{MAX_REMOTE_ATTEMPTS}"
        )
    if workers is not None and (workers <= 0 or workers > MAX_REMOTE_WORKERS):
        fail(
            "Authenticated package request worker count must be between 1 and "
            f"{MAX_REMOTE_WORKERS}"
        )


def retry_after_seconds(headers: Any) -> float | None:
    value = headers.get("Retry-After") if headers is not None else None
    if value is None:
        return None
    value = value.strip()
    if re.fullmatch(r"[0-9]+", value):
        return min(float(value), MAX_RETRY_AFTER_SECONDS)
    try:
        retry_at = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if retry_at is None:
        return None
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=datetime.timezone.utc)
    delay = retry_at.timestamp() - time.time()
    return min(max(delay, 0.0), MAX_RETRY_AFTER_SECONDS)


def jitter_seconds() -> float:
    try:
        value = float(JITTER_SOURCE())
    except (TypeError, ValueError):
        value = 0.0
    if not math.isfinite(value):
        value = 0.0
    return min(max(value, 0.0), 1.0) * RETRY_JITTER_SECONDS


def wait_before_retry(attempt: int, retry_after: float | None = None) -> None:
    base_delay = (
        retry_after
        if retry_after is not None
        else min(0.25 * (2**attempt), MAX_RETRY_AFTER_SECONDS)
    )
    SLEEP(min(max(base_delay, 0.0), MAX_RETRY_AFTER_SECONDS) + jitter_seconds())


def wait_between_preflight_scans() -> None:
    SLEEP(PREFLIGHT_DELAY_SECONDS + jitter_seconds())


def url_origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        fail(f"Authenticated package URL has an invalid HTTP(S) origin: {url}")
    if parsed.username is not None or parsed.password is not None:
        fail("Authenticated package URLs must not contain user information")
    try:
        port = parsed.port
    except ValueError as error:
        fail(f"Authenticated package URL has an invalid port: {error}")
    if port is None:
        port = 443 if scheme == "https" else 80
    hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if scheme == "http" and hostname not in {"127.0.0.1", "::1", "localhost"}:
        fail("Authenticated package requests require HTTPS except on the loopback interface")
    return scheme, hostname, port


class SameOriginAuthorizationRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects that could forward release credentials to another origin."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        resolved_url = urllib.parse.urljoin(request.full_url, new_url)
        if url_origin(request.full_url) != url_origin(resolved_url):
            fail(
                "Refusing to follow an authenticated package redirect across origins: "
                f"{url_origin(request.full_url)} -> {url_origin(resolved_url)}"
            )
        if request.get_method() == "PUT":
            if code not in {307, 308}:
                fail(
                    "Refusing an authenticated PUT redirect that does not preserve "
                    f"the HTTP method and request body: status={code}"
                )
            body = request.data
            if body is None or not hasattr(body, "rewind"):
                fail("Authenticated PUT redirect cannot safely replay its request body")
            body.rewind()
            redirected_headers = {
                key: value
                for key, value in request.headers.items()
                if key.lower() != "host"
            }
            return urllib.request.Request(
                resolved_url,
                data=body,
                headers=redirected_headers,
                method="PUT",
            )
        return super().redirect_request(
            request,
            file_pointer,
            code,
            message,
            headers,
            resolved_url,
        )


def authenticated_request(
    url: str,
    actor: str,
    token: str,
    attempts: int,
    allow_missing: bool,
    response_handler: Callable[[Any], _RESPONSE_VALUE],
    *,
    missing_policy: MissingResponsePolicy | None = None,
) -> _RESPONSE_VALUE | None:
    require_remote_limits(attempts)
    url_origin(url)
    effective_missing_policy = missing_policy or (
        MissingResponsePolicy.IMMEDIATE
        if allow_missing
        else MissingResponsePolicy.KNOWN_PRESENT
    )
    headers = {
        "Authorization": authorization_header(actor, token),
        "Accept": "application/octet-stream",
        "User-Agent": "casidp-release-auditor/1",
    }
    opener = urllib.request.build_opener(SameOriginAuthorizationRedirectHandler())
    last_outcome = "no response"
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers=headers)
            with opener.open(request, timeout=60) as response:
                return response_handler(response)
        except urllib.error.HTTPError as error:
            status = error.code
            retry_after = retry_after_seconds(error.headers)
            error.close()
            if status == 404:
                if effective_missing_policy == MissingResponsePolicy.IMMEDIATE:
                    return None
                last_outcome = "HTTP 404"
                if attempt + 1 == attempts:
                    if effective_missing_policy == MissingResponsePolicy.RETRY_MISSING:
                        return None
                    raise RemoteTransientError(
                        f"Known-present package path remained HTTP 404 after "
                        f"{attempts} bounded attempts: {url}"
                    )
                wait_before_retry(attempt, retry_after)
                continue
            if status not in RETRYABLE_HTTP_STATUS_CODES:
                fail(f"Authenticated package request failed with HTTP {status}: {url}")
            last_outcome = f"HTTP {status}"
        except (http.client.HTTPException, OSError, urllib.error.URLError) as error:
            last_outcome = type(error).__name__
            retry_after = None
        if attempt + 1 < attempts:
            wait_before_retry(attempt, retry_after)
    raise RemoteTransientError(
        f"Unable to read {url} after {attempts} bounded attempts: {last_outcome}"
    )


def response_content_length(response: Any) -> int | None:
    value = response.headers.get("Content-Length")
    if value is None:
        return None
    if not re.fullmatch(r"[0-9]+", value):
        raise RemoteContentConflict(
            f"Remote package response has an invalid Content-Length: {value!r}"
        )
    return int(value)


def stream_remote_digest(
    response: Any,
    expected_size: int,
) -> tuple[str, int]:
    declared_size = response_content_length(response)
    if declared_size is not None and declared_size != expected_size:
        raise RemoteContentConflict(
            "Remote package response Content-Length disagrees with the release manifest: "
            f"expected {expected_size}, got {declared_size}"
        )

    digest = hashlib.sha256()
    actual_size = 0
    while True:
        chunk = response.read(REMOTE_READ_CHUNK_SIZE)
        if not chunk:
            break
        actual_size += len(chunk)
        if actual_size > expected_size:
            raise RemoteContentConflict(
                "Remote package is larger than the release manifest: "
                f"expected {expected_size}, received at least {actual_size}"
            )
        digest.update(chunk)
    if actual_size != expected_size:
        raise RemoteContentConflict(
            "Remote package size disagrees with the release manifest: "
            f"expected {expected_size}, got {actual_size}"
        )
    return digest.hexdigest(), actual_size


def request_remote_digest(
    url: str,
    actor: str,
    token: str,
    attempts: int,
    expected_size: int,
) -> tuple[str, int]:
    result = authenticated_request(
        url,
        actor,
        token,
        attempts,
        False,
        lambda response: stream_remote_digest(response, expected_size),
    )
    if result is None:
        fail(f"Remote package unexpectedly disappeared: {url}")
    return result


def validate_manifest_artifact_path(path: str) -> PurePosixPath:
    normalized_path = PurePosixPath(path)
    if (
        "\\" in path
        or "%" in path
        or any(character in path for character in "\r\n\0?#")
        or normalized_path.is_absolute()
        or normalized_path.parts[:1] != ("repository",)
        or len(normalized_path.parts) < 2
        or any(part in {"", ".", ".."} for part in normalized_path.parts)
        or normalized_path.as_posix() != path
    ):
        fail(f"Release manifest contains an unsafe artifact path: {path}")
    return normalized_path


def load_manifest_artifacts(manifest_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = load_json_strict(manifest_path, "release manifest JSON")
    if not isinstance(manifest, dict):
        fail("Release manifest must be a JSON object")
    require_exact_keys(
        manifest,
        {
            "schemaVersion",
            "coordinates",
            "source",
            "publication",
            "taskGraph",
            "sbom",
            "artifacts",
        },
        "Release manifest",
    )
    if type(manifest.get("schemaVersion")) is not int or manifest["schemaVersion"] != 1:
        fail("Release manifest must use schemaVersion 1")

    nested_schemas = {
        "coordinates": {"group", "version"},
        "source": {
            "forkRepository",
            "forkCommit",
            "releaseTag",
            "upstreamVersion",
            "upstreamTag",
            "upstreamCommit",
        },
        "publication": {
            "repository",
            "projectCount",
            "signed",
            "atomic",
            "partialFailurePolicy",
        },
        "taskGraph": {"path", "sha256"},
        "sbom": {"path", "sha256", "format"},
    }
    for field, expected_keys in nested_schemas.items():
        value = manifest.get(field)
        if not isinstance(value, dict):
            fail(f"Release manifest {field} must be an object")
        require_exact_keys(value, expected_keys, f"Release manifest {field}")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        fail("Release manifest contains no artifacts")
    artifact_paths: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            fail("Release manifest contains a malformed artifact entry")
        require_exact_keys(
            item,
            {"path", "sha256", "size"},
            "Release manifest artifact entry",
        )
        path = item.get("path")
        digest = item.get("sha256")
        size = item.get("size")
        if not isinstance(path, str):
            fail("Release manifest contains an invalid artifact path")
        validate_manifest_artifact_path(path)
        if path in artifact_paths:
            fail(f"Release manifest contains a duplicate artifact path: {path}")
        artifact_paths.add(path)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail(f"Release manifest contains an invalid SHA-256 for {path}")
        if type(size) is not int or size < 0:
            fail(f"Release manifest contains an invalid byte size for {path}")
    if [item["path"] for item in artifacts] != sorted(artifact_paths):
        fail("Release manifest artifacts are not in canonical path order")
    return manifest, artifacts


def remote_url(base_url: str, artifact_path: str) -> str:
    repository_identity(base_url)
    validate_manifest_artifact_path(artifact_path)
    relative = artifact_path.removeprefix("repository/")
    return f"{base_url.rstrip('/')}/{urllib.parse.quote(relative, safe='/.-_~')}"


def repository_identity(url: str) -> tuple[tuple[str, str, int], str]:
    parsed = urllib.parse.urlsplit(url)
    origin = url_origin(url)
    path_parts = parsed.path.removesuffix("/").split("/")[1:]
    if parsed.query or parsed.fragment:
        fail("Authenticated package repository URLs must not contain a query or fragment")
    if not parsed.path or parsed.path == "/":
        fail("Authenticated package repository URL must contain a repository path")
    if (
        "%" in parsed.path
        or "\\" in parsed.path
        or any(character in parsed.path for character in "\r\n\0")
        or any(part in {"", ".", ".."} for part in path_parts)
    ):
        fail("Authenticated package repository URL contains a non-canonical path")
    return origin, parsed.path.rstrip("/")


def require_manifest_repository(manifest: dict[str, Any], repository_url: str) -> None:
    publication = manifest.get("publication")
    expected_url = publication.get("repository") if isinstance(publication, dict) else None
    if not isinstance(expected_url, str):
        fail("Release manifest is not bound to a package repository")
    if repository_identity(expected_url) != repository_identity(repository_url):
        fail(
            "Requested package repository does not match the audited release manifest: "
            f"{repository_url}"
        )


def manifest_artifact_coordinates(
    artifact_path: str,
    group: str,
    version: str,
) -> tuple[str, str]:
    parts = validate_manifest_artifact_path(artifact_path).parts
    group_parts = tuple(group.split("."))
    artifact_index = 1 + len(group_parts)
    version_index = artifact_index + 1
    if (
        len(parts) != version_index + 2
        or tuple(parts[1:artifact_index]) != group_parts
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", parts[artifact_index])
        or parts[version_index] != version
    ):
        fail(
            "Release manifest artifact path is not bound to its Maven identity: "
            f"{artifact_path}"
        )
    artifact = parts[artifact_index]
    filename = parts[-1]
    basename = f"{artifact}-{version}"
    primary_suffix = next(
        (suffix for suffix in PRIMARY_SUFFIXES if filename == f"{basename}{suffix}"),
        None,
    )
    if primary_suffix is not None:
        return artifact, primary_suffix
    signed_suffix = next(
        (
            suffix
            for suffix in PRIMARY_SUFFIXES
            if filename == f"{basename}{suffix}.asc"
        ),
        None,
    )
    if signed_suffix is None:
        fail(
            "Release manifest artifact filename is not an audited primary publication "
            f"or detached signature: {artifact_path}"
        )
    return artifact, f"{signed_suffix}.asc"


def validate_publish_manifest(
    manifest: dict[str, Any],
    artifacts: list[dict[str, Any]],
    repository_url: str,
) -> None:
    coordinates = manifest.get("coordinates")
    source = manifest.get("source")
    publication = manifest.get("publication")
    if not isinstance(coordinates, dict):
        fail("Release manifest coordinates are missing")
    if not isinstance(source, dict):
        fail("Release manifest source identity is missing")
    if not isinstance(publication, dict):
        fail("Release manifest publication identity is missing")

    group = coordinates.get("group")
    version = coordinates.get("version")
    if group != EXPECTED_FORK_GROUP:
        fail(f"Release manifest has an untrusted Maven group: {group}")
    if not isinstance(version, str) or not re.fullmatch(
        r"8\.0\.0-casidp\.[1-9][0-9]*",
        version,
    ):
        fail(f"Release manifest has an invalid fork version: {version}")

    fork_commit = source.get("forkCommit")
    release_tag = f"v{version}"
    expected_source = {
        "forkRepository": EXPECTED_FORK_REPOSITORY,
        "releaseTag": release_tag,
        "upstreamCommit": EXPECTED_UPSTREAM_COMMIT,
        "upstreamTag": f"v{EXPECTED_UPSTREAM_VERSION}",
        "upstreamVersion": EXPECTED_UPSTREAM_VERSION,
    }
    mismatched_source = {
        key: source.get(key)
        for key, expected in expected_source.items()
        if source.get(key) != expected
    }
    if mismatched_source:
        fail(f"Release manifest has an untrusted source identity: {mismatched_source}")
    if not isinstance(fork_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", fork_commit):
        fail("Release manifest forkCommit must be a full lowercase Git commit")

    if publication.get("signed") is not True:
        fail("Remote publication requires a signed=true release manifest")
    project_count = publication.get("projectCount")
    if (
        isinstance(project_count, bool)
        or not isinstance(project_count, int)
        or project_count <= 0
    ):
        fail("Release manifest publication projectCount must be positive")
    if publication.get("atomic") is not False:
        fail("Release manifest must explicitly acknowledge non-atomic package publication")
    if publication.get("partialFailurePolicy") != EXPECTED_PARTIAL_FAILURE_POLICY:
        fail("Release manifest has an invalid partial-failure policy")
    require_manifest_repository(manifest, repository_url)

    task_graph = manifest.get("taskGraph")
    if not isinstance(task_graph, dict):
        fail("Release manifest taskGraph evidence is missing")
    if task_graph.get("path") != TASK_GRAPH_NAME or not re.fullmatch(
        r"[0-9a-f]{64}",
        str(task_graph.get("sha256", "")),
    ):
        fail("Release manifest taskGraph evidence is invalid")
    sbom = manifest.get("sbom")
    if not isinstance(sbom, dict):
        fail("Release manifest SBOM evidence is missing")
    if (
        sbom.get("path") != SBOM_NAME
        or sbom.get("format") != "CycloneDX-1.6"
        or not re.fullmatch(r"[0-9a-f]{64}", str(sbom.get("sha256", "")))
    ):
        fail("Release manifest SBOM evidence is invalid")

    expected_environment = {
        "GITHUB_REPOSITORY": "SoooEZ/cas",
        "GITHUB_SHA": fork_commit,
        "GITHUB_REF_NAME": release_tag,
        "GITHUB_REF": f"refs/tags/{release_tag}",
    }
    mismatched_environment = {
        name: os.environ.get(name)
        for name, expected in expected_environment.items()
        if os.environ.get(name) != expected
    }
    if mismatched_environment:
        fail(
            "GitHub workflow identity does not match the signed release manifest: "
            f"{mismatched_environment}"
        )
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    expected_workflow_ref = (
        "SoooEZ/cas/.github/workflows/casidp-release.yml"
        f"@refs/tags/{release_tag}"
    )
    if workflow_ref and workflow_ref != expected_workflow_ref:
        fail("GITHUB_WORKFLOW_REF is not bound to the signed release tag")
    dispatch_tag = os.environ.get("CASIDP_RELEASE_TAG", "")
    if dispatch_tag and dispatch_tag != release_tag:
        fail("CASIDP_RELEASE_TAG is not bound to the signed release manifest")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
            fail("GitHub Actions publication must be started by workflow_dispatch")
        if os.environ.get("GITHUB_REF_TYPE") != "tag":
            fail("GitHub Actions publication must run from the signed release tag")
        if not workflow_ref:
            fail("GITHUB_WORKFLOW_REF must bind publication to the signed release tag")
        if (
            repository_identity(repository_url)
            != repository_identity(EXPECTED_PACKAGE_REPOSITORY)
        ):
            fail("GitHub Actions publication is restricted to the fork package repository")

    for item in artifacts:
        manifest_artifact_coordinates(item["path"], group, version)


def release_directory(release_dir_argument: Path) -> Path:
    absolute_release_dir = release_dir_argument.absolute()
    if absolute_release_dir.is_symlink():
        fail(f"Release directory must not be a symbolic link: {absolute_release_dir}")
    release_dir = absolute_release_dir.resolve()
    if not release_dir.is_dir():
        fail(f"Release directory does not exist: {release_dir}")
    return release_dir


def confined_regular_file(release_dir: Path, relative_path: str) -> Path:
    relative = PurePosixPath(relative_path)
    if (
        relative.is_absolute()
        or relative.as_posix() != relative_path
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        fail(f"Release evidence path is unsafe: {relative_path}")
    current = release_dir
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            fail(f"Release evidence path contains a symbolic link: {relative_path}")
    try:
        status = current.stat()
        resolved = current.resolve(strict=True)
    except FileNotFoundError:
        fail(f"Release evidence file is missing: {relative_path}")
    if not resolved.is_relative_to(release_dir) or not stat.S_ISREG(status.st_mode):
        fail(f"Release evidence is not a confined regular file: {relative_path}")
    return resolved


def trusted_signing_fingerprint() -> str:
    for environment_name in (
        "PGP_PRIVATE_KEY",
        "PGP_PASSPHRASE",
        "CASIDP_SIGNING_FINGERPRINT",
    ):
        if os.environ.get(environment_name):
            fail(
                "Remote publication refuses private signing material: "
                f"{environment_name}"
            )
    value = "".join(os.environ.get("CASIDP_TRUSTED_SIGNING_FINGERPRINT", "").split())
    value = value.upper()
    if not re.fullmatch(r"[0-9A-F]{40}(?:[0-9A-F]{24})?", value):
        fail("CASIDP_TRUSTED_SIGNING_FINGERPRINT must be a full OpenPGP fingerprint")
    return value


def verification_subprocess_environment(gnupg_home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for environment_name in (
        "GITHUB_TOKEN",
        "PGP_PRIVATE_KEY",
        "PGP_PASSPHRASE",
    ):
        environment.pop(environment_name, None)
    environment["GNUPGHOME"] = str(gnupg_home)
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    return environment


def run_verification_command(
    command: list[str],
    environment: dict[str, str],
    description: str,
) -> subprocess.CompletedProcess[str]:
    token = os.environ.get("GITHUB_TOKEN", "")
    if token and any(token in argument for argument in command):
        fail("Internal error: the package token was placed in a subprocess argument")
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"Unable to run {description}: {type(error).__name__}: {error}")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().replace("\n", " ")[-500:]
        fail(f"{description} failed: {detail or f'exit status {result.returncode}'}")
    return result


def primary_fingerprint_from_colons(listing: str) -> tuple[str, int]:
    primary_count = 0
    primary_fingerprint = ""
    awaiting_fingerprint = False
    for line in listing.splitlines():
        fields = line.split(":")
        record_type = fields[0] if fields else ""
        if record_type == "pub":
            primary_count += 1
            awaiting_fingerprint = True
        elif record_type == "fpr" and awaiting_fingerprint:
            if len(fields) > 9:
                primary_fingerprint = fields[9].upper()
            awaiting_fingerprint = False
        elif record_type in {"sub", "sec", "ssb"}:
            awaiting_fingerprint = False
    return primary_fingerprint, primary_count


def require_expected_valid_signature(
    status_output: str,
    expected_fingerprint: str,
    description: str,
) -> None:
    forbidden_statuses = {
        "BADSIG",
        "ERRSIG",
        "EXPKEYSIG",
        "EXPSIG",
        "KEYEXPIRED",
        "KEYREVOKED",
        "NO_PUBKEY",
        "REVKEYSIG",
        "SIGEXPIRED",
    }
    observed_forbidden = sorted(
        status
        for status in forbidden_statuses
        if re.search(rf"\[GNUPG:\]\s+{status}(?:\s|$)", status_output)
    )
    if observed_forbidden:
        fail(f"{description} has unsafe OpenPGP status: {observed_forbidden}")
    valid_signatures: list[tuple[str, str]] = []
    for line in status_output.splitlines():
        match = re.search(r"\[GNUPG:\]\s+VALIDSIG\s+(\S+)(?:\s+.*)?\s+(\S+)\s*$", line)
        if match:
            valid_signatures.append((match.group(1).upper(), match.group(2).upper()))
    if len(valid_signatures) != 1:
        fail(
            f"{description} must contain exactly one valid OpenPGP signature; "
            f"found {len(valid_signatures)}"
        )
    signer, primary = valid_signatures[0]
    if expected_fingerprint not in {signer, primary}:
        fail(
            f"{description} signer {signer} (primary {primary}) is not the trusted "
            f"key {expected_fingerprint}"
        )


def initialize_verification_keyring(
    public_key: Path,
    expected_fingerprint: str,
    gnupg_home: Path,
) -> dict[str, str]:
    try:
        armored_key = public_key.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"Signing public-key evidence is not ASCII armor: {error}")
    stripped_key = armored_key.strip()
    if (
        stripped_key.count("-----BEGIN PGP PUBLIC KEY BLOCK-----") != 1
        or stripped_key.count("-----END PGP PUBLIC KEY BLOCK-----") != 1
        or not stripped_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        or not stripped_key.endswith("-----END PGP PUBLIC KEY BLOCK-----")
        or "-----BEGIN PGP PRIVATE KEY BLOCK-----" in stripped_key
    ):
        fail("Signing public-key evidence is not an armored public key")

    os.chmod(gnupg_home, 0o700)
    environment = verification_subprocess_environment(gnupg_home)
    run_verification_command(
        [
            "gpg",
            "--batch",
            "--no-options",
            "--homedir",
            str(gnupg_home),
            "--quiet",
            "--import",
            str(public_key),
        ],
        environment,
        "candidate signing public-key import",
    )
    imported_listing = run_verification_command(
        [
            "gpg",
            "--batch",
            "--no-options",
            "--homedir",
            str(gnupg_home),
            "--with-colons",
            "--list-keys",
        ],
        environment,
        "imported signing public-key inspection",
    ).stdout
    imported_fingerprint, imported_count = primary_fingerprint_from_colons(imported_listing)
    if imported_count != 1:
        fail(
            "Signing public-key evidence must contain exactly one primary key; "
            f"found {imported_count}"
        )
    if imported_fingerprint != expected_fingerprint:
        fail(
            f"Candidate signing public key {imported_fingerprint or '<none>'} does not "
            f"match trusted fingerprint {expected_fingerprint}"
        )
    unsafe_primary_states = sorted(
        fields[1]
        for line in imported_listing.splitlines()
        if (fields := line.split(":"))[0] == "pub"
        and len(fields) > 1
        and fields[1] in {"d", "e", "i", "r"}
    )
    if unsafe_primary_states:
        fail(
            "Trusted signing public key is disabled, expired, invalid, or revoked: "
            f"{unsafe_primary_states}"
        )
    return environment


def verify_detached_signature(
    signature: Path,
    payload: Path,
    expected_fingerprint: str,
    gnupg_home: Path,
    environment: dict[str, str],
) -> None:
    result = run_verification_command(
        [
            "gpg",
            "--batch",
            "--no-options",
            "--homedir",
            str(gnupg_home),
            "--status-fd=1",
            "--verify",
            str(signature),
            str(payload),
        ],
        environment,
        f"OpenPGP signature verification for {payload.name}",
    )
    require_expected_valid_signature(
        f"{result.stdout}\n{result.stderr}",
        expected_fingerprint,
        f"OpenPGP signature for {payload.name}",
    )


def verify_release_tag(
    source: dict[str, Any],
    expected_fingerprint: str,
    environment: dict[str, str],
) -> None:
    release_tag = source["releaseTag"]
    fork_commit = source["forkCommit"]
    repository_root = Path(__file__).resolve().parent.parent
    tag_reference = f"refs/tags/{release_tag}"
    object_type = run_verification_command(
        ["git", "-C", str(repository_root), "cat-file", "-t", tag_reference],
        environment,
        "release tag object inspection",
    ).stdout.strip()
    if object_type != "tag":
        fail(f"Release tag {release_tag} must be an annotated tag object")
    tagged_commit = run_verification_command(
        [
            "git",
            "-C",
            str(repository_root),
            "rev-parse",
            "--verify",
            f"{tag_reference}^{{commit}}",
        ],
        environment,
        "release tag commit resolution",
    ).stdout.strip()
    if tagged_commit != fork_commit:
        fail(
            f"Release tag {release_tag} resolves to {tagged_commit}, not manifest commit "
            f"{fork_commit}"
        )
    head_commit = run_verification_command(
        ["git", "-C", str(repository_root), "rev-parse", "--verify", "HEAD^{commit}"],
        environment,
        "release checkout commit resolution",
    ).stdout.strip()
    if head_commit != fork_commit:
        fail(f"Release checkout is {head_commit}, not manifest commit {fork_commit}")
    run_verification_command(
        ["git", "-C", str(repository_root), "diff", "--quiet", "HEAD", "--"],
        environment,
        "release checkout cleanliness verification",
    )
    verification = run_verification_command(
        [
            "git",
            "-c",
            "gpg.program=gpg",
            "-C",
            str(repository_root),
            "verify-tag",
            "--raw",
            tag_reference,
        ],
        environment,
        "release tag signature verification",
    )
    require_expected_valid_signature(
        f"{verification.stdout}\n{verification.stderr}",
        expected_fingerprint,
        f"release tag {release_tag}",
    )


def parse_and_verify_checksums(
    checksums_path: Path,
    release_dir: Path,
    expected_paths: set[str],
) -> dict[str, str]:
    try:
        contents = checksums_path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"Aggregate SHA256SUMS is not valid ASCII: {error}")
    if not contents.endswith("\n") or "\r" in contents:
        fail("Aggregate SHA256SUMS must use canonical LF-terminated lines")
    entries: dict[str, str] = {}
    ordered_paths: list[str] = []
    for line in contents.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match.group(2) in entries:
            fail(f"Malformed or duplicate SHA256SUMS entry: {line}")
        relative_path = match.group(2)
        if relative_path.startswith("repository/"):
            validate_manifest_artifact_path(relative_path)
        elif relative_path not in {
            RELEASE_MANIFEST_NAME,
            SBOM_NAME,
            TASK_GRAPH_NAME,
            SIGNING_PUBLIC_KEY_NAME,
        }:
            fail(f"SHA256SUMS contains an unexpected evidence path: {relative_path}")
        entries[relative_path] = match.group(1)
        ordered_paths.append(relative_path)
    if set(entries) != expected_paths:
        fail(
            "SHA256SUMS does not exactly cover the signed candidate: "
            f"missing={sorted(expected_paths - set(entries))[:20]}, "
            f"unexpected={sorted(set(entries) - expected_paths)[:20]}"
        )
    if ordered_paths != sorted(ordered_paths):
        fail("SHA256SUMS entries are not in canonical path order")
    for relative_path, expected_digest in entries.items():
        path = confined_regular_file(release_dir, relative_path)
        actual_digest = sha256_file(path)
        if actual_digest != expected_digest:
            fail(
                f"SHA256SUMS disagrees with {relative_path}: expected {expected_digest}, "
                f"got {actual_digest}"
            )
    return entries


def validate_manifest_task_graph_coverage(
    manifest: dict[str, Any],
    artifacts: list[dict[str, Any]],
    projects: list[dict[str, Any]],
) -> set[str]:
    group = manifest["coordinates"]["group"]
    version = manifest["coordinates"]["version"]
    primary_paths: set[str] = set()
    signature_paths: set[str] = set()
    actual_artifact_ids: set[str] = set()
    for item in artifacts:
        artifact, suffix = manifest_artifact_coordinates(item["path"], group, version)
        actual_artifact_ids.add(artifact)
        if suffix.endswith(".asc"):
            signature_paths.add(item["path"])
        else:
            primary_paths.add(item["path"])
    expected_signature_paths = {f"{path}.asc" for path in primary_paths}
    if signature_paths != expected_signature_paths:
        fail(
            "Signed release manifest does not have exactly one detached signature for "
            "every Maven publication file: "
            f"missing={sorted(expected_signature_paths - signature_paths)[:20]}, "
            f"unexpected={sorted(signature_paths - expected_signature_paths)[:20]}"
        )

    expected_artifact_ids = {project["artifactId"] for project in projects}
    if actual_artifact_ids != expected_artifact_ids:
        fail(
            "Release manifest artifact IDs do not exactly match the publication task graph: "
            f"missing={sorted(expected_artifact_ids - actual_artifact_ids)[:20]}, "
            f"unexpected={sorted(actual_artifact_ids - expected_artifact_ids)[:20]}"
        )
    group_path = group.replace(".", "/")
    expected_primary_paths: set[str] = set()
    for project in projects:
        artifact = project["artifactId"]
        prefix = f"repository/{group_path}/{artifact}/{version}/{artifact}-{version}"
        expected_primary_paths.update({f"{prefix}.pom", f"{prefix}.module"})
        if project["publication"] == "MavenWeb":
            expected_primary_paths.add(f"{prefix}.war")
        elif artifact != "cas-server-support-bom":
            expected_primary_paths.add(f"{prefix}.jar")
    if primary_paths != expected_primary_paths:
        fail(
            "Release manifest does not exactly match the publication task graph outputs: "
            f"missing={sorted(expected_primary_paths - primary_paths)[:20]}, "
            f"unexpected={sorted(primary_paths - expected_primary_paths)[:20]}"
        )
    return expected_artifact_ids


def validate_task_graph_log(task_log_path: Path, projects: list[dict[str, Any]]) -> None:
    try:
        task_log = task_log_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"Publication task-graph log is not valid UTF-8: {error}")
    observed_counts: dict[str, int] = defaultdict(int)
    for match in PUBLICATION_TASK.finditer(task_log):
        project_path, publication = match.groups()
        task = (
            f"{project_path}:publish{publication}PublicationToCasIdpForkRepository"
        )
        observed_counts[task] += 1
    expected_tasks = {project["task"] for project in projects}
    observed_tasks = set(observed_counts)
    duplicates = sorted(task for task, count in observed_counts.items() if count != 1)
    if observed_tasks != expected_tasks or duplicates:
        fail(
            "Signed publication task-graph log disagrees with its audited graph: "
            f"missing={sorted(expected_tasks - observed_tasks)[:20]}, "
            f"unexpected={sorted(observed_tasks - expected_tasks)[:20]}, "
            f"duplicates={duplicates[:20]}"
        )


def validate_task_graph_against_source(projects: list[dict[str, Any]]) -> None:
    repository_root = Path(__file__).resolve().parent.parent
    settings_path = repository_root / "settings.gradle"
    if settings_path.is_symlink() or not settings_path.is_file():
        fail("Release checkout settings.gradle is missing or is a symbolic link")
    expected_paths = expected_project_paths(settings_path)
    actual_paths = {project["path"] for project in projects}
    if actual_paths != expected_paths:
        fail(
            "Signed publication task graph does not exactly cover the release checkout: "
            f"missing={sorted(expected_paths - actual_paths)[:20]}, "
            f"unexpected={sorted(actual_paths - expected_paths)[:20]}"
        )
    actual_artifacts = {project["artifactId"] for project in projects}
    missing_required = sorted(REQUIRED_ARTIFACTS - actual_artifacts)
    if missing_required:
        fail(f"Signed publication task graph omits required artifacts: {missing_required}")


def validate_source_metadata_against_manifest(manifest: dict[str, Any]) -> None:
    repository_root = Path(__file__).resolve().parent.parent
    properties_path = repository_root / "gradle.properties"
    if properties_path.is_symlink() or not properties_path.is_file():
        fail("Release checkout gradle.properties is missing or is a symbolic link")
    try:
        lines = properties_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        fail(f"Release checkout gradle.properties is invalid: {error}")
    expected = {
        "group": manifest["coordinates"]["group"],
        "version": manifest["coordinates"]["version"],
        "casIdpUpstreamVersion": manifest["source"]["upstreamVersion"],
        "casIdpUpstreamCommit": manifest["source"]["upstreamCommit"],
        "casIdpForkRepository": manifest["source"]["forkRepository"],
    }
    for key, expected_value in expected.items():
        values = [
            line.removeprefix(f"{key}=")
            for line in lines
            if line.startswith(f"{key}=")
        ]
        if values != [expected_value]:
            fail(
                f"Release checkout property {key} does not exactly match the signed "
                f"manifest: {values} != {[expected_value]}"
            )


def require_repository_matches_manifest(
    release_dir: Path,
    artifact_paths: set[str],
) -> None:
    repository = release_dir / "repository"
    if repository.is_symlink() or not repository.is_dir():
        fail("Signed candidate repository is missing or is a symbolic link")
    actual_paths: set[str] = set()
    for path in repository.rglob("*"):
        if path.is_symlink():
            fail(
                "Signed candidate repository contains a symbolic link: "
                f"{path.relative_to(release_dir)}"
            )
        if not path.is_file():
            continue
        relative_path = f"repository/{path.relative_to(repository).as_posix()}"
        if path.suffix not in CHECKSUM_SUFFIXES:
            actual_paths.add(relative_path)
    if actual_paths != artifact_paths:
        fail(
            "Signed candidate repository differs from its release manifest: "
            f"missing={sorted(artifact_paths - actual_paths)[:20]}, "
            f"unexpected={sorted(actual_paths - artifact_paths)[:20]}"
        )


def verify_publication_candidate(
    manifest_path: Path,
    release_dir_argument: Path,
    manifest: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> dict[Path, str]:
    """Verify the entire signed candidate before the first authenticated request."""
    release_dir = release_directory(release_dir_argument)
    expected_manifest_path = confined_regular_file(release_dir, RELEASE_MANIFEST_NAME)
    if manifest_path != expected_manifest_path:
        fail(
            "Publication manifest must be the audited manifest inside the release directory: "
            f"{expected_manifest_path}"
        )

    expected_fingerprint = trusted_signing_fingerprint()
    validate_source_metadata_against_manifest(manifest)
    public_key = confined_regular_file(release_dir, SIGNING_PUBLIC_KEY_NAME)
    artifact_paths = {item["path"] for item in artifacts}
    require_repository_matches_manifest(release_dir, artifact_paths)

    evidence_paths: set[Path] = {public_key}
    with tempfile.TemporaryDirectory(prefix="casidp-verify-gnupg-") as temporary_directory:
        gnupg_home = Path(temporary_directory)
        environment = initialize_verification_keyring(
            public_key,
            expected_fingerprint,
            gnupg_home,
        )
        for metadata_name in SIGNED_METADATA_NAMES:
            payload = confined_regular_file(release_dir, metadata_name)
            signature = confined_regular_file(release_dir, f"{metadata_name}.asc")
            verify_detached_signature(
                signature,
                payload,
                expected_fingerprint,
                gnupg_home,
                environment,
            )
            evidence_paths.update({payload, signature})

        checksums_path = confined_regular_file(release_dir, CHECKSUMS_NAME)
        expected_checksum_paths = artifact_paths | {
            RELEASE_MANIFEST_NAME,
            SBOM_NAME,
            TASK_GRAPH_NAME,
            SIGNING_PUBLIC_KEY_NAME,
        }
        checksum_entries = parse_and_verify_checksums(
            checksums_path,
            release_dir,
            expected_checksum_paths,
        )
        if checksum_entries[TASK_GRAPH_NAME] != manifest["taskGraph"]["sha256"]:
            fail("Release manifest disagrees with SHA256SUMS for the publication task graph")
        if checksum_entries[SBOM_NAME] != manifest["sbom"]["sha256"]:
            fail("Release manifest disagrees with SHA256SUMS for the CycloneDX SBOM")

        task_graph_path = confined_regular_file(release_dir, TASK_GRAPH_NAME)
        graph = load_json_strict(task_graph_path, "publication task graph JSON")
        projects = validate_task_graph(graph)
        if graph["projectCount"] != manifest["publication"]["projectCount"]:
            fail("Release manifest projectCount disagrees with the publication task graph")
        validate_task_graph_against_source(projects)
        validate_task_graph_log(
            confined_regular_file(release_dir, TASK_LOG_NAME),
            projects,
        )
        expected_artifacts = validate_manifest_task_graph_coverage(
            manifest,
            artifacts,
            projects,
        )

        sbom_path = confined_regular_file(release_dir, SBOM_NAME)
        sbom = load_json_strict(sbom_path, "resolved CycloneDX JSON")
        validate_resolved_sbom(
            sbom,
            manifest["coordinates"]["group"],
            manifest["coordinates"]["version"],
            expected_artifacts,
        )

        for primary_path in sorted(
            path for path in artifact_paths if PurePosixPath(path).suffix in PRIMARY_SUFFIXES
        ):
            payload = confined_regular_file(release_dir, primary_path)
            signature = confined_regular_file(release_dir, f"{primary_path}.asc")
            verify_detached_signature(
                signature,
                payload,
                expected_fingerprint,
                gnupg_home,
                environment,
            )

        verify_release_tag(manifest["source"], expected_fingerprint, environment)

    return {path: sha256_file(path) for path in evidence_paths}


def inspect_remote_artifact(
    item: dict[str, Any],
    repository_url: str,
    actor: str,
    token: str,
    attempts: int,
    missing_policy: MissingResponsePolicy = MissingResponsePolicy.IMMEDIATE,
) -> tuple[str, str | None]:
    url = remote_url(repository_url, item["path"])
    try:
        result = authenticated_request(
            url,
            actor,
            token,
            attempts,
            True,
            lambda response: stream_remote_digest(response, item["size"]),
            missing_policy=missing_policy,
        )
    except RemoteContentConflict as error:
        return "CONFLICT", str(error)
    except RemoteTransientError as error:
        return "INDETERMINATE", str(error)
    if result is None:
        return "MISSING", None
    actual_digest, _ = result
    if actual_digest != item["sha256"]:
        return (
            "CONFLICT",
            f"expected SHA-256 {item['sha256']}, got {actual_digest}",
        )
    return "EXACT", None


def publication_state(
    statuses: dict[str, str],
    details_by_path: dict[str, str],
) -> tuple[RemotePublicationState, list[str]]:
    if not statuses:
        fail("Cannot classify an empty remote publication")
    unexpected_statuses = sorted(
        set(statuses.values()) - {"MISSING", "EXACT", "CONFLICT", "INDETERMINATE"}
    )
    if unexpected_statuses:
        fail(f"Remote publication contains invalid artifact statuses: {unexpected_statuses}")
    conflicts = sorted(
        f"{path}: {details_by_path.get(path, 'remote bytes conflict')}"
        for path, status in statuses.items()
        if status == "CONFLICT"
    )
    if conflicts:
        return RemotePublicationState.CONFLICT, conflicts
    indeterminate = sorted(
        f"{path}: {details_by_path.get(path, 'remote outcome is indeterminate')}"
        for path, status in statuses.items()
        if status == "INDETERMINATE"
    )
    if indeterminate:
        return RemotePublicationState.INDETERMINATE, indeterminate
    missing = sorted(path for path, status in statuses.items() if status == "MISSING")
    exact = sorted(path for path, status in statuses.items() if status == "EXACT")
    if len(missing) == len(statuses):
        return RemotePublicationState.ABSENT, []
    if len(exact) == len(statuses):
        return RemotePublicationState.COMPLETE_EXACT, []
    return (
        RemotePublicationState.PARTIAL,
        [
            f"exact paths={exact[:20]}",
            f"missing paths={missing[:20]}",
        ],
    )


def scan_remote_publication(
    artifacts: list[dict[str, Any]],
    repository_url: str,
    actor: str,
    token: str,
    workers: int,
    attempts: int,
    missing_policy: MissingResponsePolicy,
) -> tuple[RemotePublicationState, list[str], dict[str, str]]:
    require_remote_limits(attempts, workers)

    statuses: dict[str, str] = {}
    details_by_path: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                inspect_remote_artifact,
                item,
                repository_url,
                actor,
                token,
                attempts,
                missing_policy,
            ): item["path"]
            for item in artifacts
        }
        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            status, detail = future.result()
            statuses[path] = status
            if detail:
                details_by_path[path] = detail
    state, details = publication_state(statuses, details_by_path)
    return state, details, statuses


def classify_remote_publication(
    artifacts: list[dict[str, Any]],
    repository_url: str,
    actor: str,
    token: str,
    workers: int,
    attempts: int,
) -> tuple[RemotePublicationState, list[str]]:
    state, details, _ = scan_remote_publication(
        artifacts,
        repository_url,
        actor,
        token,
        workers,
        attempts,
        MissingResponsePolicy.IMMEDIATE,
    )
    return state, details


def preflight_remote_publication(
    artifacts: list[dict[str, Any]],
    repository_url: str,
    actor: str,
    token: str,
    workers: int,
    attempts: int,
) -> tuple[RemotePublicationState, list[str]]:
    first_state, first_details, first_statuses = scan_remote_publication(
        artifacts,
        repository_url,
        actor,
        token,
        workers,
        attempts,
        MissingResponsePolicy.IMMEDIATE,
    )
    wait_between_preflight_scans()
    second_state, second_details, second_statuses = scan_remote_publication(
        artifacts,
        repository_url,
        actor,
        token,
        workers,
        attempts,
        MissingResponsePolicy.IMMEDIATE,
    )
    if first_statuses != second_statuses:
        drift = sorted(
            path
            for path in first_statuses
            if first_statuses[path] != second_statuses.get(path)
        )
        return (
            RemotePublicationState.INDETERMINATE,
            [
                "Remote exact/missing observations drifted between complete "
                f"preflight scans: {drift[:20]}",
                f"first={first_state.value}:{first_details[:20]}",
                f"second={second_state.value}:{second_details[:20]}",
            ],
        )
    if first_state != second_state:
        return (
            RemotePublicationState.INDETERMINATE,
            [
                f"Remote preflight state drifted: {first_state.value} -> "
                f"{second_state.value}"
            ],
        )
    return second_state, second_details


def confirm_remote_publication(
    artifacts: list[dict[str, Any]],
    repository_url: str,
    actor: str,
    token: str,
    workers: int,
    attempts: int,
    confirmed_exact: set[str],
    known_present: set[str],
) -> tuple[RemotePublicationState, list[str]]:
    require_remote_limits(attempts, workers)
    statuses = {path: "EXACT" for path in confirmed_exact}
    details_by_path: dict[str, str] = {}
    pending = [item for item in artifacts if item["path"] not in confirmed_exact]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                inspect_remote_artifact,
                item,
                repository_url,
                actor,
                token,
                attempts,
                (
                    MissingResponsePolicy.KNOWN_PRESENT
                    if item["path"] in known_present
                    else MissingResponsePolicy.RETRY_MISSING
                ),
            ): item["path"]
            for item in pending
        }
        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            status, detail = future.result()
            statuses[path] = status
            if detail:
                details_by_path[path] = detail
    state, details = publication_state(statuses, details_by_path)
    if state == RemotePublicationState.ABSENT:
        return (
            RemotePublicationState.INDETERMINATE,
            ["Every uploaded path remained transiently missing after bounded confirmation"],
        )
    return state, details


def local_artifact_path(release_dir: Path, artifact_path: str) -> Path:
    relative = PurePosixPath(artifact_path)
    current = release_dir
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            fail(f"Release artifact path contains a symbolic link: {artifact_path}")
    try:
        resolved = current.resolve(strict=True)
    except FileNotFoundError:
        fail(f"Release artifact is missing: {artifact_path}")
    if not resolved.is_relative_to(release_dir):
        fail(f"Release artifact escapes the release directory: {artifact_path}")
    return resolved


def snapshot_local_artifacts(
    release_dir_argument: Path,
    artifacts: list[dict[str, Any]],
    snapshot_dir: Path,
) -> list[tuple[dict[str, Any], Path]]:
    absolute_release_dir = release_dir_argument.absolute()
    if absolute_release_dir.is_symlink():
        fail(f"Release directory must not be a symbolic link: {absolute_release_dir}")
    release_dir = absolute_release_dir.resolve()
    if not release_dir.is_dir():
        fail(f"Release directory does not exist: {release_dir}")

    snapshots: list[tuple[dict[str, Any], Path]] = []
    for index, item in enumerate(sorted(artifacts, key=lambda artifact: artifact["path"])):
        source = local_artifact_path(release_dir, item["path"])
        snapshot = snapshot_dir / f"{index:06d}.artifact"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        digest = hashlib.sha256()
        actual_size = 0
        with os.fdopen(descriptor, "rb") as input_stream:
            source_stat = os.fstat(input_stream.fileno())
            if not stat.S_ISREG(source_stat.st_mode):
                fail(f"Release artifact is not a regular file: {item['path']}")
            if source_stat.st_size != item["size"]:
                fail(
                    f"Release artifact size changed after audit for {item['path']}: "
                    f"expected {item['size']}, got {source_stat.st_size}"
                )
            with snapshot.open("xb") as output_stream:
                while True:
                    chunk = input_stream.read(REMOTE_READ_CHUNK_SIZE)
                    if not chunk:
                        break
                    actual_size += len(chunk)
                    if actual_size > item["size"]:
                        fail(
                            f"Release artifact grew while being snapshotted: {item['path']}"
                        )
                    digest.update(chunk)
                    output_stream.write(chunk)
        os.chmod(snapshot, 0o600)
        if actual_size != item["size"] or digest.hexdigest() != item["sha256"]:
            fail(
                f"Release artifact bytes changed after audit for {item['path']}: "
                f"expected size/SHA-256 {item['size']}/{item['sha256']}, "
                f"got {actual_size}/{digest.hexdigest()}"
            )
        snapshots.append((item, snapshot))
    return snapshots


def verify_local_artifacts(
    release_dir_argument: Path,
    artifacts: list[dict[str, Any]],
) -> None:
    absolute_release_dir = release_dir_argument.absolute()
    if absolute_release_dir.is_symlink():
        fail(f"Release directory must not be a symbolic link: {absolute_release_dir}")
    release_dir = absolute_release_dir.resolve()
    for item in artifacts:
        path = local_artifact_path(release_dir, item["path"])
        if path.stat().st_size != item["size"] or sha256_file(path) != item["sha256"]:
            fail(f"Release artifact changed while publication was in progress: {item['path']}")


class StreamingUploadBody:
    """A replayable, bounded file body that hashes the bytes handed to HTTP."""

    def __init__(self, path: Path, expected_size: int, expected_digest: str) -> None:
        self.path = path
        self.expected_size = expected_size
        self.expected_digest = expected_digest
        self.stream: Any = None
        self.digest = hashlib.sha256()
        self.size = 0

    def __enter__(self) -> StreamingUploadBody:
        self.stream = self.path.open("rb")
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        if self.stream is not None:
            self.stream.close()

    def read(self, size: int = -1) -> bytes:
        if self.stream is None:
            fail("Streaming upload body was read outside its managed lifetime")
        bounded_size = REMOTE_READ_CHUNK_SIZE if size is None or size < 0 else size
        chunk = self.stream.read(min(bounded_size, REMOTE_READ_CHUNK_SIZE))
        self.size += len(chunk)
        if self.size > self.expected_size:
            fail(
                "Upload body is larger than its manifest byte size: "
                f"expected {self.expected_size}, sent at least {self.size}"
            )
        self.digest.update(chunk)
        return chunk

    def rewind(self) -> None:
        if self.stream is None:
            fail("Streaming upload body cannot be replayed outside its managed lifetime")
        self.stream.seek(0)
        self.digest = hashlib.sha256()
        self.size = 0

    def verify_complete(self) -> None:
        actual_digest = self.digest.hexdigest()
        if self.size != self.expected_size or actual_digest != self.expected_digest:
            fail(
                "HTTP client did not send the exact manifest bytes: "
                f"expected {self.expected_size}/{self.expected_digest}, "
                f"sent {self.size}/{actual_digest}"
            )


def put_remote_artifact(
    item: dict[str, Any],
    snapshot: Path,
    repository_url: str,
    actor: str,
    token: str,
    attempts: int,
) -> str:
    require_remote_limits(attempts)
    url = remote_url(repository_url, item["path"])
    headers = {
        "Authorization": authorization_header(actor, token),
        "Accept": "application/octet-stream",
        "Content-Length": str(item["size"]),
        "Content-Type": "application/octet-stream",
        "If-None-Match": "*",
        "User-Agent": "casidp-exact-bytes-publisher/1",
    }
    opener = urllib.request.build_opener(SameOriginAuthorizationRedirectHandler())
    last_outcome = "no response"
    for attempt in range(attempts):
        with StreamingUploadBody(snapshot, item["size"], item["sha256"]) as body:
            request = urllib.request.Request(
                url,
                data=body,
                headers=headers,
                method="PUT",
            )
            try:
                with opener.open(request, timeout=60) as response:
                    status = response.getcode()
                body.verify_complete()
                if status != 201:
                    fail(
                        "Conditional package PUT did not prove creation of a new path: "
                        f"{item['path']} returned HTTP {status}, expected 201"
                    )
                readback_status, detail = inspect_remote_artifact(
                    item,
                    repository_url,
                    actor,
                    token,
                    attempts,
                    MissingResponsePolicy.KNOWN_PRESENT,
                )
                if readback_status == "EXACT":
                    return "EXACT"
                raise KnownPresentArtifactError(item["path"], readback_status, detail)
            except urllib.error.HTTPError as error:
                status_code = error.code
                retry_after = retry_after_seconds(error.headers)
                error.close()
                if status_code == 412:
                    status, detail = inspect_remote_artifact(
                        item,
                        repository_url,
                        actor,
                        token,
                        attempts,
                        MissingResponsePolicy.KNOWN_PRESENT,
                    )
                    if status == "EXACT":
                        return "EXACT"
                    raise KnownPresentArtifactError(item["path"], status, detail)
                if status_code not in RETRYABLE_UPLOAD_STATUS_CODES:
                    fail(
                        f"Conditional package PUT failed for {item['path']}: "
                        f"HTTP {status_code}"
                    )
                last_outcome = f"HTTP {status_code}"
            except (http.client.HTTPException, OSError, urllib.error.URLError) as error:
                retry_after = None
                last_outcome = type(error).__name__
        if attempt + 1 < attempts:
            wait_before_retry(attempt, retry_after)
    raise RemoteTransientError(
        f"Unable to upload {item['path']} after {attempts} bounded attempts: "
        f"{last_outcome}"
    )


def prepare_publication_evidence(
    manifest_path: Path,
    release_dir_argument: Path,
    repository_url: str,
    verified_evidence: dict[Path, str],
) -> dict[str, Any]:
    release_dir = release_directory(release_dir_argument)
    expected_manifest = confined_regular_file(release_dir, RELEASE_MANIFEST_NAME)
    if manifest_path != expected_manifest:
        fail(
            "Publication manifest must be the audited manifest inside the release directory: "
            f"{expected_manifest}"
        )
    checksums_path = confined_regular_file(release_dir, CHECKSUMS_NAME)

    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        fail("GITHUB_RUN_ID must identify the GitHub Actions publication run")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if run_attempt and not re.fullmatch(r"[1-9][0-9]*", run_attempt):
        fail("GITHUB_RUN_ATTEMPT must be a positive integer when present")

    workflow: dict[str, str] = {"runId": run_id}
    optional_workflow_fields = {
        "runAttempt": "GITHUB_RUN_ATTEMPT",
        "repository": "GITHUB_REPOSITORY",
        "commit": "GITHUB_SHA",
        "ref": "GITHUB_REF",
        "workflowRef": "GITHUB_WORKFLOW_REF",
    }
    for field, environment_name in optional_workflow_fields.items():
        value = os.environ.get(environment_name, "")
        if value:
            workflow[field] = value

    predicate_path = release_dir / "casidp-publication.json"
    if predicate_path.is_dir():
        fail(f"Publication completion predicate path is a directory: {predicate_path}")
    predicate_path.unlink(missing_ok=True)
    return {
        "predicatePath": predicate_path,
        "manifestPath": manifest_path,
        "manifestSha256": sha256_file(manifest_path),
        "checksumsPath": checksums_path,
        "checksumsSha256": sha256_file(checksums_path),
        "verifiedEvidence": verified_evidence,
        "repository": repository_url.rstrip("/"),
        "workflow": workflow,
    }


def write_publication_evidence(context: dict[str, Any], artifact_count: int) -> None:
    manifest_path = context["manifestPath"]
    checksums_path = context["checksumsPath"]
    if sha256_file(manifest_path) != context["manifestSha256"]:
        fail("Release manifest changed while publication was in progress")
    if sha256_file(checksums_path) != context["checksumsSha256"]:
        fail("Aggregate release checksums changed while publication was in progress")
    for path, expected_digest in context["verifiedEvidence"].items():
        if not path.is_file() or path.is_symlink() or sha256_file(path) != expected_digest:
            fail(f"Signed release evidence changed while publication was in progress: {path}")
    stable_json_atomic(
        context["predicatePath"],
        {
            "schemaVersion": 1,
            "publication": {
                "artifactCount": artifact_count,
                "repository": context["repository"],
                "state": RemotePublicationState.COMPLETE_EXACT.value,
            },
            "evidence": {
                "releaseManifest": {
                    "path": manifest_path.name,
                    "sha256": context["manifestSha256"],
                },
                "sha256Sums": {
                    "path": checksums_path.name,
                    "sha256": context["checksumsSha256"],
                },
            },
            "workflow": context["workflow"],
        },
    )


def publish_remote(args: argparse.Namespace) -> None:
    manifest_argument = Path(args.manifest).absolute()
    if manifest_argument.is_symlink():
        fail(f"Release manifest must not be a symbolic link: {manifest_argument}")
    manifest_path = manifest_argument.resolve()
    manifest, artifacts = load_manifest_artifacts(manifest_path)
    validate_publish_manifest(manifest, artifacts, args.repository_url)
    verified_evidence = verify_publication_candidate(
        manifest_path,
        Path(args.release_dir),
        manifest,
        artifacts,
    )
    evidence_context = prepare_publication_evidence(
        manifest_path,
        Path(args.release_dir),
        args.repository_url,
        verified_evidence,
    )
    if sha256_file(manifest_path) != evidence_context["manifestSha256"]:
        fail("Release manifest changed while it was being verified")
    actor, token = github_credentials()
    initial_state, initial_details = preflight_remote_publication(
        artifacts,
        args.repository_url,
        actor,
        token,
        args.workers,
        args.attempts,
    )
    if initial_state == RemotePublicationState.COMPLETE_EXACT:
        verify_local_artifacts(Path(args.release_dir), artifacts)
        write_publication_evidence(evidence_context, len(artifacts))
        print(
            f"Recovered COMPLETE_EXACT publication with {len(artifacts)} "
            "already-published manifest files"
        )
        return
    if initial_state != RemotePublicationState.ABSENT:
        fail(
            f"Remote publication state is {initial_state.value}; refusing every PUT: "
            f"{initial_details[:20]}"
        )

    upload_failures: list[str] = []
    confirmed_exact: set[str] = set()
    known_present: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="casidp-exact-bytes-") as temporary_directory:
        snapshots = snapshot_local_artifacts(
            Path(args.release_dir),
            artifacts,
            Path(temporary_directory),
        )
        # A path must be read back exactly before another irreversible PUT begins.
        # This preserves the strongest possible stop boundary for a non-atomic
        # multi-module publication.
        for item, snapshot in snapshots:
            path = item["path"]
            try:
                outcome = put_remote_artifact(
                    item,
                    snapshot,
                    args.repository_url,
                    actor,
                    token,
                    args.attempts,
                )
                if outcome != "EXACT":
                    fail(f"Unexpected conditional PUT outcome for {path}: {outcome}")
                confirmed_exact.add(path)
                known_present.add(path)
            except KnownPresentArtifactError as error:
                known_present.add(error.path)
                upload_failures.append(f"{path}: {error}")
                break
            except (AuditError, OSError, urllib.error.URLError) as error:
                # Any failed PUT may have reached the service even when its response
                # was lost. A subsequent 404 is therefore never proof of absence.
                known_present.add(path)
                upload_failures.append(f"{path}: {error}")
                break

    final_state, final_details = confirm_remote_publication(
        artifacts,
        args.repository_url,
        actor,
        token,
        args.workers,
        args.attempts,
        confirmed_exact,
        known_present,
    )
    if final_state != RemotePublicationState.COMPLETE_EXACT:
        fail(
            "Exact-bytes publication did not reach COMPLETE_EXACT; "
            f"state={final_state.value}, upload failures={upload_failures[:20]}, "
            f"remote details={final_details[:20]}"
        )
    verify_local_artifacts(Path(args.release_dir), artifacts)
    write_publication_evidence(evidence_context, len(artifacts))
    if upload_failures:
        print(
            "Recovered COMPLETE_EXACT after ambiguous upload responses; "
            f"verified {len(artifacts)} manifest files"
        )
    else:
        print(f"Published and read back {len(artifacts)} exact manifest files")


def check_remote_absent(args: argparse.Namespace) -> None:
    manifest, artifacts = load_manifest_artifacts(Path(args.manifest).resolve())
    validate_publish_manifest(manifest, artifacts, args.repository_url)
    actor, token = github_credentials()
    state, details = preflight_remote_publication(
        artifacts,
        args.repository_url,
        actor,
        token,
        args.workers,
        args.attempts,
    )
    if state != RemotePublicationState.ABSENT:
        fail(
            f"Release version is not ABSENT in GitHub Packages: "
            f"state={state.value}, details={details[:20]}"
        )
    print(f"Verified all {len(artifacts)} candidate paths are unused in GitHub Packages")


def verify_remote(args: argparse.Namespace) -> None:
    manifest, artifacts = load_manifest_artifacts(Path(args.manifest).resolve())
    validate_publish_manifest(manifest, artifacts, args.repository_url)
    actor, token = github_credentials()
    state, details = confirm_remote_publication(
        artifacts,
        args.repository_url,
        actor,
        token,
        args.workers,
        args.attempts,
        set(),
        set(),
    )
    if state != RemotePublicationState.COMPLETE_EXACT:
        fail(
            "GitHub Packages read-back verification did not reach COMPLETE_EXACT: "
            f"state={state.value}, details={details[:20]}"
        )
    print(f"Read back and verified {len(artifacts)} GitHub Packages files")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subcommands = root.add_subparsers(dest="command", required=True)

    graph = subcommands.add_parser("audit-task-graph")
    graph.add_argument("--log", required=True)
    graph.add_argument("--settings", required=True)
    graph.add_argument("--output", required=True)
    graph.set_defaults(handler=audit_task_graph)

    repository = subcommands.add_parser("audit-repository")
    repository.add_argument("--repository", required=True)
    repository.add_argument("--release-dir", required=True)
    repository.add_argument("--task-graph", required=True)
    repository.add_argument("--group", required=True)
    repository.add_argument("--version", required=True)
    repository.add_argument("--fork-commit", required=True)
    repository.add_argument("--upstream-version", required=True)
    repository.add_argument("--upstream-commit", required=True)
    repository.add_argument("--fork-repository", required=True)
    repository.add_argument("--package-repository", required=True)
    repository.add_argument("--resolved-sbom", required=True)
    repository.add_argument("--require-signatures", action="store_true")
    repository.set_defaults(handler=audit_repository)

    candidate = subcommands.add_parser("verify-candidate")
    candidate.add_argument("--release-dir", required=True)
    candidate.add_argument("--group", required=True)
    candidate.add_argument("--version", required=True)
    candidate.add_argument("--fork-commit", required=True)
    candidate.set_defaults(handler=verify_candidate)

    tests = subcommands.add_parser("audit-test-results")
    tests.add_argument(
        "--result",
        action="append",
        required=True,
        help="JUnit XML path and exact test count, formatted as path:count",
    )
    tests.set_defaults(handler=audit_test_results)

    absent = subcommands.add_parser("check-remote-absent")
    absent.add_argument("--manifest", required=True)
    absent.add_argument("--repository-url", required=True)
    absent.add_argument("--workers", type=int, default=8)
    absent.add_argument("--attempts", type=int, default=5)
    absent.set_defaults(handler=check_remote_absent)

    remote = subcommands.add_parser("verify-remote")
    remote.add_argument("--manifest", required=True)
    remote.add_argument("--repository-url", required=True)
    remote.add_argument("--workers", type=int, default=8)
    remote.add_argument("--attempts", type=int, default=5)
    remote.set_defaults(handler=verify_remote)

    publish = subcommands.add_parser("publish-remote")
    publish.add_argument("--manifest", required=True)
    publish.add_argument("--release-dir", required=True)
    publish.add_argument("--repository-url", required=True)
    publish.add_argument("--workers", type=int, default=8)
    publish.add_argument("--attempts", type=int, default=5)
    publish.set_defaults(handler=publish_remote)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (AuditError, KeyError, OSError, ValueError, urllib.error.URLError) as error:
        print(f"CAS-IDP supply-chain audit failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
