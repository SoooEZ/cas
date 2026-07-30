#!/usr/bin/env python3
"""Fail-closed supply-chain checks for the CAS-IDP CAS 8 fork.

The script intentionally uses only the Python standard library so the release
workflow does not need to download and execute another package manager's code.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any


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


class AuditError(RuntimeError):
    """A release invariant was violated."""


def fail(message: str) -> None:
    raise AuditError(message)


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
    tasks: dict[str, set[str]] = defaultdict(set)
    for match in PUBLICATION_TASK.finditer(log):
        project_path, publication = match.groups()
        publications[project_path].add(publication)
        tasks[project_path].add(match.group(0).split()[0].removeprefix(">"))

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
        if not path.is_file() or path.is_symlink():
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


def audit_resolved_sbom(
    source: Path,
    destination: Path,
    group: str,
    version: str,
    expected_artifacts: set[str],
) -> None:
    """Audit and preserve the official CycloneDX Gradle plugin output."""
    try:
        sbom = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"Invalid resolved CycloneDX JSON {source}: {error}")

    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6":
        fail("Resolved SBOM must be CycloneDX JSON using schema version 1.6")
    if not isinstance(sbom.get("version"), int) or sbom["version"] < 1:
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

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def audit_repository(args: argparse.Namespace) -> None:
    repository = Path(args.repository).resolve()
    release_dir = Path(args.release_dir).resolve()
    task_graph_path = Path(args.task_graph).resolve()
    if not repository.is_dir():
        fail(f"Staged Maven repository does not exist: {repository}")

    graph = json.loads(task_graph_path.read_text(encoding="utf-8"))
    expected_artifacts = {project["artifactId"] for project in graph["projects"]}
    files = version_files(repository, args.group, args.version)

    pom_paths = [path for path in files if path.suffix == ".pom"]
    poms: list[dict[str, Any]] = []
    actual_artifacts: set[str] = set()
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
        poms.append(pom)
        actual_artifacts.add(pom["artifact"])

    missing = sorted(expected_artifacts - actual_artifacts)
    unexpected = sorted(actual_artifacts - expected_artifacts)
    if missing or unexpected:
        fail(f"Staged POM graph is incomplete; missing={missing}, unexpected={unexpected}")
    absent_required = sorted(REQUIRED_ARTIFACTS - actual_artifacts)
    if absent_required:
        fail(f"Required artifacts are absent from staging: {absent_required}")

    group_root = repository.joinpath(*args.group.split("."))
    main_binaries: set[Path] = set()
    for project in graph["projects"]:
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

    sbom_path = release_dir / "casidp.cdx.json"
    audit_resolved_sbom(
        Path(args.resolved_sbom).resolve(),
        sbom_path,
        args.group,
        args.version,
        expected_artifacts,
    )

    manifest_path = release_dir / "casidp-release-manifest.json"
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
            "partialFailurePolicy": "Burn the version; never overwrite it; release the next casidp.N version.",
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
    checksums_path = release_dir / "SHA256SUMS"
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
    manifest_path = release_dir / "casidp-release-manifest.json"
    checksums_path = release_dir / "SHA256SUMS"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

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

    manifest_artifacts = {item["path"]: item["sha256"] for item in manifest["artifacts"]}
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


def request_bytes(url: str, actor: str, token: str, attempts: int, allow_missing: bool) -> bytes | None:
    headers = {
        "Authorization": authorization_header(actor, token),
        "Accept": "application/octet-stream",
        "User-Agent": "casidp-release-auditor/1",
    }
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404 and allow_missing:
                return None
            if error.code not in {404, 408, 429, 500, 502, 503, 504}:
                raise
            last_error = error
        except urllib.error.URLError as error:
            last_error = error
        if attempt + 1 < attempts:
            time.sleep(min(2**attempt, 8))
    if allow_missing and isinstance(last_error, urllib.error.HTTPError) and last_error.code == 404:
        return None
    raise AuditError(f"Unable to read {url}: {last_error}")


def load_manifest_artifacts(manifest_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts = manifest.get("artifacts", [])
    if not artifacts:
        fail("Release manifest contains no artifacts")
    return manifest, artifacts


def remote_url(base_url: str, artifact_path: str) -> str:
    relative = artifact_path.removeprefix("repository/")
    return f"{base_url.rstrip('/')}/{urllib.parse.quote(relative, safe='/.-_~')}"


def check_remote_absent(args: argparse.Namespace) -> None:
    _, artifacts = load_manifest_artifacts(Path(args.manifest).resolve())
    artifact_paths = sorted(item["path"] for item in artifacts)

    collisions: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                request_bytes,
                remote_url(args.repository_url, path),
                args.actor,
                args.token,
                2,
                True,
            ): path
            for path in artifact_paths
        }
        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            if future.result() is not None:
                collisions.append(path)
    if collisions:
        fail(
            "Release version already exists in GitHub Packages and must never be overwritten: "
            f"{sorted(collisions)[:20]}"
        )
    print(f"Verified all {len(artifact_paths)} candidate paths are unused in GitHub Packages")


def verify_remote(args: argparse.Namespace) -> None:
    _, artifacts = load_manifest_artifacts(Path(args.manifest).resolve())
    failures: list[str] = []

    def verify(item: dict[str, Any]) -> str | None:
        url = remote_url(args.repository_url, item["path"])
        contents = request_bytes(url, args.actor, args.token, args.attempts, False)
        assert contents is not None
        actual = hashlib.sha256(contents).hexdigest()
        if actual != item["sha256"]:
            return f"{item['path']}: expected {item['sha256']}, got {actual}"
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(verify, item) for item in artifacts]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                failures.append(result)
    if failures:
        fail(f"GitHub Packages read-back verification failed: {failures[:20]}")
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
    absent.add_argument("--actor", required=True)
    absent.add_argument("--token", required=True)
    absent.add_argument("--workers", type=int, default=8)
    absent.set_defaults(handler=check_remote_absent)

    remote = subcommands.add_parser("verify-remote")
    remote.add_argument("--manifest", required=True)
    remote.add_argument("--repository-url", required=True)
    remote.add_argument("--actor", required=True)
    remote.add_argument("--token", required=True)
    remote.add_argument("--workers", type=int, default=8)
    remote.add_argument("--attempts", type=int, default=5)
    remote.set_defaults(handler=verify_remote)
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
