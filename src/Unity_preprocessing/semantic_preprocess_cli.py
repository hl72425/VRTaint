#!/usr/bin/env python3
"""Project-neutral Unity preprocessing interface for semantic CodeQL.

This wrapper reuses UnityScenePreprocessor's parser classes while fixing its
batch-only CLI, output placement, scene coverage, and GUID path normalization.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

from UnityScenePreprocessor import GUIDRegistry, UnitySceneParser

EXCLUDED_DIRS = {"Library", "Temp", "obj", "bin", ".git", ".vs"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_sha256(project: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.relative_to(project).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def normalize_ir_paths(value: object, project: Path) -> object:
    if isinstance(value, list):
        return [normalize_ir_paths(item, project) for item in value]
    if isinstance(value, dict):
        out: dict[str, object] = {}
        for key, item in value.items():
            if key in {"script_path", "prefab_path"} and isinstance(item, str) and item:
                candidate = Path(item)
                try:
                    item = candidate.resolve().relative_to(project).as_posix()
                except (OSError, ValueError):
                    item = item.replace("\\", "/")
            out[str(key)] = normalize_ir_paths(item, project)
        return out
    return value


def project_files(root: Path, suffix: str):
    assets = root / "Assets"
    if not assets.is_dir():
        return
    for path in assets.rglob(f"*{suffix}"):
        if not EXCLUDED_DIRS.intersection(path.relative_to(root).parts):
            yield path


def build_registry(project: Path) -> tuple[GUIDRegistry, list[tuple[str, str]]]:
    registry = GUIDRegistry()
    rows: list[tuple[str, str]] = []
    guid_re = re.compile(rb"^guid:\s*([0-9a-fA-F]+)\s*$", re.MULTILINE)
    for meta in project_files(project, ".meta") or []:
        try:
            match = guid_re.search(meta.read_bytes())
        except OSError:
            continue
        if not match:
            continue
        guid = match.group(1).decode("ascii").lower()
        asset = meta.with_suffix("")
        # The reused parser needs an on-disk path; consumers need a stable
        # project-relative path, so both representations are retained.
        registry.add(str(asset.resolve()), guid)
        rows.append((guid, asset.relative_to(project).as_posix()))
    return registry, sorted(rows)


def enabled_build_scenes(project: Path) -> list[Path]:
    settings = project / "ProjectSettings" / "EditorBuildSettings.asset"
    if not settings.is_file():
        return []
    text = settings.read_text(encoding="utf-8-sig", errors="replace")
    paths = re.findall(
        r"-\s+enabled:\s*1\s*\r?\n\s*path:\s*(Assets/[^\r\n]+\.unity)\s*$",
        text, re.MULTILINE)
    return [(project / Path(value.strip())).resolve() for value in paths
            if (project / Path(value.strip())).is_file()]


def analyze(project: Path, scene_scope: str) -> tuple[
        dict[str, object], list[tuple[str, str]], list[dict[str, str]], str]:
    registry, guid_rows = build_registry(project)
    parser = UnitySceneParser(registry)
    results: dict[str, object] = {}
    errors: list[dict[str, str]] = []
    build_scenes = enabled_build_scenes(project)
    effective_scope = scene_scope
    if scene_scope == "build" and build_scenes:
        scenes = sorted(build_scenes)
    else:
        scenes = sorted(project_files(project, ".unity") or [])
        if scene_scope == "build":
            effective_scope = "all-fallback-no-enabled-build-scenes"
    for scene in scenes:
        key = scene.relative_to(project).as_posix()
        try:
            results[key] = normalize_ir_paths(parser.parse_scene(str(scene)), project)
        except Exception as exc:  # retain per-file evidence instead of aborting corpus runs
            errors.append({"scene": key, "error": repr(exc)})
    return results, guid_rows, errors, effective_scope


def main() -> int:
    cli = argparse.ArgumentParser(description="Unity preprocessing API v1")
    cli.add_argument("--project-root", required=True, type=Path)
    cli.add_argument("--unity-analysis-output", required=True, type=Path)
    cli.add_argument("--guid-mapping-output", required=True, type=Path)
    cli.add_argument("--manifest-output", required=True, type=Path)
    cli.add_argument("--scene-scope", choices=("build", "all"), default="build",
                     help="enabled build scenes by default; all scans every Assets/**/*.unity")
    args = cli.parse_args()
    project = args.project_root.resolve()
    if not (project / "Assets").is_dir():
        raise FileNotFoundError(f"Assets directory missing: {project}")
    results, guid_rows, errors, effective_scope = analyze(project, args.scene_scope)
    for path in (args.unity_analysis_output, args.guid_mapping_output, args.manifest_output):
        path.parent.mkdir(parents=True, exist_ok=True)
    args.unity_analysis_output.write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    with args.guid_mapping_output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["GUID", "AssetPath"])
        writer.writerows(guid_rows)
    scene_inputs = sorted(project_files(project, ".unity") or [])
    meta_inputs = sorted(project_files(project, ".meta") or [])
    manifest = {
        "schema": "unity-preprocess/v1", "backend": "UnityScenePreprocessor",
        "project_root": str(project), "scene_count": len(results),
        "requested_scene_scope": args.scene_scope, "effective_scene_scope": effective_scope,
        "guid_count": len(guid_rows), "error_count": len(errors), "errors": errors,
        "unity_file_count": len(scene_inputs), "meta_file_count": len(meta_inputs),
        "unity_inventory_sha256": inventory_sha256(project, scene_inputs),
        "meta_inventory_sha256": inventory_sha256(project, meta_inputs),
        "unity_analysis": str(args.unity_analysis_output.resolve()),
        "unity_analysis_sha256": sha256(args.unity_analysis_output),
        "guid_mapping": str(args.guid_mapping_output.resolve()),
        "guid_mapping_sha256": sha256(args.guid_mapping_output),
    }
    args.manifest_output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False))
    return 0 if not errors else 2


if __name__ == "__main__":
    sys.exit(main())
