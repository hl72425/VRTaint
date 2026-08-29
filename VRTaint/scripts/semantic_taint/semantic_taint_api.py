#!/usr/bin/env python3
"""Stable project-neutral interface for Unity semantic CodeQL enrichment."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path


EXCLUDED_PARTS = {"Library", "PackageCache", "Temp", "obj", "bin", ".git"}


def discover(project: Path, explicit: Path | None, name: str) -> Path | None:
    if explicit:
        result = explicit.resolve()
        if not result.is_file():
            raise FileNotFoundError(result)
        return result
    direct = project / name
    if direct.exists():
        return direct.resolve()
    matches = [path for path in project.rglob(name)
               if not EXCLUDED_PARTS.intersection(path.relative_to(project).parts)]
    if len(matches) == 1:
        return matches[0].resolve()
    if len(matches) > 1:
        raise FileNotFoundError(
            f"expected one {name}, found {len(matches)}; pass its explicit CLI option")
    return None


def run_repository_preprocessor(project: Path, generated: Path, stamp: str,
                                pack_root: Path, scene_scope: str) -> tuple[Path, Path, Path]:
    preprocessor = (pack_root.resolve().parents[1] / "src" / "Unity_preprocessing" /
                    "semantic_preprocess_cli.py")
    if not preprocessor.is_file():
        raise FileNotFoundError(preprocessor)
    ir = generated / f"{stamp}_auto_unity_analysis_v001.json"
    guid = generated / f"{stamp}_auto_guid_mapping_v001.csv"
    manifest = generated / f"{stamp}_preprocess_manifest_v001.json"
    proc = subprocess.run([
        sys.executable, str(preprocessor), "--project-root", str(project),
        "--unity-analysis-output", str(ir), "--guid-mapping-output", str(guid),
        "--manifest-output", str(manifest), "--scene-scope", scene_scope,
    ], text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE,
       stderr=subprocess.STDOUT)
    (generated / f"{stamp}_preprocess_log_v001.txt").write_text(
        proc.stdout, encoding="utf-8")
    if proc.returncode:
        raise RuntimeError(f"repository preprocessor exited {proc.returncode}")
    return ir, guid, manifest


def main() -> int:
    p = argparse.ArgumentParser(description="Generic Unity semantic CodeQL interface v1")
    p.add_argument("--project-root", required=True, type=Path)
    p.add_argument("--project-id",
                   help="stable repository/project identifier; defaults to project-root basename")
    p.add_argument("--codeql-database", required=True, type=Path)
    p.add_argument("--output-root", required=True, type=Path)
    p.add_argument("--unity-analysis", type=Path)
    p.add_argument("--guid-mapping", type=Path)
    p.add_argument("--regenerate-inputs", action="store_true",
                   help="ignore discoverable IR/GUID files and rebuild generic inputs")
    p.add_argument("--scene-scope", choices=("build", "all"), default="build",
                   help="scope used when preprocessing is generated")
    p.add_argument("--pack-root", type=Path,
                   default=Path(__file__).resolve().parents[2])
    p.add_argument("--skip-security", action="store_true")
    p.add_argument("--unity-security-only", action="store_true",
                   help="omit the broad official suite but keep VRTaint security queries")
    p.add_argument("--javascript-database", type=Path,
                   help="optional JS/TS CodeQL database for companion web/server code")
    p.add_argument("--privacy-python-only", action="store_true")
    a = p.parse_args()
    project = a.project_root.resolve()
    project_id = a.project_id or project.name
    output = a.output_root.resolve()
    generated = output / "intermediate" / "generated_inputs"
    generated.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ir = None if a.regenerate_inputs and not a.unity_analysis else discover(
        project, a.unity_analysis, "unity_analysis.json")
    guid = None if a.regenerate_inputs and not a.guid_mapping else discover(
        project, a.guid_mapping, "guid_mapping.csv")
    generated_ir = ir is None
    generated_guid = guid is None
    preprocess_manifest = None
    preprocessor_backend = "precomputed"
    if ir is None or guid is None:
        generated_ir_path, generated_guid_path, preprocess_manifest = run_repository_preprocessor(
            project, generated, stamp, a.pack_root, a.scene_scope)
        preprocessor_backend = "src/Unity_preprocessing/semantic_preprocess_cli.py"
        if ir is None:
            ir = generated_ir_path
        if guid is None:
            guid = generated_guid_path
    runner = a.pack_root / "scripts" / "semantic_taint" / "semantic_taint_runner.py"
    command = [sys.executable, str(runner), "--project-root", str(project),
               "--project-id", project_id,
               "--unity-analysis", str(ir), "--guid-mapping", str(guid),
               "--codeql-database", str(a.codeql_database.resolve()),
               "--pack-root", str(a.pack_root.resolve()),
               "--output-root", str(output)]
    if a.skip_security:
        command.append("--skip-security")
    if a.unity_security_only:
        command.append("--unity-security-only")
    if a.javascript_database:
        command.extend(["--javascript-database", str(a.javascript_database.resolve())])
    proc = subprocess.run(command)
    privacy_command = [
        sys.executable, str(a.pack_root / "scripts" / "semantic_taint" /
                            "unity_privacy_flow_analyzer.py"),
        "--project-root", str(project), "--project-id", project_id,
        "--output-root", str(output / "results" / "privacy"),
    ]
    if a.privacy_python_only:
        privacy_command.append("--emit-python-only")
    privacy_proc = subprocess.run(privacy_command)
    manifest = {
        "api": "unity-semantic-codeql/v2", "project_root": str(project),
        "project_id": project_id,
        "unity_analysis": str(ir), "unity_analysis_generated": generated_ir,
        "guid_mapping": str(guid), "guid_mapping_generated": generated_guid,
        "regenerate_inputs": a.regenerate_inputs,
        "scene_scope": a.scene_scope,
        "preprocessor_backend": preprocessor_backend,
        "preprocess_manifest": str(preprocess_manifest) if preprocess_manifest else None,
        "codeql_database": str(a.codeql_database.resolve()),
        "javascript_database": str(a.javascript_database.resolve()) if a.javascript_database else None,
        "security_architecture": {
            "official_suite": not a.skip_security and not a.unity_security_only,
            "vrtaint_flow_suite": not a.skip_security,
            "five_tuple_enrichment": not a.skip_security,
            "privacy_companion": True,
        },
        "privacy_outputs": str(output / "results" / "privacy"),
        "privacy_exit_code": privacy_proc.returncode,
        "output_root": str(output),
        "exit_code": proc.returncode if proc.returncode else privacy_proc.returncode,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "interface_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return proc.returncode if proc.returncode else privacy_proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
