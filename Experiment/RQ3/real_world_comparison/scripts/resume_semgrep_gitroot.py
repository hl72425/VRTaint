#!/usr/bin/env python3
"""Resume the 18-finding Semgrep baseline on a Windows-friendly flat source corpus.

The rule packs are unchanged.  Only project-owned analyzable source files are
materialized from each CodeQL src.zip, and an explicit mapping preserves their
original archive paths for later oracle matching.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path


STAMP = "20260826_113259"
ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "intermediate" / "finding_manifest.csv"
INPUT_ROOT = ROOT / "intermediate" / "semgrep_inputs_flat_v3"
OUTPUT_ROOT = ROOT / "intermediate" / "semgrep_equal_corpus_v6_gitroot"
LOG_ROOT = ROOT / "logs" / "semgrep_equal_corpus_v6_gitroot"
RESULT_CSV = ROOT / "results" / f"{STAMP}_v006_semgrep_jobs.csv"
CSHARP_CONFIG = ROOT / "intermediate" / "semgrep_p_csharp.json"
TYPESCRIPT_CONFIG = ROOT / "intermediate" / "semgrep_p_typescript.json"
PYTHON_CONFIG = ROOT / "intermediate" / "semgrep_p_python.json"
PREP_VERSION = "codeql-src-csharp-fully-flat-v3"
PROJECT_TIMEOUT_SECONDS = 1800


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def safe_basename(name: str) -> str:
    base = Path(name.replace("\\", "/")).name
    return re.sub(r"[^A-Za-z0-9_.-]", "_", base) or "source.cs"


def prepare(row: dict[str, str]) -> tuple[Path, int, Path]:
    finding_id = row["id"]
    target = INPUT_ROOT / finding_id
    marker = target / ".prepared"
    mapping_path = target / "20260826_072713_v003_source_mapping.csv"
    if marker.is_file() and marker.read_text(encoding="utf-8", errors="replace").strip() == PREP_VERSION:
        subprocess.run(["git", "-C", str(target), "init", "-q"], check=True)
        return target, max(0, len(read_csv(mapping_path))), mapping_path

    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    source_dir = target / "src"
    source_dir.mkdir()
    source_zip = Path(row["database"]) / "src.zip"
    mapping: list[dict[str, object]] = []
    counter = 0
    with zipfile.ZipFile(source_zip) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".cs"):
                continue
            counter += 1
            flat_name = f"{counter:06d}_{safe_basename(info.filename)}"
            destination = source_dir / flat_name
            with archive.open(info) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            mapping.append({
                "finding_id": finding_id,
                "flat_path": str(destination),
                "original_path": info.filename,
                "language": "csharp",
            })

    extras: list[tuple[str, str]] = []
    if finding_id == "S08":
        extras = [("MgrServer/server.ts", "typescript")]
    elif finding_id == "P05":
        extras = [("Server/src/config.py", "python"), ("Server/src/server.py", "python")]
    for relative, language in extras:
        source = Path(row["source_root"]) / Path(relative)
        if not source.is_file():
            continue
        counter += 1
        destination = source_dir / f"{counter:06d}_{safe_basename(relative)}"
        shutil.copy2(source, destination)
        mapping.append({
            "finding_id": finding_id,
            "flat_path": str(destination),
            "original_path": str(source),
            "language": language,
        })

    write_csv(mapping_path, mapping)
    marker.write_text(PREP_VERSION + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(target), "init", "-q"], check=True)
    return target, len(mapping), mapping_path


def finding_count(path: Path) -> int:
    if not path.is_file() or path.stat().st_size == 0:
        return 0
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
        return len(document.get("results", []))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return 0


def execute(row: dict[str, str]) -> dict[str, object]:
    finding_id = row["id"]
    output = OUTPUT_ROOT / f"{finding_id}.json"
    log = LOG_ROOT / f"{finding_id}.log"
    output.parent.mkdir(parents=True, exist_ok=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        scan_root, source_files, mapping = prepare(row)
    except Exception as error:
        return {
            "id": finding_id, "project": row["project"], "status": "prepare_failed",
            "exit_code": 125, "elapsed_seconds": round(time.monotonic() - started, 1),
            "source_files": 0, "raw_findings": 0, "output": str(output),
            "mapping": "", "log": str(log), "error": repr(error),
        }

    configs = [CSHARP_CONFIG]
    if finding_id == "S08":
        configs.append(TYPESCRIPT_CONFIG)
    if finding_id == "P05":
        configs.append(PYTHON_CONFIG)
    config_args = [argument for config in configs for argument in ("--config", str(config))]
    command = [
        "pysemgrep", "scan", *config_args, "--json", "--metrics=off", "--no-git-ignore",
        "--jobs=4", "--timeout=15", "--timeout-threshold=5", "--max-target-bytes=2000000",
        "--output", str(output), str(scan_root / "src"),
    ]
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    with log.open("w", encoding="utf-8", errors="replace") as stream:
        stream.write("COMMAND: " + subprocess.list2cmdline(command) + "\n")
        stream.write(f"SOURCE_FILES: {source_files}\nMAPPING: {mapping}\n\n")
        stream.flush()
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, env=environment, cwd=str(scan_root))
        try:
            exit_code = process.wait(timeout=PROJECT_TIMEOUT_SECONDS)
            status = "completed" if exit_code == 0 and output.is_file() else "failed"
        except subprocess.TimeoutExpired:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=stream, stderr=subprocess.STDOUT, check=False,
            )
            exit_code = 124
            status = "timeout"
            stream.write(f"\nTIMEOUT after {PROJECT_TIMEOUT_SECONDS} seconds\n")
    return {
        "id": finding_id, "project": row["project"], "status": status,
        "exit_code": exit_code, "elapsed_seconds": round(time.monotonic() - started, 1),
        "source_files": source_files, "raw_findings": finding_count(output) if exit_code == 0 else 0,
        "output": str(output), "mapping": str(mapping), "log": str(log), "error": "",
    }


def main() -> int:
    manifest_rows = read_csv(MANIFEST)
    previous = read_csv(RESULT_CSV)
    completed = {row["id"]: row for row in previous if row.get("status") == "completed"}
    results: list[dict[str, object]] = list(completed.values())
    total = len(manifest_rows)
    for index, row in enumerate(manifest_rows, 1):
        finding_id = row["id"]
        if finding_id in completed:
            print(f"[{index}/{total}] resume {finding_id}: completed", flush=True)
            continue
        print(f"[{index}/{total}] Semgrep {finding_id} {row['project']}", flush=True)
        result = execute(row)
        results.append(result)
        write_csv(RESULT_CSV, results)
        print(
            f"    status={result['status']} files={result['source_files']} "
            f"raw={result['raw_findings']} seconds={result['elapsed_seconds']}",
            flush=True,
        )
    return 0 if all(row.get("status") == "completed" for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())


