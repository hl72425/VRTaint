#!/usr/bin/env python3
"""Run out-of-box Native CodeQL and Semgrep baselines for the 18-finding oracle."""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import time
import shutil
import zipfile
import posixpath
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


RUN_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = RUN_ROOT / "intermediate" / "finding_manifest.csv"
CODEQL = Path(r"tools\codeql-cli\codeql.exe")
SUITE = "codeql/csharp-queries:codeql-suites/csharp-security-and-quality.qls"
SEMGREP_CSHARP = RUN_ROOT / "intermediate" / "semgrep_p_csharp.json"
SEMGREP_TYPESCRIPT = RUN_ROOT / "intermediate" / "semgrep_p_typescript.json"
SEMGREP_PYTHON = RUN_ROOT / "intermediate" / "semgrep_p_python.json"


def rows() -> list[dict[str, str]]:
    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def run_logged(cmd: list[str], log: Path, env: dict[str, str] | None = None) -> tuple[int, float]:
    log.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    with log.open("w", encoding="utf-8", errors="replace") as out:
        out.write("COMMAND: " + subprocess.list2cmdline(cmd) + "\n\n")
        out.flush()
        p = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, check=False, env=env)
    return p.returncode, time.monotonic() - start


def native_one(row: dict[str, str]) -> dict[str, object]:
    fid = row["id"]
    out = RUN_ROOT / "intermediate" / "native_codeql" / f"{fid}.sarif"
    log = RUN_ROOT / "logs" / "native_codeql" / f"{fid}.log"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.is_file() and out.stat().st_size > 100:
        return {"id": fid, "tool": "Native CodeQL", "exit_code": 0, "seconds": 0, "status": "resumed", "output": str(out)}
    cmd = [
        str(CODEQL), "database", "analyze", row["database"], SUITE,
        "--format=sarif-latest", f"--output={out}", "--ram=3072", "--threads=2", "--rerun",
    ]
    code, elapsed = run_logged(cmd, log)
    return {"id": fid, "tool": "Native CodeQL", "exit_code": code, "seconds": round(elapsed, 1),
            "status": "ok" if code == 0 and out.is_file() else "failed", "output": str(out), "log": str(log)}


def semgrep_one(row: dict[str, str]) -> dict[str, object]:
    fid = row["id"]
    out = RUN_ROOT / "intermediate" / "semgrep_equal_corpus" / f"{fid}.json"
    log = RUN_ROOT / "logs" / "semgrep_equal_corpus" / f"{fid}.log"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.is_file() and out.stat().st_size > 100:
        return {"id": fid, "tool": "Semgrep", "exit_code": 0, "seconds": 0, "status": "resumed", "output": str(out)}
    # Use the CodeQL source archive as the shared C# corpus.  This avoids scanning
    # Unity binary/assets that were never extracted into the CodeQL database.
    scan_root = RUN_ROOT / "intermediate" / "semgrep_inputs_flat_v2" / fid
    marker = scan_root / ".prepared"
    prep_version = "flattened-codeql-src-v2"
    if not marker.exists() or marker.read_text(encoding="utf-8", errors="replace").strip() != prep_version:
        if scan_root.exists():
            shutil.rmtree(scan_root)
        scan_root.mkdir(parents=True)
        src_zip = Path(row["database"]) / "src.zip"
        with zipfile.ZipFile(src_zip) as zf:
            names = [x.filename for x in zf.infolist() if not x.is_dir()]
            common = posixpath.commonpath(names) if names else ""
            if common and "." in posixpath.basename(common):
                common = posixpath.dirname(common)
            for info in zf.infolist():
                if info.is_dir():
                    continue
                rel = posixpath.relpath(info.filename, common) if common else info.filename
                if rel == ".." or rel.startswith("../"):
                    continue
                dst = scan_root.joinpath(*Path(rel).parts)
                dst.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, dst.open("wb") as target:
                    shutil.copyfileobj(src, target)
        # Preserve the two source-backed cross-language cases outside C# DBs.
        extras: list[str] = []
        if fid == "S08":
            extras = ["MgrServer/server.ts"]
        elif fid == "P05":
            extras = ["Server/src/config.py", "Server/src/server.py"]
        for rel in extras:
            src = Path(row["source_root"]) / Path(rel)
            if src.is_file():
                dst = scan_root / "cross_language" / Path(rel)
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        marker.write_text(prep_version + "\n", encoding="utf-8")
    configs = [SEMGREP_CSHARP]
    if fid == "S08":
        configs.append(SEMGREP_TYPESCRIPT)
    if fid == "P05":
        configs.append(SEMGREP_PYTHON)
    config_args = [arg for config in configs for arg in ("--config", str(config))]
    cmd = [
        "semgrep", "scan", *config_args, "--json", "--metrics=off", "--no-git-ignore",
        "--jobs=2", "--timeout=2", "--timeout-threshold=1", "--max-target-bytes=200000",
        "--exclude=Library", "--exclude=Temp", "--exclude=Logs", "--exclude=obj",
        "--exclude=bin", "--exclude=Packages", "--exclude=.git", "--output", str(out), str(scan_root),
    ]
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    code, elapsed = run_logged(cmd, log, env)
    return {"id": fid, "tool": "Semgrep", "exit_code": code, "seconds": round(elapsed, 1),
            "status": "ok" if code == 0 and out.is_file() else "failed", "output": str(out), "log": str(log)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", choices=("native", "semgrep", "both"), default="both")
    ap.add_argument("--workers", type=int, default=3)
    args = ap.parse_args()
    jobs = rows()
    funcs = []
    if args.tool in ("native", "both"):
        funcs.append(native_one)
    if args.tool in ("semgrep", "both"):
        funcs.append(semgrep_one)
    tasks = [(fn, row) for fn in funcs for row in jobs]
    result_path = RUN_ROOT / "results" / "execution_results.json"
    done: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(fn, row): (fn.__name__, row["id"]) for fn, row in tasks}
        total = len(futures)
        for i, fut in enumerate(as_completed(futures), 1):
            name, fid = futures[fut]
            try:
                result = fut.result()
            except Exception as exc:
                result = {"id": fid, "tool": name, "status": "exception", "error": repr(exc)}
            done.append(result)
            print(f"[{i}/{total}] {result.get('tool')} {fid}: {result.get('status')} ({result.get('seconds', '-')}s)", flush=True)
            result_path.write_text(json.dumps(done, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if all(x.get("status") in ("ok", "resumed") for x in done) else 1


if __name__ == "__main__":
    raise SystemExit(main())
