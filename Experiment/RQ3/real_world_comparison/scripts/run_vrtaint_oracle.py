#!/usr/bin/env python3
"""Freshly rerun all VRTaint detectors required by the 18-finding oracle."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OLD = Path(r"query_test/VRTaint/VRTaint_18finding_coverage_20260819_103944_v001")
PACK = Path(r"query_test/VRTaint")
CODEQL = Path(r"codeql")
MANIFEST = OLD / "intermediate" / "20260819_103944_v001_targeted_jobs.csv"
PRIVACY_ANALYZER = PACK / "scripts" / "semantic_taint" / "unity_privacy_flow_analyzer.py"
JS_DB = OLD / "intermediate" / "db-javascript-Boysle_TinkerXR" / "db-javascript"
JS_QUERY = Path(r"codeql-packages/codeql/javascript-queries/2.3.3/Security/CWE-078/CommandInjection.ql")

SKIP = {"S08A", "P01", "P02", "P03", "P04", "P05", "P06"}


def run(cmd: list[str], log: Path) -> tuple[int, float]:
    log.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    with log.open("w", encoding="utf-8", errors="replace") as f:
        f.write("COMMAND: " + subprocess.list2cmdline(cmd) + "\n\n"); f.flush()
        p = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=False)
    return p.returncode, time.monotonic() - start


def decode(bqrs: Path, csv_path: Path, log: Path) -> tuple[int, int]:
    cmd = [str(CODEQL), "bqrs", "decode", "--format=csv", f"--output={csv_path}", str(bqrs)]
    with log.open("a", encoding="utf-8", errors="replace") as f:
        f.write("\nDECODE: " + subprocess.list2cmdline(cmd) + "\n")
        code = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=False).returncode
    if code or not csv_path.is_file():
        return code, 0
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        return code, max(sum(1 for _ in csv.reader(f)) - 1, 0)


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)


def main() -> int:
    run_started = time.monotonic()
    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as f:
        jobs = [x for x in csv.DictReader(f) if x["job_id"] not in SKIP and x["category"] == "security"]
    job_rows: list[dict[str, object]] = []
    out_bqrs = ROOT / "intermediate" / "vrtaint_rerun" / "bqrs"
    out_csv = ROOT / "intermediate" / "vrtaint_rerun" / "csv"
    cache = ROOT / "intermediate" / "vrtaint_rerun" / "cache"
    for d in (out_bqrs, out_csv, cache): d.mkdir(parents=True, exist_ok=True)
    total = len(jobs) + 1 + len(PRIVACY)
    done = 0
    for job in jobs:
        done += 1; jid = job["job_id"]
        print(f"[{done}/{total}] VRTaint CodeQL {jid} {job['project']} {job['query']}", flush=True)
        bqrs, csv_path = out_bqrs / f"{jid}.bqrs", out_csv / f"{jid}.csv"
        log = ROOT / "logs" / "vrtaint_rerun" / f"{jid}.log"
        cmd = [str(CODEQL), "query", "run", f"--database={job['database']}",
               f"--additional-packs={PACK}", f"--common-caches={cache}", "--ram=3072", "--threads=2",
               f"--output={bqrs}", job["query_path"]]
        code, elapsed = run(cmd, log)
        dcode, count = decode(bqrs, csv_path, log) if code == 0 and bqrs.is_file() else (-1, 0)
        job_rows.append({"job_id": jid, "finding_id": job["finding_id"], "tool_stage": "VRTaint-CodeQL",
                         "exit_code": code, "decode_exit_code": dcode, "elapsed_seconds": f"{elapsed:.1f}",
                         "result_rows": count, "detected": count > 0, "artifact": str(csv_path), "log": str(log)})
        write_csv(ROOT / "results" / "vrtaint_rerun_jobs.csv", job_rows)

    done += 1
    print(f"[{done}/{total}] VRTaint companion S08JS Boysle_TinkerXR", flush=True)
    bqrs, csv_path = out_bqrs / "S08JS.bqrs", out_csv / "S08JS.csv"
    log = ROOT / "logs" / "vrtaint_rerun" / "S08JS.log"
    cmd = [str(CODEQL), "query", "run", f"--database={JS_DB}", "--ram=3072", "--threads=2",
           f"--output={bqrs}", str(JS_QUERY)]
    code, elapsed = run(cmd, log)
    dcode, count = decode(bqrs, csv_path, log) if code == 0 and bqrs.is_file() else (-1, 0)
    job_rows.append({"job_id": "S08JS", "finding_id": "S08", "tool_stage": "VRTaint-JS-companion",
                     "exit_code": code, "decode_exit_code": dcode, "elapsed_seconds": f"{elapsed:.1f}",
                     "result_rows": count, "detected": count > 0, "artifact": str(csv_path), "log": str(log)})
    write_csv(ROOT / "results" / "vrtaint_rerun_jobs.csv", job_rows)

    for pid, project_id, project_root, expected in PRIVACY:
        done += 1
        print(f"[{done}/{total}] VRTaint privacy {pid} {project_id}", flush=True)
        output = ROOT / "intermediate" / "vrtaint_rerun" / "privacy" / pid
        output.mkdir(parents=True, exist_ok=True)
        log = ROOT / "logs" / "vrtaint_rerun" / f"{pid}.log"
        cmd = [sys.executable, str(PRIVACY_ANALYZER), "--project-root", project_root,
               "--project-id", project_id, "--output-root", str(output)]
        code, elapsed = run(cmd, log)
        findings_path = output / "privacy_findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8")) if findings_path.is_file() else {"findings": []}
        actual = {x.get("rule_id") for x in findings.get("findings", [])}
        missing = expected - actual
        job_rows.append({"job_id": pid, "finding_id": pid, "tool_stage": "VRTaint-privacy-companion",
                         "exit_code": code, "decode_exit_code": "", "elapsed_seconds": f"{elapsed:.1f}",
                         "result_rows": len(findings.get("findings", [])), "detected": code == 0 and not missing,
                         "artifact": str(findings_path), "log": str(log)})
        write_csv(ROOT / "results" / "vrtaint_rerun_jobs.csv", job_rows)

    detected_jobs = {str(x["job_id"]) for x in job_rows if str(x["detected"]).lower() == "true" or x["detected"] is True}
    finding_rows: list[dict[str, object]] = []
    for fid, required in REQUIRED.items():
        finding_rows.append({"id": fid, "category": "security", "required_jobs": ";".join(sorted(required)),
                             "detected_jobs": ";".join(sorted(required & detected_jobs)), "detected": required <= detected_jobs,
                             "elapsed_seconds": f"{sum(float(x['elapsed_seconds']) for x in job_rows if x['job_id'] in required):.1f}"})
    for pid, *_ in PRIVACY:
        x = next(x for x in job_rows if x["job_id"] == pid)
        finding_rows.append({"id": pid, "category": "privacy", "required_jobs": pid,
                             "detected_jobs": pid if x["detected"] else "", "detected": bool(x["detected"]),
                             "elapsed_seconds": x["elapsed_seconds"]})
    write_csv(ROOT / "results" / "vrtaint_rerun_findings.csv", finding_rows)
    summary = {"tool": "VRTaint targeted 18-finding validation", "finding_count": 18,
               "detected_count": sum(bool(x["detected"]) for x in finding_rows),
               "security_detected": sum(bool(x["detected"]) for x in finding_rows if x["category"] == "security"),
               "privacy_detected": sum(bool(x["detected"]) for x in finding_rows if x["category"] == "privacy"),
               "end_to_end_wall_seconds": round(time.monotonic() - run_started, 1),
               "sum_stage_seconds": round(sum(float(x["elapsed_seconds"]) for x in job_rows), 1)}
    (ROOT / "results" / "vrtaint_rerun_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return 0 if summary["detected_count"] == 18 else 1


if __name__ == "__main__":
    raise SystemExit(main())
