#!/usr/bin/env python3
"""Assert VRTaint lifecycle/object-sensitivity regression artifacts."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def column_values(path: Path, column: str) -> set[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return {row[column] for row in csv.DictReader(handle)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compile-csv", type=Path, required=True)
    parser.add_argument("--deep-compile-csv", type=Path)
    parser.add_argument("--adapter-compile-csv", type=Path)
    parser.add_argument("--lifecycle-csv", type=Path, required=True)
    parser.add_argument("--instance-csv", type=Path, required=True)
    parser.add_argument("--phase-csv", type=Path, required=True)
    parser.add_argument("--benchmark-csv", type=Path, required=True)
    parser.add_argument("--cross-reference-csv", type=Path)
    parser.add_argument("--cross-reference-negative-csv", type=Path)
    parser.add_argument("--cli-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    checks: list[dict[str, object]] = []

    def check(name: str, passed: bool, evidence: object) -> None:
        checks.append({"name": name, "passed": bool(passed), "evidence": evidence})

    with args.compile_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        compile_rows = list(csv.DictReader(handle))
    check("all production queries compile", len(compile_rows) == 35 and all(
        row.get("status") == "pass" for row in compile_rows
    ), {"count": len(compile_rows), "failed": [r for r in compile_rows if r.get("status") != "pass"]})
    for label, path, expected in (
        ("final stateful Deep compile", args.deep_compile_csv, 4),
        ("final stateful Adapter compile", args.adapter_compile_csv, 19),
    ):
        if path:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            check(label, len(rows) == expected and all(row.get("status") == "pass" for row in rows),
                  {"count": len(rows), "failed": [r for r in rows if r.get("status") != "pass"]})

    lifecycle = column_values(args.lifecycle_csv, "caseName")
    expected_positive = {
        "ConditionalCleanCase", "TaintPreservingOverwriteCase",
        "CrossProcConditionalCleanCase", "CrossFrameLateToUpdateCase",
        "CrossFrameUpdateToFixedCase", "ReenableCase", "HelperDepthCase",
        "SharedTracker", "SameInstanceTracker", "OptionalFixedKillCase",
        "ReenableBypassesStartKillCase",
    }
    expected_negative = {"MustCleanCase", "CrossProcMustCleanCase", "SignatureCase"}
    check("lifecycle positive recall", expected_positive <= lifecycle,
          {"missing": sorted(expected_positive - lifecycle)})
    check("must-kill and signature negatives", not (expected_negative & lifecycle),
          {"unexpected": sorted(expected_negative & lifecycle)})

    instance = column_values(args.instance_csv, "caseName")
    check("cross-GameObject flow rejected", "SharedTracker" not in instance,
          {"present": "SharedTracker" in instance})
    check("same-GameObject flow retained", "SameInstanceTracker" in instance,
          {"present": "SameInstanceTracker" in instance})

    with args.phase_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        phase_rows = list(csv.DictReader(handle))
    ambiguous = [row for row in phase_rows if row.get("col0") == "AmbiguousPhaseCase"]
    check("phase is single-valued Ambiguous", len(ambiguous) == 1 and
          ambiguous[0].get("phase") == "Ambiguous", ambiguous)

    benchmark_values = column_values(args.benchmark_csv, "classification")
    check("benchmark model isolated", benchmark_values == {"benchmark-only"},
          sorted(benchmark_values))

    if args.cross_reference_csv and args.cross_reference_negative_csv:
        positive_targets = column_values(args.cross_reference_csv, "col1")
        negative_targets = column_values(args.cross_reference_negative_csv, "col1")
        expected_target = "fixture:Assets/InstanceScene.unity#component:COMP-TARGET"
        check("proven cross-component reference transition", expected_target in positive_targets,
              sorted(positive_targets))
        check("unproven cross-component transition rejected", expected_target not in negative_targets,
              sorted(negative_targets))

    manifest = json.loads(args.cli_manifest.read_text(encoding="utf-8-sig"))
    check("end-to-end CLI run", manifest.get("run_state") == "complete" and
          manifest.get("counts", {}).get("failed") == 0 and
          manifest.get("counts", {}).get("timeout") == 0,
          {"run_state": manifest.get("run_state"), "counts": manifest.get("counts")})

    payload = {
        "schema": "vrtaint-lifecycle-regression/v1",
        "passed": all(item["passed"] for item in checks),
        "check_count": len(checks),
        "passed_count": sum(bool(item["passed"]) for item in checks),
        "checks": checks,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
