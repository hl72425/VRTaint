#!/usr/bin/env python3
"""Single reusable entry point for generic Unity semantic taint analysis."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def run(cmd: list[str], log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(cmd, text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(proc.stdout, encoding="utf-8")
    if proc.returncode:
        raise RuntimeError(f"command exited {proc.returncode}; see {log}")


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    p = argparse.ArgumentParser(description="Run generic five-tuple Unity semantic taint analysis")
    p.add_argument("--project-root", required=True, type=Path)
    p.add_argument("--project-id",
                   help="stable repository/project identifier; defaults to project-root basename")
    p.add_argument("--unity-analysis", required=True, type=Path)
    p.add_argument("--guid-mapping", required=True, type=Path)
    p.add_argument("--codeql-database", required=True, type=Path)
    p.add_argument("--pack-root", required=True, type=Path)
    p.add_argument("--output-root", required=True, type=Path)
    p.add_argument("--codeql", default=shutil.which("codeql") or "codeql")
    p.add_argument("--skip-security", action="store_true")
    p.add_argument("--unity-security-only", action="store_true",
                   help="run VRTaint security suite without the official broad suite")
    p.add_argument("--javascript-database", type=Path,
                   help="optional companion JS/TS database for services shipped with the Unity project")
    a = p.parse_args()
    project_id = a.project_id or a.project_root.name
    output = a.output_root.resolve()
    facts = output / "intermediate" / "facts"
    results = output / "results"
    logs = output / "intermediate" / "logs"
    for d in (facts, results, logs): d.mkdir(parents=True, exist_ok=True)

    provider = a.pack_root / "scripts" / "semantic_taint" / "semantic_fact_provider.py"
    post = a.pack_root / "scripts" / "semantic_taint" / "semantic_postprocess.py"
    validator = a.pack_root / "scripts" / "semantic_taint" / "semantic_validate.py"
    run([sys.executable, str(provider), "--project-root", str(a.project_root),
         "--unity-analysis", str(a.unity_analysis), "--guid-mapping", str(a.guid_mapping),
         "--codeql-database", str(a.codeql_database), "--output-dir", str(facts)],
        logs / "01_fact_provider.log")

    trace_bqrs = output / "intermediate" / "semantic_trace.bqrs"
    externals = [
        f"--external=semanticSeedFact={facts / 'semantic_codeql_seed_facts.csv'}",
        f"--external=semanticMethodEdgeFact={facts / 'semantic_method_edge_facts.csv'}",
        f"--external=semanticExprSeedFact={facts / 'semantic_expr_seed_facts.csv'}",
    ]
    seed_bqrs = output / "intermediate" / "semantic_seeds.bqrs"
    run([a.codeql, "query", "run", str(a.pack_root / "queries" / "SemanticTaintSeeds.ql"),
         f"--database={a.codeql_database}", *externals, f"--output={seed_bqrs}"],
        logs / "02_seed_query.log")
    seed_csv = results / "semantic_seeds.csv"
    run([a.codeql, "bqrs", "decode", str(seed_bqrs), "--format=csv", f"--output={seed_csv}"],
        logs / "03_seed_decode.log")
    run([a.codeql, "query", "run", str(a.pack_root / "queries" / "SemanticTaintTrace.ql"),
         f"--database={a.codeql_database}", *externals, f"--output={trace_bqrs}"],
        logs / "04_trace_query.log")
    trace_csv = results / "semantic_trace.csv"
    run([a.codeql, "bqrs", "decode", str(trace_bqrs), "--format=csv", f"--output={trace_csv}"],
        logs / "05_trace_decode.log")
    run([sys.executable, str(post), "--trace-csv", str(trace_csv), "--seed-csv", str(seed_csv),
         "--external-facts-json", str(facts / "semantic_seed_facts.json"),
         "--component-bindings-json", str(facts / "semantic_component_bindings.json"),
         "--project-id", project_id,
         "--output-dir", str(results)], logs / "06_postprocess.log")

    validation_path = results / "semantic_validation.json"
    run([sys.executable, str(validator),
         "--tuples-csv", str(results / "semantic_taint_tuples.csv"),
         "--evidence-json", str(results / "semantic_taint_evidence.json"),
         "--output", str(validation_path)], logs / "07_validation.log")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sarif = results / f"{stamp}_v001_official_plus_vrtaint_csharp_security.sarif"
    security_sarifs: list[Path] = []
    if not a.skip_security:
        queries = [str(a.pack_root / "queries" / "UnitySecurityAndQuality.qls"),
                   str(a.pack_root / "queries" / "UnityTaint_generic.ql"),
                   str(a.pack_root / "queries" / "SemanticTaintSecurity.ql")]
        if not a.unity_security_only:
            queries.insert(0, "codeql/csharp-queries:codeql-suites/csharp-security-and-quality.qls")
        run([a.codeql, "database", "analyze", str(a.codeql_database), *queries,
             "--format=sarif-latest", f"--output={sarif}", *externals],
            logs / "08_security_query.log")
        security_sarifs.append(sarif)
        if a.javascript_database:
            js_sarif = results / f"{stamp}_v001_official_javascript_security.sarif"
            run([a.codeql, "database", "analyze", str(a.javascript_database.resolve()),
                 "codeql/javascript-queries@2.3.3:codeql-suites/javascript-security-and-quality.qls",
                 "--format=sarif-latest", f"--output={js_sarif}", "--rerun"],
                logs / "09_javascript_security_query.log")
            security_sarifs.append(js_sarif)
        enricher = a.pack_root / "scripts" / "semantic_taint" / "security_finding_enricher.py"
        enrich_command = [sys.executable, str(enricher)]
        for input_sarif in security_sarifs:
            enrich_command.extend(["--sarif", str(input_sarif)])
        enrich_command.extend([
             "--project-id", project_id,
             "--unity-analysis", str(a.unity_analysis),
             "--output-csv", str(results / f"{stamp}_v001_security_five_tuple.csv"),
             "--output-json", str(results / f"{stamp}_v001_security_five_tuple.json")])
        run(enrich_command, logs / "10_security_enrichment.log")
    stats = json.loads((facts / "semantic_fact_stats.json").read_text(encoding="utf-8"))
    summary = json.loads((results / "semantic_taint_summary.json").read_text(encoding="utf-8"))
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    with seed_csv.open("r", encoding="utf-8-sig", newline="") as stream:
        codeql_seed_count = sum(1 for _ in csv.DictReader(stream))
    external_seed_count = len(json.loads(
        (facts / "semantic_seed_facts.json").read_text(encoding="utf-8-sig")))
    stats["codeql_seed_count"] = codeql_seed_count
    stats["semantic_only_seed_count"] = external_seed_count
    stats["seed_count"] = codeql_seed_count + external_seed_count
    security_result_count = None
    if security_sarifs:
        security_result_count = 0
        for security_sarif in security_sarifs:
            sarif_data = json.loads(security_sarif.read_text(encoding="utf-8-sig"))
            security_result_count += sum(len(run_item.get("results", [])) for run_item in sarif_data.get("runs", []))
    final = {"project": project_id, **stats, **summary,
             "validation_valid": validation["valid"],
             "validation_error_count": validation["error_count"],
             "validation_warning_count": validation["warning_count"],
             "concrete_object_count": validation["concrete_object_count"],
             "lifecycle_bound_count": validation["lifecycle_bound_count"],
             "security_result_count": security_result_count,
             "security_sarifs": [str(path) for path in security_sarifs],
             "output_root": str(output)}
    (results / "run_summary.json").write_text(json.dumps(final, ensure_ascii=False, indent=2), encoding="utf-8")
    provenance_files = [
        a.unity_analysis, a.guid_mapping, a.codeql_database / "codeql-database.yml",
        provider, post, validator,
        a.pack_root / "scripts" / "semantic_taint" / "security_finding_enricher.py",
        a.pack_root / "lib" / "SemanticTaintFacts.qll",
        a.pack_root / "lib" / "SemanticTaintDomain.qll",
        a.pack_root / "queries" / "SemanticTaintSeeds.ql",
        a.pack_root / "queries" / "SemanticTaintTrace.ql",
        a.pack_root / "queries" / "SemanticTaintSecurity.ql",
        a.pack_root / "queries" / "UnitySecurityAndQuality.qls",
        a.pack_root / "config" / "semantic-taint-policy-v1.json",
    ]
    provenance = {
        "schema": "semantic-taint-provenance/v1",
        "inputs_and_rules": [
            {"path": str(path.resolve()), "sha256": sha256(path)} for path in provenance_files
        ],
        "external_facts": [
            {"path": str(path.resolve()), "sha256": sha256(path)} for path in (
                facts / "semantic_codeql_seed_facts.csv",
                facts / "semantic_method_edge_facts.csv",
                facts / "semantic_expr_seed_facts.csv",
                facts / "semantic_component_bindings.json",
            )
        ],
    }
    (results / "provenance_manifest.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(final, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
