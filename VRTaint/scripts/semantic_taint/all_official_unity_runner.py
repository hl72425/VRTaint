#!/usr/bin/env python3
"""Run every installed official CodeQL alert pack, then Unity/VRTaint extensions."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def database_map(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"database must be EXTRACTOR=PATH: {value}")
        extractor, raw_path = value.split("=", 1)
        path = Path(raw_path).resolve()
        if not (path / "codeql-database.yml").is_file():
            raise FileNotFoundError(path / "codeql-database.yml")
        result[extractor.strip().lower()] = path
    return result


def stop_tree(proc: subprocess.Popen[str]) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        proc.kill()


def execute(command: list[str], log: Path, timeout: int) -> tuple[str, int | None]:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as stream:
        proc = subprocess.Popen(command, text=True, encoding="utf-8", errors="replace",
                                stdout=stream, stderr=subprocess.STDOUT)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            stop_tree(proc)
            return "timeout", None
    return ("completed", code) if code == 0 else ("failed", code)


def main() -> int:
    parser = argparse.ArgumentParser(description="All official CodeQL packs plus Unity/VRTaint")
    parser.add_argument("--database", action="append", default=[], required=True,
                        help="repeatable EXTRACTOR=CODEQL_DATABASE mapping")
    parser.add_argument("--all-installed-languages", action="store_true",
                        help="run non-CSharp official packs when matching databases are supplied")
    parser.add_argument("--package-root", type=Path,
                        default=Path.home() / ".codeql" / "packages" / "codeql")
    parser.add_argument("--pack-root", type=Path,
                        default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--unity-analysis", type=Path)
    parser.add_argument("--codeql", default="codeql")
    parser.add_argument("--official-timeout", type=int, default=1800)
    parser.add_argument("--unity-fast-timeout", type=int, default=600)
    parser.add_argument("--unity-deep-timeout", type=int, default=600)
    parser.add_argument("--official-vrtaint-timeout", type=int, default=7200)
    parser.add_argument("--official-vrtaint-per-query-timeout", type=int, default=300,
                        help="timeout for each generated official-model VRTaint adapter")
    parser.add_argument("--threads", type=int, default=0)
    parser.add_argument("--ram", type=int, default=8192)
    args = parser.parse_args()
    databases = database_map(args.database)
    model_pack_dir = args.pack_root / "model_pack"
    model_pack_args: list[str] = []
    if (model_pack_dir / "qlpack.yml").is_file():
        model_pack_args = ["--additional-packs", str(model_pack_dir.resolve()),
                           "--model-packs", "my-org/vrtaint-unity-csharp-models@1.0.0"]
    output = args.output_root.resolve()
    results = output / "results"
    logs = output / "intermediate" / "logs"
    adapter_root = output / "intermediate" / "official_adapter"
    for folder in (results, logs, adapter_root):
        folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    adapter = args.pack_root / "scripts" / "semantic_taint" / "official_pack_adapter.py"
    adapter_log = logs / f"{stamp}_v001_official_pack_discovery.log"
    adapter_command = [
        sys.executable, str(adapter), "--package-root", str(args.package_root.resolve()),
        "--output-root", str(adapter_root), "--codeql", args.codeql,
    ]
    if not args.all_installed_languages:
        adapter_command.extend(["--extractor", "csharp"])
    status, code = execute(adapter_command, adapter_log, 300)
    if status != "completed":
        raise RuntimeError(f"official pack discovery {status}, exit={code}; see {adapter_log}")
    adapter_manifest = json.loads(
        (adapter_root / "official_pack_adapter_manifest_v001.json").read_text(encoding="utf-8"))

    stages: list[dict[str, object]] = []
    sarifs: list[Path] = []
    for pack in adapter_manifest["packs"]:
        extractor = str(pack["extractor"]).lower()
        if extractor != "csharp" and not args.all_installed_languages:
            stages.append({"stage": f"official_{extractor}", "status": "optional-language-skipped",
                           "pack": pack["pack"], "query_count": pack["query_count"]})
            continue
        database = databases.get(extractor)
        stage_name = f"official_{extractor}_{str(pack['version']).replace('.', '_')}"
        if database is None:
            stages.append({"stage": stage_name, "status": "database-missing",
                           "pack": pack["pack"], "query_count": pack["query_count"]})
            continue
        sarif = results / f"{stamp}_v001_{stage_name}.sarif"
        command = [args.codeql, "database", "analyze", str(database), str(pack["suite"]),
                   "--format=sarif-latest", f"--output={sarif}", "--rerun",
                   f"--threads={args.threads}", f"--ram={args.ram}"]
        if extractor == "csharp":
            command.extend(model_pack_args)
        stage_status, exit_code = execute(
            command, logs / f"{stamp}_v001_{stage_name}.log", args.official_timeout)
        stages.append({"stage": stage_name, "status": stage_status, "exit_code": exit_code,
                       "pack": pack["pack"], "query_count": pack["query_count"],
                       "database": str(database), "sarif": str(sarif) if sarif.exists() else None})
        if sarif.exists():
            sarifs.append(sarif)

    csharp_database = databases.get("csharp")
    if csharp_database:
        for name, suite_name, timeout in (
            ("unity_fast", "UnitySecurityFast.qls", args.unity_fast_timeout),
            ("unity_deep", "UnitySecurityDeep.qls", args.unity_deep_timeout),
        ):
            suite = args.pack_root / "queries" / suite_name
            sarif = results / f"{stamp}_v001_{name}.sarif"
            status, code = execute([
                args.codeql, "database", "analyze", str(csharp_database), str(suite),
                "--format=sarif-latest", f"--output={sarif}", "--rerun",
                f"--threads={args.threads}", f"--ram={args.ram}", *model_pack_args,
            ], logs / f"{stamp}_v001_{name}.log", timeout)
            stages.append({"stage": name, "status": status, "exit_code": code,
                           "database": str(csharp_database),
                           "sarif": str(sarif) if sarif.exists() else None})
            if sarif.exists():
                sarifs.append(sarif)
        official_adapter_suite = args.pack_root / "queries" / "UnityOfficialDeepAdapters.qls"
        if official_adapter_suite.is_file():
            resolve_proc = subprocess.run(
                [args.codeql, "resolve", "queries", str(official_adapter_suite)],
                text=True, encoding="utf-8", errors="replace",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if resolve_proc.returncode:
                stages.append({"stage": "official_models_vrtaint_deep",
                               "status": "resolve-failed", "exit_code": resolve_proc.returncode})
            else:
                adapter_queries = [Path(line.strip()) for line in resolve_proc.stdout.splitlines()
                                   if Path(line.strip()).is_file()]
                total_budget = args.official_vrtaint_timeout
                elapsed_budget = 0
                for adapter_query in adapter_queries:
                    name = "official_vrtaint_" + adapter_query.stem.lower()
                    if elapsed_budget >= total_budget:
                        stages.append({"stage": name, "status": "budget-skipped",
                                       "query": str(adapter_query)})
                        continue
                    timeout = min(args.official_vrtaint_per_query_timeout,
                                  total_budget - elapsed_budget)
                    sarif = results / f"{stamp}_v001_{name}.sarif"
                    status, code = execute([
                        args.codeql, "database", "analyze", str(csharp_database),
                        str(adapter_query), "--format=sarif-latest", f"--output={sarif}",
                        "--rerun", f"--threads={args.threads}", f"--ram={args.ram}",
                        *model_pack_args,
                    ], logs / f"{stamp}_v001_{name}.log", timeout)
                    elapsed_budget += timeout
                    stages.append({"stage": name, "status": status, "exit_code": code,
                                   "query": str(adapter_query), "database": str(csharp_database),
                                   "sarif": str(sarif) if sarif.exists() else None})
                    if sarif.exists():
                        sarifs.append(sarif)

    if sarifs:
        enricher = args.pack_root / "scripts" / "semantic_taint" / "security_finding_enricher.py"
        command = [sys.executable, str(enricher)]
        for sarif in sarifs:
            command.extend(["--sarif", str(sarif)])
        if args.unity_analysis:
            command.extend(["--unity-analysis", str(args.unity_analysis.resolve())])
        command.extend([
            "--output-csv", str(results / f"{stamp}_v001_all_official_plus_unity_five_tuple.csv"),
            "--output-json", str(results / f"{stamp}_v001_all_official_plus_unity_five_tuple.json"),
        ])
        status, code = execute(command, logs / f"{stamp}_v001_five_tuple_enrichment.log", 600)
        stages.append({"stage": "five_tuple_enrichment", "status": status, "exit_code": code,
                       "input_sarif_count": len(sarifs)})

    manifest = {
        "schema": "all-official-unity-security-run/v1", "created": stamp,
        "database_map": {key: str(value) for key, value in databases.items()},
        "installed_official_pack_count": adapter_manifest["pack_count"],
        "installed_official_alert_query_count": adapter_manifest["total_alert_query_count"],
        "adapter_manifest": str((adapter_root / "official_pack_adapter_manifest_v001.json").resolve()),
        "stages": stages,
    }
    manifest_path = results / f"{stamp}_v001_all_official_run_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"manifest": str(manifest_path.resolve()), "stages": stages}, ensure_ascii=False))
    return 0 if all(stage["status"] in {"completed", "database-missing", "optional-language-skipped", "timeout", "budget-skipped"}
                    for stage in stages) else 1


if __name__ == "__main__":
    raise SystemExit(main())
