#!/usr/bin/env python3
"""Interactive and automation-friendly VRTaint pipeline executor."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable


VERSION = "20260829_145900_v013"


def _default_pack_root() -> Path:
    """Locate the VRTaint pack root: prefer the environment variable, otherwise derive it from this script's location.

    This script may live in either of two places:
    1. Inside the pack:  <pack_root>/maintenance/main-entry/scripts/
       -> parents[0]=scripts, parents[1]=main entry dir, parents[2]=maintenance dir,
          parents[3]=VRTaint pack root.
    2. Under src/:        <root>/src/vrtaint_cli.py
       -> parents[0]=src, parents[1]=<root> (dataset root), pack root = <root>/query_test/VRTaint.

    After the tree is reorganized/moved, the VRTRAINT_PACK_ROOT environment variable can
    still be used to specify the pack root explicitly.
    """
    env = os.environ.get("VRTRAINT_PACK_ROOT")
    if env:
        return Path(env).resolve()
    here = Path(__file__).resolve()
    if here.parent.name == "src":
        # <root>/src/vrtaint_cli.py -> pack root at <root>/query_test/VRTaint
        return here.parent.parent / "query_test" / "VRTaint"
    return here.parents[3]


def _default_inspector_analyzer() -> Path:
    """Locate UnityInspectorBindingAnalyzer: prefer the environment variable, otherwise derive it from pack_root.

    Derivation rule (when pack_root=<root>/query_test/VRTaint, parents[1]=<root>):
        <root>/src/Unity_preprocessing/UnityInspectorBindingAnalyzer.py
    """
    env = os.environ.get("VRTRAINT_INSPECTOR_ANALYZER")
    if env:
        return Path(env).resolve()
    return DEFAULT_PACK_ROOT.parents[1] / "src" / "Unity_preprocessing" / "UnityInspectorBindingAnalyzer.py"


DEFAULT_PACK_ROOT = _default_pack_root()
DEFAULT_INSPECTOR_ANALYZER = _default_inspector_analyzer()
MODEL_PACK_NAME = "my-org/vrtaint-unity-csharp-models@1.0.0"
INSTANCE_MODEL_PACK_NAME = "my-org/vrtaint-unity-instance-models@1.0.0"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


@dataclass
class StageResult:
    stage: str
    status: str
    seconds: float
    exit_code: int | None
    command: list[str]
    log: str
    artifacts: list[str]
    result_count: int | None = None
    note: str = ""


class ProgressReporter:
    """Console + machine-readable progress without changing query semantics."""

    def __init__(self, run_root: Path, mode: str = "normal", heartbeat_seconds: float = 10.0):
        self.run_root = run_root
        self.mode = mode
        self.heartbeat_seconds = max(1.0, heartbeat_seconds)
        self.status_dir = run_root / "intermediate" / "progress"
        self.status_dir.mkdir(parents=True, exist_ok=True)
        self.current_path = self.status_dir / "current_stage.json"
        self.events_path = self.status_dir / "progress_events.jsonl"
        self._print_lock = threading.Lock()

    def console(self, message: str) -> None:
        if self.mode == "quiet":
            return
        with self._print_lock:
            print(message, flush=True)

    def verbose_line(self, line: str) -> None:
        if self.mode == "verbose":
            self.console(f"    {line}")

    def _write_state(self, payload: dict[str, object], event: str) -> None:
        payload = dict(payload)
        payload.update({"schema": "vrtaint-live-progress/v1", "event": event,
                        "updated": datetime.now().astimezone().isoformat(timespec="seconds")})
        tmp = self.current_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.current_path)
        event_payload = dict(payload)
        if event == "heartbeat":
            event_payload.pop("command", None)
        with self.events_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event_payload, ensure_ascii=False) + "\n")

    def start(self, stage: str, command: list[str], log: Path, timeout: int, pid: int | None,
              dry_run: bool = False) -> dict[str, object]:
        state: dict[str, object] = {
            "stage": stage, "status": "dry-run" if dry_run else "running",
            "pid": pid, "elapsed_seconds": 0.0, "timeout_seconds": timeout,
            "remaining_seconds": timeout, "log": str(log), "log_bytes": 0,
            "command": command,
        }
        self.console(f"\n[{stage}] START timeout={timeout}s log={log}")
        if self.mode == "verbose":
            self.console(f"[{stage}] COMMAND {quote_command(command)}")
        self._write_state(state, "start")
        return state

    def spawned(self, state: dict[str, object], pid: int) -> None:
        state["pid"] = pid
        self._write_state(state, "spawned")

    def heartbeat(self, state: dict[str, object], elapsed: float, log: Path) -> None:
        timeout = int(state["timeout_seconds"])
        state.update({
            "status": "running", "elapsed_seconds": round(elapsed, 1),
            "remaining_seconds": max(0, round(timeout - elapsed, 1)),
            "log_bytes": log.stat().st_size if log.exists() else 0,
        })
        self.console(
            f"[{state['stage']}] RUNNING elapsed={state['elapsed_seconds']}s "
            f"remaining={state['remaining_seconds']}s pid={state['pid']} "
            f"log={state['log_bytes']}B"
        )
        self._write_state(state, "heartbeat")

    def finish(self, state: dict[str, object], status: str, seconds: float,
               exit_code: int | None, result_count: int | None, log: Path) -> None:
        state.update({
            "status": status, "elapsed_seconds": seconds,
            "remaining_seconds": max(0, round(int(state["timeout_seconds"]) - seconds, 1)),
            "exit_code": exit_code, "result_count": result_count,
            "log_bytes": log.stat().st_size if log.exists() else 0,
        })
        self._write_state(state, "finish")
        self.console(
            f"[{state['stage']}] END status={status} exit={exit_code} "
            f"seconds={seconds} results={result_count}"
        )


def stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def choose(prompt: str, choices: list[tuple[str, str]], default: str) -> str:
    print(prompt)
    for key, label in choices:
        suffix = " [default]" if key == default else ""
        print(f"  {key}. {label}{suffix}")
    valid = {key for key, _ in choices}
    while True:
        answer = input(f"Please choose [{default}]: ").strip() or default
        if answer in valid:
            return answer
        print("Invalid input; please enter a number from the list.")


def ask_path(label: str, current: Path | None = None, required: bool = True) -> Path | None:
    suffix = f" [{current}]" if current else ""
    while True:
        answer = input(f"{label}{suffix}: ").strip().strip('"')
        if not answer and current:
            return current.resolve()
        if not answer and not required:
            return None
        if answer:
            return Path(answer).expanduser().resolve()
        print("This path is required.")


def ensure_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label} does not exist: {path}")


def validate_database(path: Path) -> None:
    ensure_file(path / "codeql-database.yml", "CodeQL database marker")


def validate_project(path: Path) -> None:
    if not (path / "Assets").is_dir():
        raise FileNotFoundError(f"Unity Assets directory does not exist: {path / 'Assets'}")


def quote_command(command: list[str]) -> str:
    return subprocess.list2cmdline(command)


def stop_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def sarif_count(path: Path) -> int | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return sum(len(run.get("results", [])) for run in data.get("runs", []))
    except (OSError, json.JSONDecodeError):
        return None


def run_stage(stage: str, command: list[str], log: Path, timeout: int,
              artifacts: list[Path], dry_run: bool = False,
              progress: ProgressReporter | None = None) -> StageResult:
    log.parent.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        artifact.parent.mkdir(parents=True, exist_ok=True)
    if progress is None:
        print(f"\n[{stage}] {quote_command(command)}", flush=True)
    if dry_run:
        log.write_text("DRY-RUN\n" + quote_command(command) + "\n", encoding="utf-8")
        result = StageResult(stage, "dry-run", 0.0, None, command, str(log),
                             [str(path) for path in artifacts], note="command not executed")
        if progress:
            state = progress.start(stage, command, log, timeout, None, dry_run=True)
            progress.finish(state, result.status, result.seconds, result.exit_code,
                            result.result_count, log)
        return result
    started = time.monotonic()
    with log.open("w", encoding="utf-8") as stream:
        stream.write("COMMAND: " + quote_command(command) + "\n\n")
        stream.flush()
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        state = progress.start(stage, command, log, timeout, None) if progress else None
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace",
                                creationflags=creationflags,
                                start_new_session=(os.name != "nt"))
        if progress and state:
            progress.spawned(state, proc.pid)

        def drain_output() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                stream.write(line)
                stream.flush()
                if progress:
                    progress.verbose_line(line.rstrip("\r\n"))

        reader = threading.Thread(target=drain_output, name=f"vrtaint-{safe_slug(stage)}",
                                  daemon=True)
        reader.start()
        next_heartbeat = started + (progress.heartbeat_seconds if progress else timeout + 1)
        status = "running"
        exit_code: int | None = None
        while True:
            exit_code = proc.poll()
            now = time.monotonic()
            elapsed = now - started
            if exit_code is not None:
                status = "completed" if exit_code == 0 else "failed"
                break
            if elapsed >= timeout:
                stop_process_tree(proc)
                proc.wait()
                exit_code = None
                status = "timeout"
                stream.write(f"\nTIMEOUT after {timeout} seconds\n")
                stream.flush()
                break
            if progress and now >= next_heartbeat:
                progress.heartbeat(state, elapsed, log)  # type: ignore[arg-type]
                next_heartbeat = now + progress.heartbeat_seconds
            time.sleep(0.2)
        reader.join(timeout=5)
    seconds = round(time.monotonic() - started, 2)
    count = next((sarif_count(path) for path in artifacts if path.suffix.lower() == ".sarif"), None)
    if status == "completed" and count is not None:
        status = "completed_findings" if count > 0 else "completed_zero"
    result = StageResult(stage, status, seconds, exit_code, command, str(log),
                         [str(path) for path in artifacts if path.exists()], count)
    if progress and state:
        progress.finish(state, status, seconds, exit_code, count, log)
    else:
        print(f"[{stage}] status={status}, exit={exit_code}, seconds={seconds}, results={count}",
              flush=True)
    return result


def model_args(pack_root: Path, instance_model_pack: Path | None = None,
               instance_only: bool = False) -> list[str]:
    model_pack = pack_root / "model_pack"
    instance_pack = instance_model_pack or pack_root / "instance_model_pack"
    if instance_only:
        return ["--additional-packs", str(instance_pack),
                "--model-packs", INSTANCE_MODEL_PACK_NAME]
    return [
        "--additional-packs", os.pathsep.join([str(model_pack), str(instance_pack)]),
        "--model-packs", MODEL_PACK_NAME,
        "--model-packs", INSTANCE_MODEL_PACK_NAME,
    ]


def codeql_analyze(codeql: str, database: Path, query: Path | str, sarif: Path,
                   threads: int, ram: int, pack_root: Path, use_models: bool = True,
                   force_rerun: bool = False, max_disk_cache: int = 8192,
                   instance_model_pack: Path | None = None,
                   instance_only: bool = False) -> list[str]:
    command = [codeql, "database", "analyze", str(database), str(query),
               "--format=sarif-latest", f"--output={sarif}",
               f"--threads={threads}", f"--ram={ram}",
               f"--max-disk-cache={max_disk_cache}"]
    if force_rerun:
        command.append("--rerun")
    if use_models:
        command.extend(model_args(pack_root, instance_model_pack, instance_only))
    return command


def checkpoint_path(run_root: Path) -> Path:
    return run_root / "intermediate" / "checkpoints" / "query_status.json"


def load_checkpoint(run_root: Path) -> dict[str, dict[str, object]]:
    path = checkpoint_path(run_root)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return {str(item["stage"]): item for item in data.get("stages", [])}
    except (OSError, json.JSONDecodeError, KeyError):
        return {}


def record_stage(a: argparse.Namespace, run_root: Path, stages: list[StageResult],
                 result: StageResult) -> StageResult:
    stages[:] = [item for item in stages if item.stage != result.stage]
    stages.append(result)
    path = checkpoint_path(run_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({
        "schema": "vrtaint-query-checkpoint/v2", "executor_version": VERSION,
        "pipeline": a.pipeline, "updated": stamp(),
        "stages": [asdict(item) for item in stages],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
    csv_path = path.with_name("query_status_incremental.csv")
    csv_tmp = csv_path.with_suffix(".tmp")
    with csv_tmp.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["stage", "status", "seconds", "exit_code",
                                                        "result_count", "log", "artifacts", "note"])
        writer.writeheader()
        for item in stages:
            row = asdict(item)
            row["artifacts"] = ";".join(item.artifacts)
            row.pop("command", None)
            writer.writerow(row)
    csv_tmp.replace(csv_path)
    a.prior = {item.stage: asdict(item) for item in stages}
    return result


def query_id(path: Path) -> str:
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:40]:
            if "@id " in line:
                return line.split("@id", 1)[1].strip().strip("*/ ")
    except OSError:
        pass
    return path.stem


def safe_slug(value: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "_" for ch in value).strip("_")
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug[:100] or "query"


def resolve_queries(a: argparse.Namespace, spec: str | Path, run_root: Path,
                    category: str) -> list[Path]:
    command = [a.codeql, "resolve", "queries", str(spec), "--format=json"]
    log = run_root / "intermediate" / "logs" / f"{a.run_stamp}_v002_resolve_{category}.log"
    proc = subprocess.run(command, text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("COMMAND: " + quote_command(command) + "\n\nSTDOUT:\n" + proc.stdout +
                   "\nSTDERR:\n" + proc.stderr, encoding="utf-8")
    if proc.returncode:
        raise RuntimeError(f"resolve queries failed for {category}; see {log}")
    try:
        paths = [Path(item).resolve() for item in json.loads(proc.stdout)]
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid resolve output for {category}; see {log}") from exc
    production_root = (a.pack_root / "queries").resolve()
    try:
        spec_is_production = Path(spec).resolve().is_relative_to(production_root)
    except (OSError, ValueError):
        spec_is_production = False
    if spec_is_production:
        paths = [path for path in paths if path.is_relative_to(production_root)]
    if a.query_filter:
        needle = a.query_filter.lower()
        paths = [path for path in paths if needle in str(path).lower() or needle in query_id(path).lower()]
    if a.max_queries > 0:
        paths = paths[:a.max_queries]
    catalog = run_root / "intermediate" / "resolved_queries" / f"{a.run_stamp}_v002_{category}.json"
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text(json.dumps({"spec": str(spec), "count": len(paths),
                                   "queries": [str(path) for path in paths]},
                                  ensure_ascii=False, indent=2), encoding="utf-8")
    return paths


def execute_query(a: argparse.Namespace, run_root: Path, stages: list[StageResult],
                  category: str, query: Path, timeout: int,
                  database: Path | None = None, use_models: bool = True,
                  instance_only: bool = False) -> StageResult:
    qid = query_id(query)
    digest = hashlib.sha1(str(query).encode("utf-8")).hexdigest()[:8]
    slug = safe_slug(qid)
    stage = f"{category}:{qid}"
    sarif = run_root / "results" / category / f"{a.run_stamp}_v002_{slug}_{digest}.sarif"
    log = run_root / "intermediate" / "logs" / category / f"{a.run_stamp}_v002_{slug}_{digest}.log"
    previous = a.prior.get(stage)
    completed_states = {"completed", "completed_zero", "completed_findings", "cached_completed"}
    previous_artifact = None
    if previous:
        previous_artifact = next((Path(item) for item in previous.get("artifacts", [])
                                  if str(item).lower().endswith(".sarif")), None)
    if (a.resume and not a.force_rerun and previous and previous.get("status") in completed_states
            and previous_artifact and previous_artifact.is_file()):
        result = StageResult(stage, "cached_completed", 0.0, 0, [], str(previous.get("log", "")),
                             [str(previous_artifact)], sarif_count(previous_artifact), "resume checkpoint")
        return record_stage(a, run_root, stages, result)
    if (a.resume and previous and previous.get("status") == "timeout" and not a.retry_timeouts):
        result = StageResult(stage, "timeout_skipped", 0.0, None, [], str(previous.get("log", "")),
                             list(previous.get("artifacts", [])), None,
                             "use --retry-timeouts to rerun")
        return record_stage(a, run_root, stages, result)
    command = codeql_analyze(a.codeql, database or a.database, query, sarif, a.threads, a.ram,
                             a.pack_root, use_models, a.force_rerun, a.max_disk_cache,
                             a.instance_model_pack, instance_only)
    result = run_stage(stage, command, log, timeout, [sarif], a.dry_run, a.progress)
    return record_stage(a, run_root, stages, result)


def execute_suite(a: argparse.Namespace, run_root: Path, stages: list[StageResult],
                  category: str, spec: str | Path, timeout: int) -> None:
    queries = resolve_queries(a, spec, run_root, category)
    a.progress.console(f"[{category}] resolved {len(queries)} individual queries")
    for index, query in enumerate(queries, 1):
        a.progress.console(f"[{category}] {index}/{len(queries)}: {query_id(query)}")
        execute_query(a, run_root, stages, category, query, timeout)


def find_unity_inputs(project: Path, unity_analysis: Path | None,
                      guid_mapping: Path | None) -> tuple[Path | None, Path | None]:
    if unity_analysis is None:
        matches = [path for path in project.rglob("unity_analysis.json")
                   if not {"Library", "Temp", "obj", "bin", ".git"}.intersection(path.parts)]
        if len(matches) == 1:
            unity_analysis = matches[0]
    if guid_mapping is None:
        matches = [path for path in project.rglob("guid_mapping.csv")
                   if not {"Library", "Temp", "obj", "bin", ".git"}.intersection(path.parts)]
        if len(matches) == 1:
            guid_mapping = matches[0]
    return unity_analysis, guid_mapping


def selected_query(pack_root: Path, rule: str | None, interactive: bool) -> Path:
    choices = {
        "1": pack_root / "queries" / "UnityZipSlip.ql",
        "2": pack_root / "queries" / "UnityUntrustedDeserialization.ql",
        "3": pack_root / "queries" / "UnityTaintedFilePath.ql",
        "4": pack_root / "queries" / "UnityCommandInjection.ql",
        "5": pack_root / "queries" / "UnityUnauthenticatedHttpSurface.ql",
        "6": pack_root / "queries" / "UnityUnboundedDecompression.ql",
        "7": pack_root / "queries" / "UnityPackagePathTraversal.ql",
        "8": pack_root / "queries" / "UnitySensitiveDataExposure.ql",
        "9": pack_root / "queries" / "UnityScriptWriteExecution.ql",
    }
    aliases = {
        "zipslip": choices["1"], "deserialization": choices["2"],
        "path": choices["3"], "command": choices["4"], "http": choices["5"],
        "decompression": choices["6"], "unitypackage": choices["7"],
        "privacy": choices["8"], "script": choices["9"],
    }
    if rule:
        candidate = Path(rule).expanduser()
        if candidate.is_file():
            return candidate.resolve()
        if rule.lower() in aliases:
            return aliases[rule.lower()]
        adapter = pack_root / "queries" / "generated_official_adapters" / rule
        if adapter.suffix.lower() != ".ql":
            adapter = adapter.with_suffix(".ql")
        if adapter.is_file():
            return adapter.resolve()
        raise FileNotFoundError(f"Unable to resolve rule: {rule}")
    if not interactive:
        raise ValueError("the 'single' pipeline requires --rule")
    answer = choose("Single rule:", [
        ("1", "High-precision Zip Slip"), ("2", "Unsafe deserialization"),
        ("3", "Tainted file path"), ("4", "Command injection"),
        ("5", "Unauthenticated HTTP Surface"), ("6", "Unbounded gRPC decompression"),
        ("7", "UnityPackage path traversal"), ("8", "Unity/VR sensitive data exfiltration"),
        ("9", "External file write to script execution surface"),
    ], "1")
    return choices[answer]


def pipeline_compile(a: argparse.Namespace, run_root: Path, stages: list[StageResult]) -> None:
    suite_specs = [
        ("compile_fast", a.pack_root / "queries" / "UnitySecurityFast.qls"),
        ("compile_deep", a.pack_root / "queries" / "UnitySecurityDeep.qls"),
        ("compile_adapters", a.pack_root / "queries" / "UnityOfficialDeepAdapters.qls"),
    ]
    queries: list[Path] = []
    seen: set[Path] = set()
    for category, spec in suite_specs:
        for query in resolve_queries(a, spec, run_root, category):
            if query not in seen:
                seen.add(query); queries.append(query)
    started = time.monotonic()
    outcomes: list[str] = []
    for index, query in enumerate(queries, 1):
        qid = query_id(query)
        stage_name = "compile:" + qid
        prior = a.prior.get(stage_name)
        if a.resume and prior and prior.get("status") in {"completed", "cached_completed"} and not a.force_rerun:
            cached = StageResult(stage_name, "cached_completed", 0.0, 0, [],
                                 str(prior.get("log", "")), list(prior.get("artifacts", [])),
                                 note="reused successful compile checkpoint")
            record_stage(a, run_root, stages, cached); outcomes.append(cached.status); continue
        elapsed = time.monotonic() - started
        if elapsed >= a.compile_total_timeout:
            skipped = StageResult(stage_name, "budget_skipped", 0.0, None, [], "", [],
                                  note="compile total budget exhausted")
            record_stage(a, run_root, stages, skipped); outcomes.append(skipped.status); continue
        timeout = min(a.compile_timeout, max(1, int(a.compile_total_timeout - elapsed)))
        digest = hashlib.sha1(str(query).encode("utf-8")).hexdigest()[:8]
        log = run_root / "intermediate" / "logs" / "compile" / (
            f"{a.run_stamp}_v002_{safe_slug(qid)}_{digest}.log")
        command = [a.codeql, "query", "compile", "--check-only",
                   f"--threads={a.threads}", f"--ram={a.ram}", str(query)]
        a.progress.console(f"[compile] {index}/{len(queries)}: {qid}")
        result = run_stage(stage_name, command, log, timeout, [], a.dry_run, a.progress)
        record_stage(a, run_root, stages, result); outcomes.append(result.status)
    if a.dry_run:
        final_status = "dry-run"
    elif any(status == "failed" for status in outcomes):
        final_status = "failed"
    elif any(status in {"timeout", "budget_skipped"} for status in outcomes):
        final_status = "timeout"
    else:
        final_status = "completed"
    record_stage(a, run_root, stages, StageResult(
        "compile", final_status, round(time.monotonic() - started, 2),
        0 if final_status in {"completed", "dry-run"} else None, [], "", [],
        note=f"individual query compilation: {len(queries)} queries"))


def pipeline_compile_privacy(a: argparse.Namespace, run_root: Path,
                             stages: list[StageResult]) -> None:
    """Compile the framework-backed privacy query and optional auxiliary query."""
    queries = []
    if a.privacy_codeql_languages in {"all", "csharp"}:
        queries.extend([
            a.pack_root / "queries" / "UnitySensitiveDataExposure.ql",
            a.pack_root / "queries" / "20260829_040000_v001_UnitySerializedSensitiveDataExposure.ql",
        ])
    if a.privacy_codeql_languages in {"all", "python"} and a.python_database:
        queries.append(a.pack_root / "python_queries" /
                       "20260829_053000_v001_python_privacy_pack" /
                       "20260829_053000_v001_PythonBiometricNetworkExposure.ql")
    outcomes = []
    for query in queries:
        qid = query_id(query)
        log = run_root / "intermediate" / "logs" / "compile" / (
            f"{a.run_stamp}_v004_{safe_slug(qid)}_privacy.log")
        command = [a.codeql, "query", "compile", "--check-only",
                   f"--threads={a.threads}", f"--ram={a.ram}", str(query)]
        result = run_stage("compile:" + qid, command, log, a.compile_timeout, [],
                           a.dry_run, a.progress)
        record_stage(a, run_root, stages, result); outcomes.append(result.status)
    final_status = "dry-run" if a.dry_run else (
        "failed" if any(x == "failed" for x in outcomes) else
        ("timeout" if any(x == "timeout" for x in outcomes) else "completed"))
    record_stage(a, run_root, stages, StageResult(
        "compile", final_status, 0.0, 0 if final_status == "completed" else None,
        [], "", [], note=f"dedicated CodeQL privacy compilation: {len(queries)} queries"))


def pipeline_fast(a: argparse.Namespace, run_root: Path, stages: list[StageResult]) -> None:
    execute_suite(a, run_root, stages, "unity_fast",
                  a.pack_root / "queries" / "UnitySecurityFast.qls", a.fast_timeout)


def pipeline_privacy_codeql(a: argparse.Namespace, run_root: Path,
                            stages: list[StageResult]) -> None:
    # One generic query supplies privacy Source/Sink/API summaries to the same
    # VRTaintInstanceFlow used by the security rules.  Lifecycle, events,
    # serialized references, ownership and instance state are therefore not
    # bypassed by endpoint-only or precomputed source-to-sink results.
    execute_query(a, run_root, stages, "privacy-codeql",
                  a.pack_root / "queries" / "UnitySensitiveDataExposure.ql",
                  a.privacy_timeout, instance_only=True)
    pipeline_privacy_configuration(a, run_root, stages)


def pipeline_privacy_configuration(a: argparse.Namespace, run_root: Path,
                                   stages: list[StageResult]) -> None:
    """Report direct sensitive SDK configuration semantics from scene/prefab facts."""
    execute_query(
        a, run_root, stages, "privacy-configuration",
        a.pack_root / "queries" / "20260829_040000_v001_UnitySerializedSensitiveDataExposure.ql",
        min(a.privacy_timeout, 300), instance_only=True,
    )


def pipeline_python_privacy_codeql(a: argparse.Namespace, run_root: Path,
                                   stages: list[StageResult]) -> None:
    if a.python_database is None:
        return
    query = (a.pack_root / "python_queries" / "20260829_053000_v001_python_privacy_pack" /
             "20260829_053000_v001_PythonBiometricNetworkExposure.ql")
    execute_query(a, run_root, stages, "privacy-codeql-python", query,
                  a.deep_timeout, a.python_database, use_models=False)


def pipeline_deep(a: argparse.Namespace, run_root: Path, stages: list[StageResult]) -> None:
    execute_suite(a, run_root, stages, "unity_deep",
                  a.pack_root / "queries" / "UnitySecurityDeep.qls", a.deep_timeout)


def adapter_sink_preflight(a: argparse.Namespace, run_root: Path,
                           stages: list[StageResult]) -> dict[str, tuple[int, int]] | None:
    """Return exact official sink counts, or None to fail open and run every adapter.

    This query imports the same public ``Sink`` classes as the generated adapters.
    Consequently a zero count proves that the corresponding adapter has no possible
    result in this database, independently of VRTaint's propagation semantics.
    """
    if not a.adapter_preflight:
        return None
    query = a.pack_root / "queries" / "preflight" / "VRTaintOfficialAdapterSinkPreflight.ql"
    bqrs = run_root / "intermediate" / "preflight" / f"{a.run_stamp}_v001_adapter_sinks.bqrs"
    csv_path = run_root / "intermediate" / "preflight" / f"{a.run_stamp}_v001_adapter_sinks.csv"
    command = [a.codeql, "query", "run", str(query), f"--database={a.database}",
               f"--output={bqrs}", f"--threads={a.threads}", f"--ram={a.ram}",
               f"--max-disk-cache={a.max_disk_cache}"]
    result = run_stage(
        "adapter_preflight", command,
        run_root / "intermediate" / "logs" / f"{a.run_stamp}_v001_adapter_preflight.log",
        a.adapter_preflight_timeout, [bqrs], a.dry_run, a.progress)
    record_stage(a, run_root, stages, result)
    if a.dry_run or result.status not in {"completed", "completed_zero", "completed_findings"}:
        return None
    decode = [a.codeql, "bqrs", "decode", str(bqrs), "--format=csv", f"--output={csv_path}"]
    decoded = run_stage(
        "adapter_preflight_decode", decode,
        run_root / "intermediate" / "logs" / f"{a.run_stamp}_v001_adapter_preflight_decode.log",
        120, [csv_path], False, a.progress)
    record_stage(a, run_root, stages, decoded)
    if decoded.status not in {"completed", "completed_zero", "completed_findings"}:
        return None
    with csv_path.open("r", encoding="utf-8-sig", newline="") as stream:
        return {row["family"]: (int(row["sinkCount"]), int(row["sourceCount"]))
                for row in csv.DictReader(stream)}


def pipeline_adapters(a: argparse.Namespace, run_root: Path, stages: list[StageResult]) -> None:
    queries = resolve_queries(a, a.pack_root / "queries" / "UnityOfficialDeepAdapters.qls",
                              run_root, "adapters")
    sink_counts = adapter_sink_preflight(a, run_root, stages)
    started = time.monotonic()
    for query in queries:
        family = query.stem.removeprefix("VRTaintOfficial")
        candidates = sink_counts.get(family, (0, 0)) if sink_counts is not None else None
        if candidates is not None and (candidates[0] == 0 or candidates[1] == 0):
            record_stage(a, run_root, stages, StageResult(
                "adapters:" + query_id(query), "applicability_skipped", 0.0, 0, [], "", [], 0,
                note=("exact adapter endpoint preflight: "
                      f"project-owned sinks={candidates[0]}, configured sources={candidates[1]}")))
            continue
        elapsed = time.monotonic() - started
        if elapsed >= a.adapter_total_timeout:
            record_stage(a, run_root, stages,
                         StageResult("adapters:" + query_id(query), "budget_skipped", 0.0,
                                     None, [], "", [], note="adapter total budget exhausted"))
            continue
        timeout = min(a.adapter_timeout, max(1, int(a.adapter_total_timeout - elapsed)))
        execute_query(a, run_root, stages, "adapters", query, timeout)


def pipeline_official(a: argparse.Namespace, run_root: Path, stages: list[StageResult]) -> None:
    execute_suite(a, run_root, stages, "official",
                  "codeql/csharp-queries:codeql-suites/csharp-security-and-quality.qls",
                  a.official_query_timeout)


def pipeline_javascript_official(a: argparse.Namespace, run_root: Path,
                                 stages: list[StageResult]) -> None:
    """Run official JS/TS rules when a companion database is supplied."""
    if a.javascript_database is None:
        return
    # A C#-centred qlpack lock does not necessarily make the separately
    # installed JavaScript query pack visible to `resolve queries` by pack
    # spec. Prefer the newest valid official suite in the local CodeQL pack
    # cache, while retaining the canonical pack spec as a portable fallback.
    js_suite: Path | str = (
        "codeql/javascript-queries:codeql-suites/"
        "javascript-security-and-quality.qls"
    )
    cache_root = Path.home() / ".codeql" / "packages" / "codeql" / "javascript-queries"
    candidates = list(cache_root.glob(
        "*/codeql-suites/javascript-security-and-quality.qls"
    )) if cache_root.is_dir() else []
    if candidates:
        def version_key(path: Path) -> tuple[int, ...]:
            try:
                return tuple(int(part) for part in path.parents[1].name.split("."))
            except ValueError:
                return (0,)
        js_suite = max(candidates, key=version_key)
    queries = resolve_queries(
        a,
        js_suite,
        run_root,
        "official-js",
    )
    a.progress.console(f"[official-js] resolved {len(queries)} individual queries")
    for index, query in enumerate(queries, 1):
        a.progress.console(f"[official-js] {index}/{len(queries)}: {query_id(query)}")
        execute_query(a, run_root, stages, "official-js", query,
                      a.official_query_timeout, a.javascript_database, False)


def pipeline_single(a: argparse.Namespace, run_root: Path, stages: list[StageResult]) -> None:
    query = selected_query(a.pack_root, a.rule, a.interactive)
    execute_query(a, run_root, stages, "single", query, a.deep_timeout)


def pipeline_semantic(a: argparse.Namespace, run_root: Path, stages: list[StageResult],
                      include_security: bool = False,
                      privacy_python_only: bool = False) -> None:
    validate_project(a.project)
    semantic_output = run_root / "semantic"
    command = [sys.executable, str(a.pack_root / "scripts" / "semantic_taint" / "semantic_taint_api.py"),
               "--project-root", str(a.project), "--codeql-database", str(a.database),
               "--output-root", str(semantic_output), "--pack-root", str(a.pack_root),
               "--project-id", a.project_id]
    command.append("--unity-security-only" if include_security else "--skip-security")
    if privacy_python_only:
        command.append("--privacy-python-only")
    if a.unity_analysis:
        command.extend(["--unity-analysis", str(a.unity_analysis)])
    if a.guid_mapping:
        command.extend(["--guid-mapping", str(a.guid_mapping)])
    if a.javascript_database:
        command.extend(["--javascript-database", str(a.javascript_database)])
    if a.regenerate_inputs:
        command.append("--regenerate-inputs")
    command.extend(["--scene-scope", a.scene_scope])
    artifacts = [semantic_output / "interface_manifest.json",
                 semantic_output / "results" / "run_summary.json",
                 semantic_output / "results" / "semantic_taint_tuples.csv",
                 semantic_output / "results" / "semantic_validation.json",
                 semantic_output / "results" / "privacy" / "privacy_findings.sarif",
                 semantic_output / "results" / "privacy" / "privacy_five_tuple.csv",
                 semantic_output / "results" / "privacy" / "privacy_validation.json"]
    result = run_stage("semantic_five_tuple", command,
                       run_root / "intermediate" / "logs" / f"{a.run_stamp}_v002_semantic.log",
                       a.semantic_timeout, artifacts, a.dry_run, a.progress)
    record_stage(a, run_root, stages, result)
    # Promote companion privacy artifacts into the unified results tree so the
    # aggregate SARIF and downstream five-tuple enrichment include them.
    if not a.dry_run and result.status in {"completed", "completed_zero", "completed_findings"}:
        promoted = run_root / "results" / "privacy_companion"
        promoted.mkdir(parents=True, exist_ok=True)
        for name in ("privacy_findings.sarif", "privacy_findings.csv",
                     "privacy_findings.json", "privacy_five_tuple.csv",
                     "privacy_validation.json"):
            source = semantic_output / "results" / "privacy" / name
            if source.is_file():
                shutil.copy2(source, promoted / name)


def pipeline_privacy_companion(a: argparse.Namespace, run_root: Path,
                               stages: list[StageResult]) -> None:
    """Run only the companion-language privacy pass; C# is handled by CodeQL."""
    output = run_root / "results" / "privacy_companion"
    command = [
        sys.executable,
        str(a.pack_root / "scripts" / "semantic_taint" / "unity_privacy_flow_analyzer.py"),
        "--project-root", str(a.project), "--project-id", a.project_id,
        "--output-root", str(output), "--emit-python-only",
    ]
    artifacts = [output / "privacy_findings.sarif", output / "privacy_five_tuple.csv",
                 output / "privacy_validation.json"]
    result = run_stage(
        "privacy_companion", command,
        run_root / "intermediate" / "logs" / f"{a.run_stamp}_v001_privacy_companion.log",
        a.semantic_timeout, artifacts, a.dry_run, a.progress)
    record_stage(a, run_root, stages, result)


def aggregate_sarif(run_root: Path, run_stamp: str) -> Path | None:
    inputs = [path for path in sorted((run_root / "results").rglob("*.sarif"))
              if "aggregate" not in path.name.lower()]
    if not inputs:
        return None
    runs: list[dict[str, object]] = []
    for path in inputs:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            for run in data.get("runs", []):
                run.setdefault("properties", {})["vrtaintSourceSarif"] = str(path.resolve())
                runs.append(run)
        except (OSError, json.JSONDecodeError):
            continue
    output = run_root / "results" / "aggregate" / f"{run_stamp}_v002_aggregate.sarif"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"version": "2.1.0",
                                  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                                  "runs": runs}, ensure_ascii=False), encoding="utf-8")
    return output


def enrich_security(a: argparse.Namespace, run_root: Path, stages: list[StageResult]) -> None:
    aggregate = aggregate_sarif(run_root, a.run_stamp) if not a.dry_run else None
    if not aggregate:
        return
    csv_path = run_root / "results" / f"{a.run_stamp}_v001_security_five_tuple.csv"
    json_path = run_root / "results" / f"{a.run_stamp}_v001_security_five_tuple.json"
    command = [sys.executable, str(a.pack_root / "scripts" / "semantic_taint" / "security_finding_enricher.py")]
    command.extend(["--sarif", str(aggregate), "--project-id",
                    a.project_id])
    if a.unity_analysis:
        command.extend(["--unity-analysis", str(a.unity_analysis)])
    command.extend(["--output-csv", str(csv_path), "--output-json", str(json_path)])
    record_stage(a, run_root, stages,
                 run_stage("security_five_tuple_enrichment", command,
                           run_root / "intermediate" / "logs" / f"{a.run_stamp}_v002_enrichment.log",
                           600, [csv_path, json_path], a.dry_run, a.progress))


def prepare_instance_model(a: argparse.Namespace, run_root: Path,
                           stages: list[StageResult]) -> None:
    """Select or generate the project data-extension pack used by stateful queries."""
    fallback = a.pack_root / "instance_model_pack"
    a.instance_model_pack = fallback
    if a.disable_instance_model:
        return
    if a.instance_model_pack_override:
        candidate = a.instance_model_pack_override.resolve()
        ensure_file(candidate / "qlpack.yml", "Unity instance model pack")
        a.instance_model_pack = candidate
        return
    if not (a.project and a.database and a.unity_analysis):
        return

    inspector_schema_ok = False
    if a.inspector_bindings and a.inspector_bindings.is_file():
        try:
            with a.inspector_bindings.open("r", encoding="utf-8-sig", newline="") as stream:
                columns = set(next(csv.reader(stream), []))
            inspector_schema_ok = {
                "source_component_type", "event_field", "target_component_type",
                "target_method", "param_index", "call_type", "call_state", "provenance",
            }.issubset(columns)
        except OSError:
            inspector_schema_ok = False
    if not a.disable_configuration_events and (not inspector_schema_ok or a.force_rerun):
        analyzer = a.inspector_analyzer.resolve()
        if analyzer.is_file():
            generated_bindings = (
                run_root / "intermediate" / "configuration_events" / "inspector_bindings.csv"
            )
            analyzer_command = [
                sys.executable, str(analyzer), "--project-root", str(a.project),
                "--output-csv", str(generated_bindings), "--workers", str(max(1, min(4, a.threads))),
            ]
            if a.force_rerun:
                analyzer_command.append("--force")
            analyzer_result = run_stage(
                "configuration_event_extraction", analyzer_command,
                run_root / "intermediate" / "logs" / f"{a.run_stamp}_v001_configuration_events.log",
                1800, [generated_bindings], a.dry_run, a.progress,
            )
            record_stage(a, run_root, stages, analyzer_result)
            if analyzer_result.status not in {"failed", "timeout"}:
                a.inspector_bindings = generated_bindings

    generated = run_root / "intermediate" / "instance_model_pack"
    work = run_root / "intermediate" / "instance_model_generation"
    summary = generated / "semantic_model_summary.json"
    command = [
        sys.executable,
        str(a.pack_root / "scripts" / "semantic_taint" / "unity_instance_model_pack.py"),
        "--project-root", str(a.project), "--database", str(a.database),
        "--unity-analysis", str(a.unity_analysis), "--output-pack", str(generated),
        "--project-id", a.project_id, "--codeql", a.codeql,
        "--query-root", str(a.pack_root), "--work-dir", str(work),
    ]
    if a.guid_mapping:
        command.extend(["--guid-mapping", str(a.guid_mapping)])
    if a.node_bindings:
        command.extend(["--node-bindings", str(a.node_bindings)])
    if a.inspector_bindings and not a.disable_configuration_events:
        command.extend(["--inspector-bindings", str(a.inspector_bindings)])
    if a.component_references:
        command.extend(["--component-references", str(a.component_references)])
    if a.disable_serialized_references:
        command.append("--disable-serialized-references")
    result = run_stage(
        "unity_instance_model", command,
        run_root / "intermediate" / "logs" / f"{a.run_stamp}_v001_instance_model.log",
        1800, [summary, generated / "component_join_qa.csv",
               generated / "serialized_reference_qa.csv"], a.dry_run, a.progress,
    )
    record_stage(a, run_root, stages, result)
    if result.status not in {"failed", "timeout"}:
        a.instance_model_pack = generated


def prepare_privacy_model(a: argparse.Namespace, run_root: Path,
                          stages: list[StageResult]) -> None:
    """Add local unresolved-source and direct serialized-configuration facts."""
    if (a.pipeline not in {"privacy", "full"} or not a.project or
            (a.pipeline == "privacy" and a.privacy_codeql_languages == "python")):
        return
    script_root = a.pack_root / "scripts" / "semantic_taint"
    generated = run_root / "intermediate" / "privacy_instance_model_pack"
    summary = generated / "privacy_model_summary.json"
    command = [
        sys.executable,
        str(script_root / "20260829_145900_v001_unity_privacy_source_model_pack.py"),
        "--project-root", str(a.project), "--output-pack", str(generated),
        "--base-pack", str(a.instance_model_pack),
        "--source-generator", str(script_root / "20260829_040000_v001_unity_privacy_model_pack.py"),
    ]
    result = run_stage(
        "privacy_model", command,
        run_root / "intermediate" / "logs" / f"{a.run_stamp}_v001_privacy_model.log",
        a.semantic_timeout, [summary], a.dry_run, a.progress)
    record_stage(a, run_root, stages, result)
    if result.status not in {"failed", "timeout"}:
        a.instance_model_pack = generated


def project_has_javascript(project: Path) -> bool:
    """Return true for project-owned JS/TS, excluding generated/vendor trees."""
    ignored = {
        ".git", ".svn", "Library", "Temp", "Logs", "obj", "bin",
        "node_modules", "Packages", "PackageCache", "Build", "Builds",
        "dist", "coverage", "vendor", "ThirdParty", "Plugins",
    }
    for root, dirs, files in os.walk(project):
        dirs[:] = [name for name in dirs if name not in ignored]
        for name in files:
            lower = name.lower()
            if lower.endswith((".js", ".jsx", ".ts", ".tsx")) and not lower.endswith(".d.ts"):
                return True
    return False


def prepare_javascript_database(a: argparse.Namespace, run_root: Path,
                                stages: list[StageResult]) -> None:
    """Create/reuse a companion JS/TS database for mixed-language Unity projects."""
    if a.javascript_database is not None or not a.auto_javascript_database or a.project is None:
        return
    if not project_has_javascript(a.project):
        record_stage(a, run_root, stages, StageResult(
            "javascript_database", "applicability_skipped", 0.0, 0, [], "", [],
            note="no project-owned JavaScript/TypeScript source found"))
        return
    database = run_root / "intermediate" / "databases" / "db-javascript"
    marker = database / "codeql-database.yml"
    if marker.is_file() and not a.force_rerun:
        a.javascript_database = database
        record_stage(a, run_root, stages, StageResult(
            "javascript_database", "cached_completed", 0.0, 0, [], "",
            [str(database)], note="reused companion JavaScript/TypeScript database"))
        return
    command = [
        a.codeql, "database", "create", str(database), "--language=javascript",
        f"--source-root={a.project}", "--overwrite",
    ]
    result = run_stage(
        "javascript_database", command,
        run_root / "intermediate" / "logs" / f"{a.run_stamp}_v001_javascript_database.log",
        a.javascript_database_timeout, [database], a.dry_run, a.progress,
    )
    record_stage(a, run_root, stages, result)
    if result.status in {"completed", "cached_completed", "dry-run"}:
        a.javascript_database = database


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Unified interactive/automation VRTaint executor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--pipeline", choices=[
        "full", "quick", "official", "fast", "deep", "semantic", "privacy", "single", "compile"
    ])
    ap.add_argument("--project", type=Path, help="Unity project root; required for full/semantic/privacy")
    ap.add_argument("--project-id", help="stable repository/project identifier; defaults to the project directory name")
    ap.add_argument("--database", type=Path, help="C# CodeQL database")
    ap.add_argument("--javascript-database", type=Path,
                    help="optional JS/TS CodeQL database; for Web/admin services shipped with the Unity project")
    ap.add_argument("--python-database", type=Path,
                    help="optional Python CodeQL database; for Unity companion vision/biometric processing code")
    ap.add_argument("--privacy-codeql-languages", choices=("all", "csharp", "python"),
                    default="all", help="CodeQL languages executed by the privacy pipeline")
    ap.add_argument("--privacy-timeout", type=int, default=900,
                    help="per-project timeout for the framework-backed privacy query")
    ap.add_argument("--auto-javascript-database", action=argparse.BooleanOptionalAction,
                    default=True,
                    help="automatically create a companion CodeQL database when --project is given and project-owned JS/TS is found")
    ap.add_argument("--javascript-database-timeout", type=int, default=3600)
    ap.add_argument("--output-root", type=Path, help="output root directory for this run")
    ap.add_argument("--pack-root", type=Path, default=DEFAULT_PACK_ROOT)
    ap.add_argument("--unity-analysis", type=Path)
    ap.add_argument("--guid-mapping", type=Path)
    ap.add_argument("--instance-model-pack", dest="instance_model_pack_override", type=Path,
                    help="pre-generated Unity component instance CodeQL model pack")
    ap.add_argument("--node-bindings", type=Path,
                    help="optional precise node-binding CSV for configuration-driven cross-GameObject disambiguation")
    ap.add_argument("--inspector-bindings", type=Path,
                    help="inspector_bindings.csv generated by UnityInspectorBindingAnalyzer")
    ap.add_argument("--inspector-analyzer", type=Path, default=DEFAULT_INSPECTOR_ANALYZER,
                    help="Unity scene/Prefab persistent event resolver")
    ap.add_argument("--disable-configuration-events", action="store_true",
                    help="disable Inspector persistent UnityEvent extraction and taint flow")
    ap.add_argument("--component-references", type=Path,
                    help="optional owner/field/target component references CSV")
    ap.add_argument("--disable-serialized-references", action="store_true",
                    help="disable automatic recovery of serialized component references in .unity/.prefab")
    ap.add_argument("--disable-instance-model", action="store_true",
                    help="use explicit TYPE/GLOBAL fallback and do not generate scene instance facts")
    ap.add_argument("--rule", help="single rule alias, file name, or absolute path")
    ap.add_argument("--scene-scope", choices=["build", "all"], default="build")
    ap.add_argument("--regenerate-inputs", action="store_true")
    ap.add_argument("--codeql", default=shutil.which("codeql") or "codeql")
    ap.add_argument("--threads", type=int, default=1,
                    help="single-threaded by default to avoid concurrent Java compilers exhausting the Windows pagefile on large suites")
    ap.add_argument("--ram", type=int, default=6144,
                    help="query evaluator memory budget; 6144MB avoids the stage-cache shutdown caused by an ~1.8GB heap")
    ap.add_argument("--max-disk-cache", type=int, default=8192,
                    help="upper bound in MB of the CodeQL intermediate-stage disk cache")
    ap.add_argument("--compile-timeout", type=int, default=600)
    ap.add_argument("--compile-total-timeout", type=int, default=7200)
    ap.add_argument("--official-query-timeout", type=int, default=1200)
    ap.add_argument("--fast-timeout", type=int, default=900)
    ap.add_argument("--deep-timeout", type=int, default=2400)
    ap.add_argument("--adapter-timeout", type=int, default=1200)
    ap.add_argument("--adapter-total-timeout", type=int, default=21600)
    ap.add_argument("--adapter-preflight", action=argparse.BooleanOptionalAction, default=True,
                    help="first run an exact applicability preflight against official Sink classes; adapters with zero candidates are marked proven inapplicable")
    ap.add_argument("--adapter-preflight-timeout", type=int, default=300)
    ap.add_argument("--semantic-timeout", type=int, default=7200)
    ap.add_argument("--resume", action="store_true", help="reuse completed queries and run only unfinished stages")
    ap.add_argument("--retry-timeouts", action="store_true", help="retry timed-out queries during resume")
    ap.add_argument("--force-rerun", action="store_true", help="ignore CodeQL and executor checkpoint caches")
    ap.add_argument("--query-filter", help="only run queries whose path or query id contains this string")
    ap.add_argument("--max-queries", type=int, default=0, help="maximum number of queries per suite; 0 means all")
    ap.add_argument("--progress", choices=["quiet", "normal", "verbose"], default="normal",
                    help="progress display: quiet shows only the final summary; normal shows timed heartbeats; verbose mirrors subprocess output")
    ap.add_argument("--heartbeat-seconds", type=float, default=10.0,
                    help="heartbeat interval for normal/verbose mode, minimum 1 second")
    ap.add_argument("--skip-compile", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="only generate commands, logs, and manifest")
    ap.add_argument("--non-interactive", action="store_true", help="fail immediately when arguments are missing")
    return ap.parse_args()


def complete_interactive(a: argparse.Namespace) -> argparse.Namespace:
    a.interactive = not a.non_interactive
    if not a.interactive:
        return a
    if not a.pipeline:
        mapping = {
            "1": "full", "2": "quick", "3": "official", "4": "fast",
            "5": "deep", "6": "semantic", "7": "single", "8": "compile",
            "9": "privacy"
        }
        answer = choose("Available VRTaint pipelines:", [
            ("1", "Full system: compile + official C#/optional JS + Fast + Deep + 19 Adapters + five-tuple semantics"),
            ("2", "Quick security: compile + official C#/optional JS + Unity Fast + result enrichment"),
            ("3", "Official security-and-quality (C#; also runs JS/TS when --javascript-database is provided)"),
            ("4", "Unity Fast only (quick iteration/regression testing)"),
            ("5", "Deep taint: compile + 5 Deep queries (incl. privacy/script-write execution chains) + 19 Adapters + result enrichment"),
            ("6", "Semantic five-tuple only: Unity IR/GUID + Semantic facts + VRTaint trace"),
            ("7", "Single rule"), ("8", "Compile validation only"),
            ("9", "General privacy detection: privacy CodeQL + Unity/Prefab companion analysis + five-tuple"),
        ], "1")
        a.pipeline = mapping[answer]
    if a.pipeline != "compile" and a.database is None:
        a.database = ask_path("CodeQL C# database")
    if a.pipeline in {"full", "semantic", "privacy"} and a.project is None:
        a.project = ask_path("Unity project root")
    if a.output_root is None:
        default = Path.cwd() / f"VRTaint_run_{stamp()}_v001"
        a.output_root = ask_path("Output directory", default)
    if a.pipeline in {"full", "semantic", "privacy"}:
        a.unity_analysis, a.guid_mapping = find_unity_inputs(
            a.project.resolve(), a.unity_analysis, a.guid_mapping)
        if a.unity_analysis:
            print(f"Found Unity IR: {a.unity_analysis}")
        if a.guid_mapping:
            print(f"Found GUID mapping: {a.guid_mapping}")
    return a


def validate_args(a: argparse.Namespace) -> None:
    a.pack_root = a.pack_root.resolve()
    ensure_file(a.pack_root / "qlpack.yml", "VRTaint qlpack")
    if not a.pipeline:
        raise ValueError("--pipeline is required unless running in interactive mode")
    if a.pipeline != "compile":
        if a.database is None:
            raise ValueError(f"the '{a.pipeline}' pipeline requires --database")
        a.database = a.database.resolve()
        validate_database(a.database)
    if a.pipeline in {"full", "semantic", "privacy"}:
        if a.project is None:
            raise ValueError(f"the '{a.pipeline}' pipeline requires --project")
        a.project = a.project.resolve()
        validate_project(a.project)
    elif a.project is not None:
        a.project = a.project.resolve()
        validate_project(a.project)
    if a.javascript_database:
        a.javascript_database = a.javascript_database.resolve()
        validate_database(a.javascript_database)
    if a.python_database:
        a.python_database = a.python_database.resolve()
        validate_database(a.python_database)
    if a.output_root is None:
        raise ValueError("--output-root is required")
    a.output_root = a.output_root.resolve()
    if a.unity_analysis:
        a.unity_analysis = a.unity_analysis.resolve(); ensure_file(a.unity_analysis, "Unity IR")
    if a.guid_mapping:
        a.guid_mapping = a.guid_mapping.resolve(); ensure_file(a.guid_mapping, "GUID mapping")
    if a.node_bindings:
        a.node_bindings = a.node_bindings.resolve(); ensure_file(a.node_bindings, "node bindings")
    if a.component_references:
        a.component_references = a.component_references.resolve()
        ensure_file(a.component_references, "component references")
    if a.inspector_bindings:
        a.inspector_bindings = a.inspector_bindings.resolve()
        ensure_file(a.inspector_bindings, "inspector bindings")
    elif a.project and (a.project / "inspector_bindings.csv").is_file():
        a.inspector_bindings = (a.project / "inspector_bindings.csv").resolve()
    if not a.project_id:
        a.project_id = a.project.name if a.project else "PROJECT_SLOT"


def write_summary(a: argparse.Namespace, run_root: Path, stages: list[StageResult]) -> Path:
    result_dir = run_root / "results"
    result_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "vrtaint-cli-run/v2", "executor_version": VERSION,
        "pipeline": a.pipeline, "created": a.run_stamp,
        "project": str(a.project) if a.project else None, "project_id": a.project_id,
        "database": str(a.database) if a.database else None,
        "javascript_database": str(a.javascript_database) if a.javascript_database else None,
        "python_database": str(a.python_database) if a.python_database else None,
        "pack_root": str(a.pack_root), "output_root": str(run_root),
        "instance_model_pack": str(a.instance_model_pack),
        "run_state": "dry-run" if stages and all(item.status == "dry-run" for item in stages) else
                     ("failed" if any(item.status == "failed" for item in stages) else
                     ("partial" if any(item.status in {"timeout", "timeout_skipped", "budget_skipped"}
                                       for item in stages) else "complete")),
        "settings": {
            "threads": a.threads, "ram": a.ram, "compile_timeout": a.compile_timeout,
            "max_disk_cache": a.max_disk_cache,
            "compile_total_timeout": a.compile_total_timeout,
            "official_query_timeout": a.official_query_timeout, "fast_timeout": a.fast_timeout,
            "deep_timeout": a.deep_timeout, "adapter_timeout": a.adapter_timeout,
            "adapter_total_timeout": a.adapter_total_timeout,
            "adapter_preflight": a.adapter_preflight,
            "adapter_preflight_timeout": a.adapter_preflight_timeout,
            "semantic_timeout": a.semantic_timeout, "dry_run": a.dry_run,
            "disable_serialized_references": a.disable_serialized_references,
            "disable_configuration_events": a.disable_configuration_events,
            "component_references": str(a.component_references) if a.component_references else None,
            "resume": a.resume, "retry_timeouts": a.retry_timeouts,
            "force_rerun": a.force_rerun, "query_filter": a.query_filter,
            "max_queries": a.max_queries,
            "auto_javascript_database": a.auto_javascript_database,
            "javascript_database_timeout": a.javascript_database_timeout,
            "progress": a.progress_mode,
            "heartbeat_seconds": a.heartbeat_seconds,
        },
        "counts": {
            "stage_count": len(stages),
            "completed": sum(item.status in {"completed", "completed_zero", "completed_findings",
                                              "cached_completed", "applicability_skipped"} for item in stages),
            "completed_zero": sum(item.status == "completed_zero" for item in stages),
            "completed_findings": sum(item.status == "completed_findings" for item in stages),
            "cached_completed": sum(item.status == "cached_completed" for item in stages),
            "applicability_skipped": sum(item.status == "applicability_skipped" for item in stages),
            "timeout": sum(item.status in {"timeout", "timeout_skipped"} for item in stages),
            "failed": sum(item.status == "failed" for item in stages),
            "budget_skipped": sum(item.status == "budget_skipped" for item in stages),
            "sarif_results": sum(item.result_count or 0 for item in stages),
        },
        "stages": [asdict(item) for item in stages],
    }
    path = result_dir / f"{a.run_stamp}_v002_vrtaint_cli_manifest.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    csv_path = result_dir / f"{a.run_stamp}_v002_query_status.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["stage", "status", "seconds", "exit_code",
                                                    "result_count", "log", "artifacts", "note"])
        writer.writeheader()
        for item in stages:
            row = asdict(item)
            row["artifacts"] = ";".join(item.artifacts)
            row.pop("command", None)
            writer.writerow(row)
    return path


def main() -> int:
    a = complete_interactive(parse_args())
    validate_args(a)
    a.run_stamp = stamp()
    run_root = a.output_root
    if a.project:
        a.unity_analysis, a.guid_mapping = find_unity_inputs(
            a.project, a.unity_analysis, a.guid_mapping)
    for folder in (run_root / "results", run_root / "intermediate" / "logs"):
        folder.mkdir(parents=True, exist_ok=True)
    a.progress_mode = a.progress
    a.progress = ProgressReporter(run_root, a.progress_mode, a.heartbeat_seconds)
    a.progress.console(
        f"=== VRTaint START pipeline={a.pipeline} project={a.project_id} "
        f"progress={a.progress_mode} output={run_root} ==="
    )
    a.prior = load_checkpoint(run_root) if a.resume else {}
    stages: list[StageResult] = []
    for item in a.prior.values():
        try:
            stages.append(StageResult(**item))
        except TypeError:
            continue
    prepare_javascript_database(a, run_root, stages)
    prepare_instance_model(a, run_root, stages)
    prepare_privacy_model(a, run_root, stages)
    compile_done = any(item.stage == "compile" and item.status == "completed" for item in stages)
    if not a.skip_compile and not (a.resume and compile_done and not a.force_rerun):
        if a.pipeline == "privacy":
            pipeline_compile_privacy(a, run_root, stages)
        else:
            pipeline_compile(a, run_root, stages)
        if next(item for item in stages if item.stage == "compile").status in {"failed", "timeout"}:
            manifest = write_summary(a, run_root, stages)
            print(f"Compilation failed, Manifest: {manifest}")
            return 2
    if a.pipeline == "compile":
        pass
    elif a.pipeline == "quick":
        pipeline_official(a, run_root, stages); pipeline_javascript_official(a, run_root, stages); pipeline_fast(a, run_root, stages); enrich_security(a, run_root, stages)
    elif a.pipeline == "official":
        pipeline_official(a, run_root, stages); pipeline_javascript_official(a, run_root, stages); enrich_security(a, run_root, stages)
    elif a.pipeline == "fast":
        pipeline_fast(a, run_root, stages); enrich_security(a, run_root, stages)
    elif a.pipeline == "deep":
        pipeline_deep(a, run_root, stages); pipeline_adapters(a, run_root, stages); enrich_security(a, run_root, stages)
    elif a.pipeline == "semantic":
        # Semantic facts are produced once. Security rules are intentionally kept
        # in the per-query executor so one slow query cannot discard other results.
        pipeline_semantic(a, run_root, stages, include_security=False)
    elif a.pipeline == "privacy":
        if a.python_database is None:
            pipeline_privacy_companion(a, run_root, stages)
        if a.privacy_codeql_languages in {"all", "csharp"}:
            pipeline_privacy_codeql(a, run_root, stages)
        if a.privacy_codeql_languages in {"all", "python"}:
            pipeline_python_privacy_codeql(a, run_root, stages)
        enrich_security(a, run_root, stages)
    elif a.pipeline == "single":
        pipeline_single(a, run_root, stages); enrich_security(a, run_root, stages)
    elif a.pipeline == "full":
        # First build/reuse Unity IR and semantic facts. This lets all subsequent
        # SARIF findings use the same lifecycle/context vocabulary during enrichment.
        pipeline_semantic(a, run_root, stages, include_security=False,
                          privacy_python_only=True)
        if not a.unity_analysis and not a.dry_run:
            generated = sorted((run_root / "semantic" / "intermediate" / "generated_inputs").glob(
                "*_auto_unity_analysis_v001.json"), key=lambda p: p.stat().st_mtime)
            if generated:
                a.unity_analysis = generated[-1]
        pipeline_official(a, run_root, stages)
        pipeline_javascript_official(a, run_root, stages)
        pipeline_fast(a, run_root, stages)
        # UnitySensitiveDataExposure.ql is already part of UnitySecurityDeep.qls.
        # Do not execute the same framework-backed query twice in a full run.
        pipeline_privacy_configuration(a, run_root, stages)
        pipeline_python_privacy_codeql(a, run_root, stages)
        pipeline_deep(a, run_root, stages)
        pipeline_adapters(a, run_root, stages)
        enrich_security(a, run_root, stages)
    manifest = write_summary(a, run_root, stages)
    print("\n=== VRTaint run finished ===")
    print(f"Pipeline: {a.pipeline}")
    print(f"Results directory: {run_root}")
    print(f"Manifest: {manifest}")
    print(f"State={json.loads(manifest.read_text(encoding='utf-8'))['run_state']}")
    print(f"Completed={sum(s.status in {'completed','completed_zero','completed_findings','cached_completed','applicability_skipped'} for s in stages)}, "
          f"Timed out={sum(s.status in {'timeout','timeout_skipped'} for s in stages)}, "
          f"Failed={sum(s.status == 'failed' for s in stages)}")
    if any(s.status == "failed" for s in stages):
        return 1
    if any(s.status in {"timeout", "timeout_skipped", "budget_skipped"} for s in stages):
        return 3
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nUser aborted.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
