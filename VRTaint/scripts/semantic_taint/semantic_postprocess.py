#!/usr/bin/env python3
"""Materialize generic semantic taint five-tuples from CodeQL trace rows."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


OUT_COLUMNS = [
    "fact_id", "object", "field_path", "phase", "context", "source",
    "influence_kind", "confidence", "endpoint_kind", "source_node", "endpoint_node",
]
CONTEXT_KEYS = [
    "schema", "project", "asset", "scene", "game_object", "component", "script",
    "phase", "entry", "callable", "event", "thread", "coroutine", "async",
    "binding_status", "binding_confidence", "binding_provenance",
]


def parse_context(value: str) -> dict[str, str]:
    try:
        parsed = json.loads(value or "{}")
        if isinstance(parsed, dict):
            return {str(k): str(v) for k, v in parsed.items()}
    except json.JSONDecodeError:
        pass
    out: dict[str, str] = {}
    for part in (value or "").split(";"):
        if "=" in part:
            key, val = part.split("=", 1)
            out[key] = val
    return out


def normalized_context(source_value: str, endpoint_value: str, endpoint_phase: str,
                       project_id: str) -> str:
    source = parse_context(source_value)
    endpoint = parse_context(endpoint_value)
    merged = {}
    for key in CONTEXT_KEYS:
        if key == "schema":
            merged[key] = "unity-context/v2"
        elif key == "project":
            merged[key] = project_id
        elif key == "asset":
            merged[key] = source.get("asset", source.get("scene", endpoint.get("scene", "UNKNOWN")))
        elif key == "phase":
            merged[key] = endpoint_phase or source.get("phase", source.get("entry", "Unbound"))
        elif key == "entry":
            merged[key] = endpoint_phase or source.get("entry", "Unbound")
        elif key in {"component", "script", "callable"}:
            merged[key] = endpoint.get(key, source.get(key, "UNKNOWN"))
        else:
            merged[key] = source.get(key, endpoint.get(key, "UNKNOWN"))
    if merged.get("binding_status") in {"", "UNKNOWN"}:
        merged["binding_status"] = "type-only"
    if merged.get("binding_confidence") in {"", "UNKNOWN"}:
        merged["binding_confidence"] = "medium"
    if merged.get("binding_provenance") in {"", "UNKNOWN"}:
        merged["binding_provenance"] = "codeql"
    return json.dumps(merged, ensure_ascii=False, separators=(",", ":"))


def load_component_bindings(path: Path | None) -> list[dict[str, str]]:
    if not path or not path.exists():
        return []
    rows = json.loads(path.read_text(encoding="utf-8-sig"))
    return [{str(k): str(v) for k, v in row.items()} for row in rows]


def expand_endpoint_object(row: dict[str, str], bindings: list[dict[str, str]],
                           project_id: str) -> list[dict[str, str]]:
    """Replace Type#* with scene/prefab component instances when YAML proves them.

    Multiple instances are intentionally retained: choosing one without runtime
    evidence would be less sound than exposing every source-proven candidate.
    """
    value = row.get("object", "")
    if not value.endswith("#*"):
        return [row]
    component_type = value[:-2]
    ctx = parse_context(row.get("context", ""))
    source_scene = ctx.get("scene", "UNKNOWN")
    matches = [b for b in bindings if b.get("component_type") == component_type]
    same_asset = [b for b in matches if source_scene not in {"", "UNKNOWN", "NONE"}
                  and b.get("asset_path") == source_scene]
    if same_asset:
        matches = same_asset
    if not matches:
        return [row]
    expanded = []
    for binding in matches:
        clone = dict(row)
        component_id = binding.get("component_id", binding.get("component_file_id", "UNKNOWN"))
        clone["object"] = (
            f"asset:{binding.get('asset_path', 'UNKNOWN')}|"
            f"gameObject:{binding.get('game_object_name', 'UNKNOWN')}|"
            f"component:{component_type}#{component_id}"
        )
        bound_ctx = dict(ctx)
        bound_ctx["schema"] = "unity-context/v2"
        bound_ctx["project"] = project_id
        bound_ctx["asset"] = binding.get("asset_path", bound_ctx.get("asset", "UNKNOWN"))
        bound_ctx["scene"] = binding.get("asset_path", bound_ctx.get("scene", "UNKNOWN"))
        bound_ctx["game_object"] = binding.get("game_object_name", "UNKNOWN")
        bound_ctx["component"] = f"{component_type}#{component_id}"
        bound_ctx["binding_status"] = "resolved"
        bound_ctx["binding_confidence"] = binding.get("confidence", "high")
        bound_ctx["binding_provenance"] = "unity-yaml+guid-mapping"
        clone["context"] = json.dumps(
            {key: bound_ctx.get(key, "UNKNOWN") for key in CONTEXT_KEYS},
            ensure_ascii=False, separators=(",", ":"))
        expanded.append(clone)
    return expanded


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--trace-csv", required=True, type=Path)
    p.add_argument("--seed-csv", type=Path)
    p.add_argument("--external-facts-json", type=Path)
    p.add_argument("--component-bindings-json", type=Path)
    p.add_argument("--project-id", required=True)
    p.add_argument("--output-dir", required=True, type=Path)
    a = p.parse_args()
    a.output_dir.mkdir(parents=True, exist_ok=True)
    with a.trace_csv.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    tuples = []
    component_bindings = load_component_bindings(a.component_bindings_json)
    if a.seed_csv and a.seed_csv.exists():
        with a.seed_csv.open("r", encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                tuples.append({
                    "fact_id": r.get("factId", ""), "object": r.get("objectId", ""),
                    "field_path": r.get("accessPath", ""), "phase": r.get("phase", "Unbound"),
                    "context": normalized_context(r.get("context", ""), "", r.get("phase", ""), a.project_id),
                    "source": r.get("sourceKind", ""), "influence_kind": r.get("influenceKind", ""),
                    "confidence": r.get("confidence", ""), "endpoint_kind": "seed",
                    "source_node": r.get("source", ""), "endpoint_node": "",
                })
    if a.external_facts_json and a.external_facts_json.exists():
        external = json.loads(a.external_facts_json.read_text(encoding="utf-8-sig"))
        for r in external:
            if int(r.get("parameter_index", 0)) >= 0:
                continue
            tuples.append({
                "fact_id": r.get("fact_id", ""), "object": r.get("object_id", ""),
                "field_path": r.get("access_path", ""), "phase": r.get("phase", "Unbound"),
                "context": normalized_context(r.get("context", ""), "", r.get("phase", ""), a.project_id),
                "source": r.get("source_kind", ""), "influence_kind": r.get("influence_kind", ""),
                "confidence": r.get("confidence", ""), "endpoint_kind": "semantic-control-seed",
                "source_node": "", "endpoint_node": "",
            })
    for r in rows:
        endpoint_phase = r.get("col13", "")
        effective_phase = endpoint_phase if endpoint_phase not in {"", "Unbound"} else r.get("phase", "Unbound")
        context = normalized_context(r.get("context", ""), r.get("col14", ""), effective_phase,
                                     a.project_id)
        endpoint_path = r.get("col12", "")
        # field/path describes the endpoint slot only. Propagation history stays
        # in source_node/endpoint_node rather than being embedded in this slot.
        field_path = endpoint_path or r.get("accessPath", "")
        projected = {
            "fact_id": r.get("factId", ""),
            "object": r.get("col11", "") or r.get("objectId", ""),
            "field_path": field_path,
            "phase": effective_phase,
            "context": context,
            "source": r.get("sourceKind", ""),
            "influence_kind": r.get("influenceKind", ""),
            "confidence": r.get("confidence", ""),
            "endpoint_kind": r.get("col10", ""),
            "source_node": r.get("source", ""),
            "endpoint_node": r.get("sink", ""),
        }
        tuples.extend(expand_endpoint_object(projected, component_bindings, a.project_id))
    seen = set()
    deduped = []
    for row in tuples:
        key = tuple(row[c] for c in OUT_COLUMNS)
        if key not in seen:
            seen.add(key); deduped.append(row)

    csv_path = a.output_dir / "semantic_taint_tuples.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=OUT_COLUMNS, lineterminator="\n")
        w.writeheader(); w.writerows(deduped)
    (a.output_dir / "semantic_taint_tuples.json").write_text(
        json.dumps(deduped, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = {
        "schema": "semantic-taint-result/v1",
        "tuple_count": len(deduped),
        # Data-bearing semantic paths are not vulnerability candidates. Only
        # the separately filtered Security query is allowed to emit findings.
        "data_trace_count": sum(1 for r in deduped if r["influence_kind"] == "data"),
        "configuration_trace_count": sum(1 for r in deduped if r["influence_kind"] == "configuration"),
        "control_fact_count": sum(1 for r in deduped if r["influence_kind"] == "control"),
        "endpoint_kinds": {},
    }
    for r in deduped:
        summary["endpoint_kinds"][r["endpoint_kind"]] = summary["endpoint_kinds"].get(r["endpoint_kind"], 0) + 1
    (a.output_dir / "semantic_taint_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    evidence = []
    for row in deduped:
        ctx = parse_context(row["context"])
        evidence.append({
            "fact_id": row["fact_id"],
            "tuple": {
                "object": row["object"], "field_path": row["field_path"],
                "phase": row["phase"], "context": ctx, "source": row["source"],
            },
            "evidence": {
                "script": ctx.get("script", "UNKNOWN"),
                "scene": ctx.get("scene", "UNKNOWN"),
                "component": ctx.get("component", "UNKNOWN"),
                "source_node": row["source_node"], "endpoint_node": row["endpoint_node"],
            },
            "verification": {
                "node_join": "verified" if row["source_node"] else "semantic-only",
                "lifecycle_join": "verified" if row["phase"] != "Unbound" else "unbound",
                "object_join": "verified" if "#*" not in row["object"] else "summary",
                "confidence": row["confidence"],
            }
        })
    (a.output_dir / "semantic_taint_evidence.json").write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
