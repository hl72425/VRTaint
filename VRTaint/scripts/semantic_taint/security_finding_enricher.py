#!/usr/bin/env python3
"""Normalize official CodeQL and VRTaint SARIF into one five-tuple result schema."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from urllib.parse import unquote


FIELDS = [
    "rule_id", "level", "message", "path", "line", "column",
    "object", "field_path", "phase", "context", "source",
    "tuple_origin", "result_fingerprint", "sarif",
]
LIFECYCLE_PHASES = {
    "Reset", "Awake", "OnEnable", "Start", "FixedUpdate", "Update", "LateUpdate",
    "OnTriggerEnter", "OnTriggerExit", "OnTriggerStay", "OnCollisionEnter",
    "OnCollisionExit", "OnCollisionStay", "OnMouseDown", "OnMouseUp", "OnMouseEnter",
    "OnMouseOver", "OnMouseExit", "OnMouseDrag", "OnPreCull", "OnBecameVisible",
    "OnBecameInvisible", "OnWillRenderObject", "OnPreRender", "OnRenderObject",
    "OnPostRender", "OnRenderImage", "OnGUI", "OnApplicationPause",
    "OnApplicationQuit", "OnDisable", "OnDestroy", "OnAnimatorIK", "OnAnimatorMove",
    "Unbound",
}


def normalize_script_path(value: str) -> str:
    normalized = unquote(value or "").replace("\\", "/")
    marker = "/Assets/"
    if marker in normalized:
        normalized = "Assets/" + normalized.split(marker, 1)[1]
    return normalized.removeprefix("./").lower()


def extract_tuples(message: str) -> list[list[str]]:
    marker = "Tuple=<"
    cursor = 0
    found: list[list[str]] = []
    while (start := message.find(marker, cursor)) >= 0:
        content_start = start + len(marker)
        context_start = message.find("{", content_start)
        if context_start < 0:
            break
        doubled = message.startswith("{{", context_start)
        context_end = message.find("}}" if doubled else "}", context_start + 1)
        if context_end < 0:
            break
        context_end += 2 if doubled else 1
        prefix = message[content_start:context_start].removesuffix(", ")
        dimensions = prefix.split(", ", 2)
        source_start = context_end
        if message.startswith(", ", source_start):
            source_start += 2
        tuple_end = message.find(">.", source_start)
        if len(dimensions) != 3 or tuple_end < 0:
            cursor = context_end
            continue
        context_value = message[context_start:context_end]
        if doubled:
            context_value = context_value[1:-1]
        try:
            json.loads(context_value)
        except json.JSONDecodeError:
            cursor = context_end
            continue
        found.append([*dimensions, context_value, message[source_start:tuple_end]])
        cursor = tuple_end + 2
    return found


def canonical_context(context: dict[str, object], project_id: str, phase: str) -> dict[str, object]:
    """Return the one stable v2 context vocabulary and key order used everywhere."""
    return {
        "schema": "unity-context/v2", "project": project_id,
        "asset": context.get("asset", "UNKNOWN"), "scene": context.get("scene", "UNKNOWN"),
        "game_object": context.get("game_object", "UNKNOWN"),
        "component": context.get("component", "UNKNOWN"),
        "script": context.get("script", "PATH_SLOT"), "phase": phase,
        "entry": phase, "callable": context.get("callable", "CALLABLE_SLOT"),
        "event": context.get("event", "UNKNOWN"), "thread": context.get("thread", "UNKNOWN"),
        "coroutine": context.get("coroutine", "UNKNOWN"), "async": context.get("async", "UNKNOWN"),
        "binding_status": context.get("binding_status", "unresolved"),
        "binding_confidence": context.get("binding_confidence", "low"),
        "binding_provenance": context.get("binding_provenance", "sarif-location"),
    }


def fallback_tuple(rule_id: str, path: str, project_id: str) -> list[str]:
    component = (Path(unquote(path)).stem or "TYPE_SLOT") + "#*"
    context = canonical_context({
        "asset": "UNKNOWN", "scene": "UNKNOWN",
        "game_object": "UNKNOWN", "component": component, "script": unquote(path) or "PATH_SLOT",
        "callable": "CALLABLE_SLOT", "event": "UNKNOWN",
        "thread": "UNKNOWN", "coroutine": "UNKNOWN", "async": "UNKNOWN",
        "binding_status": "unresolved", "binding_confidence": "low",
        "binding_provenance": "sarif-location",
    }, project_id, "Unbound")
    return [component, "PATH_SLOT", "Unbound",
            json.dumps(context, ensure_ascii=False, separators=(",", ":")),
            f"CodeQL::{rule_id}"]


def load_scene_index(path: Path | None) -> dict[str, list[dict[str, object]]]:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    index: dict[str, list[dict[str, object]]] = {}
    records: list[dict[str, object]] = []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict) and ("records" in data or "components" in data):
        records = data.get("records", data.get("components", []))
    elif isinstance(data, dict):
        # unity_analysis.json v1: top-level keys are scene/prefab asset paths.
        for asset_path, asset in data.items():
            if not isinstance(asset, dict):
                continue
            game_objects = {str(item.get("fileID", "")): item for item in asset.get("gameobjects", [])
                            if isinstance(item, dict)}
            for script in asset.get("scripts", []):
                if not isinstance(script, dict):
                    continue
                game_object = game_objects.get(str(script.get("gameObject", "")), {})
                script_path = str(script.get("script_path") or "")
                records.append({
                    "script_path": script_path,
                    "asset": asset_path,
                    "scene": asset_path,
                    "game_object": game_object.get("name", "UNKNOWN"),
                    "component": Path(script_path.replace("\\", "/")).stem or "UNKNOWN",
                    "component_id": script.get("fileID", "UNKNOWN"),
                })
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict):
            continue
        script = normalize_script_path(str(record.get("script_path", record.get("script", ""))))
        if script:
            index.setdefault(script, []).append(record)
    return index


def enrich_context(values: list[str], result_path: str,
                   scene_index: dict[str, list[dict[str, object]]], project_id: str) -> str:
    context = json.loads(values[3])
    original_phase = values[2]
    if original_phase not in LIFECYCLE_PHASES:
        context["callable"] = context.get("callable") or original_phase
        values[2] = "Unbound"
    context = canonical_context(context, project_id, values[2])
    values[3] = json.dumps(context, ensure_ascii=False, separators=(",", ":"))
    if not scene_index:
        return "native-unbound" if values[2] == "Unbound" else "native"
    key = normalize_script_path(result_path)
    matches = scene_index.get(key, [])
    if not matches:
        matches = [record for script, items in scene_index.items()
                   if key.endswith(script) for record in items]
    if not matches:
        context.update({"binding_status": "type-only", "binding_confidence": "medium",
                        "binding_provenance": "codeql"})
        context = canonical_context(context, project_id, values[2])
        values[3] = json.dumps(context, ensure_ascii=False, separators=(",", ":"))
        return "native-unbound" if values[2] == "Unbound" else "native"
    first = matches[0]
    context["asset"] = first.get("asset", first.get("scene", context.get("asset", "UNKNOWN")))
    context["scene"] = first.get("scene", first.get("scene_name", context.get("scene", "UNKNOWN")))
    context["game_object"] = first.get("game_object", first.get("gameObject", context.get("game_object", "UNKNOWN")))
    context["component"] = first.get("component", first.get("component_type", context.get("component", "UNKNOWN")))
    context["binding_status"] = "resolved"
    context["binding_confidence"] = "high"
    context["binding_provenance"] = "unity-analysis+codeql-location"
    context = canonical_context(context, project_id, values[2])
    values[3] = json.dumps(context, ensure_ascii=False, separators=(",", ":"))
    return "scene-enriched"


def fingerprint(row: dict[str, object]) -> str:
    return "|".join(str(row.get(k, "")) for k in ("rule_id", "path", "line", "column", "message"))


def read_sarif(path: Path, scene_index: dict[str, list[dict[str, object]]],
               project_id: str) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    rows: list[dict[str, object]] = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            artifact = loc.get("artifactLocation", {})
            region = loc.get("region", {})
            message = result.get("message", {}).get("text", "")
            path_value = unquote(artifact.get("uri", ""))
            tuples = extract_tuples(message)
            used_fallback = not tuples
            if used_fallback:
                tuples = [fallback_tuple(result.get("ruleId", "RULE_SLOT"), path_value, project_id)]
            for values in tuples:
              origin = enrich_context(values, path_value, scene_index, project_id)
              if used_fallback:
                  origin = "slot-scene-enriched" if origin == "scene-enriched" else "slot-fallback"
              row: dict[str, object] = {
                "rule_id": result.get("ruleId", ""), "level": result.get("level", ""),
                "message": message, "path": path_value, "line": region.get("startLine", ""),
                "column": region.get("startColumn", ""), "object": values[0],
                "field_path": values[1], "phase": values[2], "context": values[3],
                "source": values[4], "tuple_origin": origin, "sarif": str(path.resolve()),
              }
              row["result_fingerprint"] = fingerprint(row) + "|" + "|".join(values)
              rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", type=Path, action="append", required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--unity-analysis", type=Path,
                        help="optional generic Unity scene/component IR for context joining")
    parser.add_argument("--project-id", default="PROJECT_SLOT")
    args = parser.parse_args()
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    scene_index = load_scene_index(args.unity_analysis)
    for sarif in args.sarif:
        for row in read_sarif(sarif, scene_index, args.project_id):
            key = str(row["result_fingerprint"])
            if key not in seen:
                rows.append(row)
                seen.add(key)
    for output in (args.output_csv, args.output_json):
        output.parent.mkdir(parents=True, exist_ok=True)
    with args.output_csv.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    args.output_json.write_text(json.dumps({
        "schema": "unity-security-five-tuple/v2", "result_count": len(rows),
        "native_tuple_count": sum(str(r["tuple_origin"]).startswith("native") for r in rows),
        "slot_tuple_count": sum(not str(r["tuple_origin"]).startswith("native") for r in rows),
        "results": rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"results": len(rows), "csv": str(args.output_csv.resolve()),
                      "json": str(args.output_json.resolve())}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
