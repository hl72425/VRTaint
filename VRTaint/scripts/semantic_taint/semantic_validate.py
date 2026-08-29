#!/usr/bin/env python3
"""Validate the project-neutral semantic-taint result contract."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

CONTEXT_KEYS_V1 = [
    "schema", "project", "scene", "game_object", "component", "script",
    "entry", "callable", "event", "thread", "coroutine", "async",
]
CONTEXT_KEYS_V2 = [
    "schema", "project", "asset", "scene", "game_object", "component", "script",
    "phase", "entry", "callable", "event", "thread", "coroutine", "async",
    "binding_status", "binding_confidence", "binding_provenance",
]
LIFECYCLE = {
    "Reset", "Awake", "OnEnable", "Start", "FixedUpdate", "Update", "LateUpdate",
    "OnTriggerEnter", "OnTriggerStay", "OnTriggerExit", "OnCollisionEnter",
    "OnCollisionStay", "OnCollisionExit", "OnMouseDown", "OnMouseUp", "OnMouseEnter",
    "OnMouseOver", "OnMouseExit", "OnMouseDrag", "OnPreCull", "OnBecameVisible",
    "OnBecameInvisible", "OnWillRenderObject", "OnPreRender", "OnRenderObject",
    "OnPostRender", "OnRenderImage", "OnGUI", "OnApplicationPause",
    "OnApplicationFocus", "OnApplicationQuit", "OnDisable", "OnDestroy",
    "OnAnimatorIK", "OnAnimatorMove", "Unbound", "Ambiguous",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tuples-csv", required=True, type=Path)
    parser.add_argument("--evidence-json", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    with args.tuples_csv.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    evidence = json.loads(args.evidence_json.read_text(encoding="utf-8-sig"))
    errors: list[dict[str, object]] = []
    warnings: list[dict[str, object]] = []
    for index, row in enumerate(rows, 1):
        for key in ("object", "field_path", "phase", "context", "source"):
            if not row.get(key):
                errors.append({"row": index, "field": key, "reason": "empty-required-slot"})
        if row.get("phase") not in LIFECYCLE:
            errors.append({"row": index, "field": "phase", "reason": "not-unity-lifecycle",
                           "value": row.get("phase")})
        try:
            context = json.loads(row.get("context", ""))
            schema = context.get("schema")
            expected_keys = CONTEXT_KEYS_V2 if schema == "unity-context/v2" else CONTEXT_KEYS_V1
            if list(context.keys()) != expected_keys:
                errors.append({"row": index, "field": "context", "reason": "schema-key-order",
                               "keys": list(context.keys())})
            if schema not in {"unity-context/v1", "unity-context/v2"}:
                errors.append({"row": index, "field": "context.schema", "reason": "wrong-schema"})
            if schema == "unity-context/v2":
                if context.get("phase") != row.get("phase"):
                    errors.append({"row": index, "field": "context.phase",
                                   "reason": "tuple-context-mismatch"})
                if context.get("binding_status") not in {"resolved", "type-only", "unresolved"}:
                    errors.append({"row": index, "field": "context.binding_status",
                                   "reason": "invalid-binding-status"})
                if context.get("binding_confidence") not in {"high", "medium", "low"}:
                    errors.append({"row": index, "field": "context.binding_confidence",
                                   "reason": "invalid-binding-confidence"})
        except (json.JSONDecodeError, AttributeError) as exc:
            errors.append({"row": index, "field": "context", "reason": "invalid-json",
                           "detail": str(exc)})
        if row.get("phase") == "Unbound":
            warnings.append({"row": index, "field": "phase", "reason": "lifecycle-unresolved"})
        if "#*" in row.get("object", ""):
            warnings.append({"row": index, "field": "object", "reason": "instance-unresolved"})
    if len(evidence) != len(rows):
        errors.append({"field": "evidence", "reason": "count-mismatch",
                       "tuples": len(rows), "evidence": len(evidence)})
    report = {
        "schema": "semantic-taint-validation/v2", "valid": not errors,
        "tuple_count": len(rows), "error_count": len(errors), "warning_count": len(warnings),
        "concrete_object_count": sum("#*" not in row.get("object", "") for row in rows),
        "lifecycle_bound_count": sum(row.get("phase") != "Unbound" for row in rows),
        "errors": errors, "warnings": warnings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("valid", "tuple_count", "error_count",
                                             "warning_count", "concrete_object_count",
                                             "lifecycle_bound_count")}, ensure_ascii=False))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
