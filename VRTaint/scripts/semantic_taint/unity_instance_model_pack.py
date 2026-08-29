#!/usr/bin/env python3
"""Generate a project-neutral CodeQL data-extension pack for Unity instances.

The generator joins Unity scene/prefab IR to declarations extracted from the
CodeQL database. It deliberately emits exact instance facts only for joins with
high or medium confidence; unresolved scripts remain explicit type/global
fallbacks in the QL layer instead of receiving invented identities.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


LIFECYCLE_NAMES = {
    "Reset", "Awake", "OnEnable", "Start", "FixedUpdate", "Update", "LateUpdate",
    "OnMouseDown", "OnMouseUp", "OnMouseUpAsButton", "OnMouseEnter", "OnMouseOver",
    "OnMouseExit", "OnMouseDrag", "OnBecameVisible", "OnBecameInvisible",
    "OnWillRenderObject", "OnPreCull", "OnPreRender", "OnRenderObject", "OnPostRender",
    "OnGUI", "OnApplicationQuit", "OnDisable", "OnDestroy", "OnAnimatorMove",
    "OnDrawGizmos", "OnDrawGizmosSelected", "OnValidate", "OnTransformChildrenChanged",
    "OnTransformParentChanged", "OnParticleSystemStopped", "OnParticleTrigger",
    "OnParticleUpdateJobScheduled", "OnApplicationFocus", "OnApplicationPause",
    "OnAnimatorIK", "OnCollisionEnter", "OnCollisionExit", "OnCollisionStay",
    "OnCollisionEnter2D", "OnCollisionExit2D", "OnCollisionStay2D", "OnTriggerEnter",
    "OnTriggerExit", "OnTriggerStay", "OnTriggerEnter2D", "OnTriggerExit2D",
    "OnTriggerStay2D", "OnControllerColliderHit", "OnJointBreak", "OnJointBreak2D",
    "OnParticleCollision", "OnAudioFilterRead", "OnRenderImage",
}


@dataclass(frozen=True)
class CallableRow:
    script_path: str
    type_name: str
    method_name: str
    parameter_count: int
    parameter_types: str
    return_type: str
    is_static: bool
    is_component: bool
    line: int


@dataclass(frozen=True)
class SerializedReference:
    """A same-asset PPtr recovered from one MonoBehaviour YAML document."""

    owner_file_id: str
    field_path: str
    target_file_id: str
    line: int


DOCUMENT_RE = re.compile(r"^---\s+!u!(?P<class_id>\d+)\s+&(?P<file_id>-?\d+)")
KEY_RE = re.compile(r"^(?P<indent>\s*)(?:-\s+)?(?P<key>[^:#][^:]*):(?P<value>.*)$")
LIST_VALUE_RE = re.compile(r"^(?P<indent>\s*)-\s+(?P<value>\{.*)$")
FILE_ID_RE = re.compile(r"\bfileID:\s*(?P<file_id>-?\d+)")
GUID_RE = re.compile(r"\bguid:\s*(?P<guid>[0-9a-fA-F]+)")
STRUCTURAL_REFERENCE_KEYS = {"m_GameObject", "m_Script", "m_CorrespondingSourceObject"}


def mask_csharp_noncode(text: str) -> str:
    """Mask comments and quoted contents while preserving newlines."""
    out = list(text)
    i, state = 0, "code"
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out[i] = out[i + 1] = " "; i += 2; state = "line"; continue
            if ch == "/" and nxt == "*":
                out[i] = out[i + 1] = " "; i += 2; state = "block"; continue
            if ch == "@" and nxt == '"':
                out[i] = out[i + 1] = " "; i += 2; state = "verbatim"; continue
            if ch == '"': out[i] = " "; state = "string"
            elif ch == "'": out[i] = " "; state = "char"
        elif state == "line":
            if ch == "\n": state = "code"
            else: out[i] = " "
        elif state == "block":
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "; i += 2; state = "code"; continue
            if ch != "\n": out[i] = " "
        elif state == "verbatim":
            if ch == '"' and nxt == '"':
                out[i] = out[i + 1] = " "; i += 2; continue
            if ch == '"': out[i] = " "; state = "code"
            elif ch != "\n": out[i] = " "
        else:
            if ch == "\\" and nxt:
                out[i] = " "; out[i + 1] = " " if nxt != "\n" else nxt; i += 2; continue
            if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                out[i] = " "; state = "code"
            elif ch != "\n": out[i] = " "
        i += 1
    return "".join(out)


def discover_unity_event_invocations(
    project_root: Path, inventory: Iterable[CallableRow], event_fields: Iterable[str]
) -> list[list[object]]:
    """Find exact source lines containing configured event-field `.Invoke(...)`."""
    fields = sorted({f for f in event_fields if re.fullmatch(r"[A-Za-z_]\w*", f)})
    if not fields:
        return []
    pattern = re.compile(
        r"\b(?P<field>" + "|".join(map(re.escape, fields)) + r")\s*\.\s*Invoke\s*\("
    )
    root = project_root.resolve()
    rows: set[tuple[object, ...]] = set()
    for script_path in sorted({row.script_path for row in inventory}):
        source_file = next((p for p in (root / "Assets" / script_path, root / script_path) if p.is_file()), None)
        if source_file is None:
            continue
        try:
            masked = mask_csharp_noncode(source_file.read_text(encoding="utf-8-sig", errors="replace"))
        except OSError:
            continue
        for match in pattern.finditer(masked):
            rows.add((script_path, match.group("field"), masked.count("\n", 0, match.start()) + 1,
                      "source-lexical"))
    return [list(row) for row in sorted(rows)]


def parse_unity_serialized_references(asset_file: Path) -> list[SerializedReference]:
    """Extract local MonoBehaviour-to-object PPtrs without parsing arbitrary YAML."""

    references: list[SerializedReference] = []
    current_class = ""
    current_owner = ""
    key_stack: list[tuple[int, str]] = []
    try:
        lines = asset_file.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return references

    for line_number, raw_line in enumerate(lines, 1):
        document = DOCUMENT_RE.match(raw_line)
        if document:
            current_class = document.group("class_id")
            current_owner = document.group("file_id")
            key_stack.clear()
            continue
        if current_class != "114" or not current_owner:
            continue

        list_value = LIST_VALUE_RE.match(raw_line)
        key_match = KEY_RE.match(raw_line)
        if list_value:
            indent = len(list_value.group("indent"))
            value = list_value.group("value")
            while key_stack and indent < key_stack[-1][0]:
                key_stack.pop()
            path_parts = [key for _, key in key_stack if key != "MonoBehaviour"]
            if path_parts:
                path_parts[-1] += "[]"
            key = path_parts[-1] if path_parts else "[]"
            field_path = ".".join(path_parts)
        elif key_match:
            indent = len(key_match.group("indent"))
            key = key_match.group("key").strip()
            value = key_match.group("value")
            while key_stack and indent <= key_stack[-1][0]:
                key_stack.pop()
            field_path = ".".join(
                [stack_key for _, stack_key in key_stack if stack_key != "MonoBehaviour"] + [key]
            )
            if not value.strip():
                key_stack.append((indent, key))
        else:
            continue

        file_id_match = FILE_ID_RE.search(value)
        if not file_id_match or key in STRUCTURAL_REFERENCE_KEYS:
            continue
        target_file_id = file_id_match.group("file_id")
        if target_file_id == "0":
            continue
        guid_match = GUID_RE.search(value)
        if guid_match and set(guid_match.group("guid")) != {"0"}:
            continue
        references.append(
            SerializedReference(current_owner, field_path, target_file_id, line_number)
        )
    return references


def discover_serialized_component_references(
    project_root: Path,
    asset_paths: Iterable[str],
    modeled_components: dict[tuple[str, str], str],
) -> tuple[list[list[object]], list[dict[str, object]], int]:
    """Resolve PPtrs only when owner and target are modeled same-asset components."""

    rows: set[tuple[object, ...]] = set()
    qa: list[dict[str, object]] = []
    scanned_assets = 0
    root = project_root.resolve()
    for raw_asset_path in sorted(set(asset_paths)):
        asset_path = norm_path(raw_asset_path)
        if not asset_path.lower().endswith((".unity", ".prefab")):
            continue
        candidate = (root / Path(asset_path)).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            qa.append({
                "asset_path": asset_path, "line": 0, "owner_file_id": "",
                "field_path": "", "target_file_id": "", "status": "outside_project_root",
            })
            continue
        if not candidate.is_file():
            qa.append({
                "asset_path": asset_path, "line": 0, "owner_file_id": "",
                "field_path": "", "target_file_id": "", "status": "asset_missing",
            })
            continue
        scanned_assets += 1
        for reference in parse_unity_serialized_references(candidate):
            owner = modeled_components.get((asset_path.lower(), reference.owner_file_id))
            target = modeled_components.get((asset_path.lower(), reference.target_file_id))
            status = "modeled" if owner and target else (
                "owner_unmodeled" if not owner else "target_unmodeled"
            )
            qa.append({
                "asset_path": asset_path,
                "line": reference.line,
                "owner_file_id": reference.owner_file_id,
                "field_path": reference.field_path,
                "target_file_id": reference.target_file_id,
                "status": status,
            })
            if owner and target and owner != target:
                rows.add((owner, reference.field_path, target, "high"))
    return [list(row) for row in sorted(rows)], qa, scanned_assets


def run_checked(command: list[str], cwd: Path | None = None) -> None:
    printable = subprocess.list2cmdline(command)
    print(f"[run] {printable}")
    completed = subprocess.run(command, cwd=cwd, text=True)
    if completed.returncode:
        raise RuntimeError(f"command failed ({completed.returncode}): {printable}")


def norm_path(value: str | os.PathLike[str]) -> str:
    text = str(value).strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return "/".join(part for part in text.split("/") if part not in ("", "."))


def unity_asset_relative(raw: str, project_root: Path) -> str:
    value = norm_path(raw)
    root = norm_path(project_root.resolve())
    lower = value.lower()
    root_lower = root.lower()
    if lower.startswith(root_lower + "/"):
        value = value[len(root) + 1 :]
        lower = value.lower()
    for marker in ("assets/", "packages/", "projectsettings/"):
        index = lower.find("/" + marker)
        if index >= 0:
            return value[index + 1 :]
        if lower.startswith(marker):
            return value
    return value


def yaml_row(values: Iterable[object]) -> str:
    return json.dumps(list(values), ensure_ascii=False)


def load_guid_map(path: Path | None) -> dict[str, str]:
    if not path or not path.exists():
        return {}
    result: dict[str, str] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            guid = (row.get("GUID") or row.get("guid") or "").strip().lower()
            asset = (row.get("AssetPath") or row.get("asset_path") or "").strip()
            if guid and asset:
                result[guid] = asset
    return result


def read_inventory(path: Path) -> list[CallableRow]:
    rows: list[CallableRow] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        next(reader, None)
        for raw in reader:
            if len(raw) < 9:
                continue
            rows.append(
                CallableRow(
                    script_path=norm_path(raw[0]),
                    type_name=raw[1],
                    method_name=raw[2],
                    parameter_count=int(raw[3]),
                    parameter_types=raw[4],
                    return_type=raw[5],
                    is_static=raw[6].lower() == "true",
                    is_component=raw[7].lower() == "true",
                    line=int(raw[8]),
                )
            )
    return rows


def match_inventory_path(asset_path: str, inventory_paths: set[str]) -> tuple[str | None, str]:
    target = norm_path(asset_path)
    target_lower = target.lower()
    exact = [p for p in inventory_paths if p.lower() == target_lower]
    if len(exact) == 1:
        return exact[0], "high"
    suffix = [
        p for p in inventory_paths
        if p.lower().endswith("/" + target_lower) or target_lower.endswith("/" + p.lower())
    ]
    if len(suffix) == 1:
        return suffix[0], "medium"
    return None, "unresolved"


def choose_types(
    script_path: str, methods: list[CallableRow], hinted_type: str = ""
) -> tuple[list[str], str]:
    resolved_component_types = sorted({m.type_name for m in methods if m.is_component})
    # A scene/prefab m_Script attachment is itself positive component evidence.
    # none-mode databases frequently cannot resolve UnityEngine.MonoBehaviour,
    # so requiring the inheritance edge here would erase every real instance.
    declared_types = sorted({m.type_name for m in methods})
    candidate_types = resolved_component_types or declared_types
    if not candidate_types:
        return [], "unresolved"
    hinted_matches = [name for name in candidate_types if name == hinted_type]
    if len(hinted_matches) == 1:
        return hinted_matches, "high" if resolved_component_types else "medium"
    stem = Path(script_path).stem.lower()
    stem_matches = [name for name in candidate_types if name.lower() == stem]
    if len(stem_matches) == 1:
        return stem_matches, "high" if resolved_component_types else "medium"
    if len(candidate_types) == 1:
        return candidate_types, "medium"
    return [], "ambiguous"


def sentinel_sections() -> list[tuple[str, list[list[object]]]]:
    return [
        ("unityComponentReferenceModel", [["__NONE__", "__NONE__", "__NONE__", "none"]]),
        ("unityExecutionOrderModel", [["__NONE__", 0, "none"]]),
    ]


def load_optional_rows(path: Path | None, columns: list[str]) -> list[list[object]]:
    if not path or not path.exists():
        return []
    output: list[list[object]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            output.append([int(row[c]) if c == "line" else row[c] for c in columns])
    return output


def emit_model(path: Path, sections: list[tuple[str, list[list[object]]]]) -> None:
    lines = ["extensions:"]
    for predicate, rows in sections:
        lines.extend([
            "  - addsTo:",
            "      pack: my-org/csharp-custom-queries",
            f"      extensible: {predicate}",
            "    data:",
        ])
        for row in rows:
            lines.append("      - " + yaml_row(row))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--unity-analysis", required=True, type=Path)
    parser.add_argument("--guid-mapping", type=Path)
    parser.add_argument("--output-pack", required=True, type=Path)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--node-bindings", type=Path,
                        help="optional CSV: script_path,line,role,component_id,object_id,confidence")
    parser.add_argument("--inspector-bindings", type=Path,
                        help="UnityInspectorBindingAnalyzer CSV for exact UnityEvent targets")
    parser.add_argument("--component-references", type=Path,
                        help="optional CSV: owner_component_id,field_path,target_component_id,confidence")
    parser.add_argument("--disable-serialized-references", action="store_true",
                        help="skip automatic same-asset .unity/.prefab component reference recovery")
    parser.add_argument("--execution-order", type=Path,
                        help="optional CSV: type_name,order_value,provenance")
    parser.add_argument(
        "--coverage-manifest", type=Path,
        help=(
            "optional CSV: script_path,type_name,coverage,provenance; complete is "
            "accepted only with verified-no-dynamic-instantiation, closed-world-build, "
            "or test-fixture provenance. Omitted types remain partial/open-world"
        ),
    )
    parser.add_argument("--ram", type=int, default=2048, help="CodeQL query RAM limit in MB")
    parser.add_argument("--codeql-search-path", help="override CodeQL pack search path")
    parser.add_argument("--codeql-additional-packs", help="high-priority local CodeQL pack root")
    parser.add_argument("--codeql-home", type=Path, help="workspace-local HOME for CodeQL caches")
    parser.add_argument("--codeql", default="codeql")
    parser.add_argument("--query-root", type=Path,
                        default=Path(__file__).resolve().parents[2])
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()

    if args.codeql_home:
        codeql_home = str(args.codeql_home.resolve())
        Path(codeql_home).mkdir(parents=True, exist_ok=True)
        os.environ["HOME"] = codeql_home
        os.environ["USERPROFILE"] = codeql_home

    output_pack = args.output_pack.resolve()
    work_dir = (args.work_dir or output_pack / "intermediate").resolve()
    models_dir = output_pack / "models"
    work_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    inventory_query = args.query_root / "tests" / "UnityCallableInventory.ql"
    inventory_bqrs = work_dir / "unity_callable_inventory.bqrs"
    inventory_csv = work_dir / "unity_callable_inventory.csv"
    search_path = args.codeql_search_path or f"{args.query_root};{Path.home() / '.codeql' / 'packages'}"
    inventory_command = [
        args.codeql, "query", "run", str(inventory_query),
        f"--database={args.database}", f"--output={inventory_bqrs}",
        "--search-path", search_path, f"--ram={args.ram}",
    ]
    if args.codeql_additional_packs:
        inventory_command.extend(["--additional-packs", args.codeql_additional_packs])
    run_checked(inventory_command)
    run_checked([
        args.codeql, "bqrs", "decode", str(inventory_bqrs), "--format=csv",
        f"--output={inventory_csv}",
    ])

    inventory = read_inventory(inventory_csv)
    by_path: dict[str, list[CallableRow]] = defaultdict(list)
    for method in inventory:
        by_path[method.script_path].append(method)
    inventory_paths = set(by_path)
    guid_map = load_guid_map(args.guid_mapping)
    unity_ir = json.loads(args.unity_analysis.read_text(encoding="utf-8-sig"))

    component_rows: list[list[object]] = []
    modeled_components: dict[tuple[str, str], str] = {}
    entry_rows: set[tuple[object, ...]] = set()
    qa_components: list[dict[str, object]] = []
    scene_items = unity_ir.items() if isinstance(unity_ir, dict) else []
    for raw_asset_path, scene in scene_items:
        asset_path = unity_asset_relative(str(raw_asset_path), args.project_root)
        for game_object in scene.get("gameobjects", []):
            game_object_id = str(game_object.get("fileID", "unknown"))
            game_object_name = str(game_object.get("name", ""))
            active = game_object.get("active")
            active_state = "active" if active is True else "inactive" if active is False else "unknown"
            for component in game_object.get("components", []):
                component_file_id = str(component.get("fileID", "unknown"))
                raw_script = str(component.get("script_path") or "")
                guid = str(component.get("script_guid") or "").lower()
                if not raw_script and guid:
                    raw_script = guid_map.get(guid, "")
                normalized_script = unity_asset_relative(raw_script, args.project_root) if raw_script else ""
                matched_path, path_confidence = match_inventory_path(normalized_script, inventory_paths)
                types, type_confidence = choose_types(
                    matched_path or normalized_script,
                    by_path.get(matched_path or "", []),
                    str(component.get("type_name") or ""),
                )
                confidence = (
                    "high" if path_confidence == "high" and type_confidence == "high"
                    else "medium" if matched_path and types
                    else "unresolved"
                )
                component_id = f"{args.project_id}:{asset_path}#component:{component_file_id}"
                qa = {
                    "asset_path": asset_path,
                    "game_object_id": game_object_id,
                    "game_object_name": game_object_name,
                    "component_file_id": component_file_id,
                    "component_id": component_id,
                    "raw_script_path": raw_script,
                    "normalized_script_path": normalized_script,
                    "matched_codeql_path": matched_path,
                    "candidate_types": types,
                    "confidence": confidence,
                }
                qa_components.append(qa)
                if confidence not in {"high", "medium"}:
                    continue
                for type_name in types:
                    component_rows.append([
                        args.project_id, asset_path, game_object_id, game_object_name,
                        component_id, matched_path, type_name, active_state, confidence,
                    ])
                    modeled_components[(asset_path.lower(), component_file_id)] = component_id
                    for method in by_path[matched_path]:
                        if method.type_name == type_name and method.method_name in LIFECYCLE_NAMES:
                            entry_rows.add((matched_path, type_name, method.method_name,
                                            method.method_name, confidence))

    node_rows = load_optional_rows(
        args.node_bindings,
        ["script_path", "line", "role", "component_id", "object_id", "confidence"],
    )
    entry_instance_rows: list[list[object]] = []
    inspector_reference_rows: list[list[object]] = []
    serialized_event_rows: list[list[object]] = []
    inspector_modeled = 0
    runtime_event_binding_rows = 0
    runtime_event_binding_qa: list[dict[str, object]] = []
    if args.inspector_bindings and args.inspector_bindings.exists():
        known_component_ids = {str(row[4]) for row in component_rows}
        with args.inspector_bindings.open("r", encoding="utf-8-sig", newline="") as handle:
            for binding in csv.DictReader(handle):
                type_name = (binding.get("target_component_type") or "").strip()
                target_assembly_type = (
                    binding.get("target_assembly_type") or ""
                ).split(",", 1)[0].strip()
                method_name = (binding.get("target_method") or "").strip()
                target_file_id = (binding.get("target_file_id") or "").strip()
                if not type_name or type_name == "Unknown" or not method_name or not target_file_id:
                    continue
                runtime_event_binding_rows += 1
                matches = [
                    method for method in inventory
                    if method.type_name == type_name and method.method_name == method_name
                ]
                script_paths = sorted({method.script_path for method in matches})
                is_engine_target = target_assembly_type.startswith("UnityEngine.")
                if len(script_paths) == 1:
                    script_path = script_paths[0]
                elif is_engine_target:
                    # Engine-owned persistent listeners are real runtime
                    # callbacks even though their implementation is outside
                    # project source. The QL layer resolves the external method
                    # when Unity assemblies are present in the CodeQL database.
                    script_path = "@engine/UnityEngine"
                else:
                    continue
                asset_path = unity_asset_relative(
                    binding.get("source_file") or "", args.project_root
                )
                target_object_key = "name:" + (binding.get("target_gameobject") or "unknown")
                component_id = f"{args.project_id}:{asset_path}#component:{target_file_id}"
                object_id = (
                    f"asset:{asset_path}|gameObject:{target_object_key}"
                    f"|component:{component_id}"
                )
                confidence = "high"
                if component_id not in known_component_ids and not is_engine_target:
                    component_rows.append([
                        args.project_id, asset_path, target_object_key,
                        binding.get("target_gameobject") or "", component_id,
                        script_path, type_name, "unknown", confidence,
                    ])
                    known_component_ids.add(component_id)
                if not is_engine_target:
                    entry_instance_rows.append([
                        script_path, type_name, method_name, component_id, object_id,
                        asset_path, confidence,
                    ])
                # Inspector YAML identifies the concrete script attached to the
                # component. An event field may be declared on this type or on a
                # base class; UnitySerializedConfig resolves that declaration via
                # the CodeQL type hierarchy instead of treating this as the field
                # declaring type.
                attached_type = (binding.get("source_component_type") or "").strip()
                source_file_id = (binding.get("source_file_id") or "").strip()
                attached_paths = sorted({
                    method.script_path for method in inventory
                    if method.type_name == attached_type
                })
                if source_file_id and len(attached_paths) == 1:
                    owner_component_id = (
                        f"{args.project_id}:{asset_path}#component:{source_file_id}"
                    )
                    if owner_component_id not in known_component_ids:
                        source_object_key = "name:" + (
                            binding.get("source_gameobject") or "unknown"
                        )
                        component_rows.append([
                            args.project_id, asset_path, source_object_key,
                            binding.get("source_gameobject") or "", owner_component_id,
                            attached_paths[0], attached_type, "unknown", confidence,
                        ])
                        known_component_ids.add(owner_component_id)
                    inspector_reference_rows.append([
                        owner_component_id,
                        "event:" + (binding.get("event_field") or "unknown"),
                        component_id,
                        confidence,
                    ])
                    listener_mode = (binding.get("call_type") or "dynamic").strip().lower()
                    call_state = (binding.get("call_state") or "2").strip()
                    try:
                        parameter_index = int((binding.get("param_index") or "0").strip())
                    except ValueError:
                        parameter_index = -1
                    if listener_mode == "dynamic" and parameter_index >= 0 and call_state in {"1", "2"}:
                        serialized_event_rows.append([
                            attached_paths[0], attached_type, owner_component_id,
                            binding.get("event_field") or "", script_path, type_name,
                            component_id, method_name, parameter_index, parameter_index,
                            "dynamic", call_state, asset_path, confidence,
                        ])
                runtime_event_binding_qa.append({
                    "asset_path": asset_path,
                    "event_field": binding.get("event_field") or "",
                    "owner_type": attached_type,
                    "target_type": target_assembly_type or type_name,
                    "target_method": method_name,
                    "call_state": binding.get("call_state") or "2",
                    "runtime_executable": "true",
                    "codeql_materialization": (
                        "ready" if source_file_id and len(attached_paths) == 1
                        else "runtime-binding-only: source event implementation is external/unresolved"
                    ),
                })
                inspector_modeled += 1
    entry_instance_rows = [list(row) for row in sorted({tuple(row) for row in entry_instance_rows})]
    serialized_reference_rows: list[list[object]] = []
    serialized_reference_qa: list[dict[str, object]] = []
    serialized_assets_scanned = 0
    if not args.disable_serialized_references:
        serialized_reference_rows, serialized_reference_qa, serialized_assets_scanned = (
            discover_serialized_component_references(
                args.project_root, [str(path) for path, _ in scene_items], modeled_components
            )
        )
    reference_rows = inspector_reference_rows + serialized_reference_rows + load_optional_rows(
        args.component_references,
        ["owner_component_id", "field_path", "target_component_id", "confidence"],
    )
    reference_rows = [list(row) for row in sorted({tuple(row) for row in reference_rows})]
    serialized_event_rows = [
        list(row) for row in sorted({tuple(row) for row in serialized_event_rows})
    ]
    serialized_event_invocation_rows = discover_unity_event_invocations(
        args.project_root, inventory, (str(row[3]) for row in serialized_event_rows)
    )
    order_rows = load_optional_rows(
        args.execution_order, ["type_name", "order_value", "provenance"]
    )

    accepted_complete_provenance = {
        "verified-no-dynamic-instantiation", "closed-world-build", "test-fixture"
    }
    coverage_rows = load_optional_rows(
        args.coverage_manifest,
        ["script_path", "type_name", "coverage", "provenance"],
    )
    normalized_coverage: dict[tuple[str, str], list[object]] = {}
    for row in coverage_rows:
        script_path, type_name, coverage, provenance = map(str, row)
        script_path = norm_path(script_path)
        coverage = coverage.strip().lower()
        provenance = provenance.strip().lower()
        if coverage not in {"partial", "complete"}:
            raise ValueError(
                f"invalid coverage '{coverage}' for {script_path}:{type_name}"
            )
        if coverage == "complete" and provenance not in accepted_complete_provenance:
            raise ValueError(
                "complete coverage requires explicit closed-world provenance for "
                f"{script_path}:{type_name}; got '{provenance}'"
            )
        normalized_coverage[(script_path, type_name)] = [
            script_path, type_name, coverage, provenance
        ]

    # Asset recovery is open-world by default: scenes/prefabs do not prove that
    # Instantiate, Addressables, AssetBundles, or runtime loading creates no more
    # instances. Consequently a discovered exact instance never suppresses the
    # unknown fallback unless a separate coverage manifest proves completeness.
    for component_row in component_rows:
        script_path = str(component_row[5])
        type_name = str(component_row[6])
        normalized_coverage.setdefault(
            (script_path, type_name),
            [script_path, type_name, "partial", "asset-scan-open-world"],
        )
    coverage_rows = [
        normalized_coverage[key] for key in sorted(normalized_coverage)
    ]

    sections = [
        ("unityComponentInstanceModel", component_rows or [
            ["__NONE__", "__NONE__", "__NONE__", "__NONE__", "__NONE__",
             "__NONE__", "__NONE__", "__NONE__", "none"]
        ]),
        ("unityLifecycleEntryModel", [list(row) for row in sorted(entry_rows)] or [
            ["__NONE__", "__NONE__", "__NONE__", "__NONE__", "none"]
        ]),
        ("unityNodeInstanceModel", node_rows or [
            ["__NONE__", 0, "none", "__NONE__", "__NONE__", "none"]
        ]),
        ("unityEntryInstanceModel", entry_instance_rows or [
            ["__NONE__", "__NONE__", "__NONE__", "__NONE__", "__NONE__", "__NONE__", "none"]
        ]),
        ("unityComponentReferenceModel", reference_rows or sentinel_sections()[0][1]),
        ("unityExecutionOrderModel", order_rows or sentinel_sections()[1][1]),
        ("unityInstanceCoverageModel", coverage_rows or [[
            "__NONE__", "__NONE__", "partial", "none"
        ]]),
        ("unitySerializedUnityEventBindingModel", serialized_event_rows or [[
            "__NONE__", "__NONE__", "__NONE__", "__NONE__", "__NONE__", "__NONE__",
            "__NONE__", "__NONE__", -1, -1, "none", "0", "__NONE__", "none"
        ]]),
        ("unitySerializedUnityEventInvocationModel", serialized_event_invocation_rows or [[
            "__NONE__", "__NONE__", 0, "none"
        ]]),
    ]

    pack_name = "my-org/vrtaint-unity-instance-models"
    (output_pack / "qlpack.yml").write_text(
        "\n".join([
            f"name: {pack_name}", "version: 1.0.0", "library: true",
            "extensionTargets:", "  my-org/csharp-custom-queries: ^0.3.0",
            "dataExtensions:", "  - models/*.model.yml", "",
        ]), encoding="utf-8"
    )
    # project_id is a semantic identifier and may legitimately contain '/' or
    # '\\' (for example owner/repository). It must not be interpreted as a
    # filesystem path when naming the generated data-extension file.
    model_slug = re.sub(r"[^A-Za-z0-9._-]+", "_", args.project_id).strip("._-") or "project"
    model_file = models_dir / f"{model_slug}.instance.model.yml"
    emit_model(model_file, sections)

    script_bearing = [item for item in qa_components if item["raw_script_path"]]
    project_owned = [
        item for item in script_bearing
        if str(item["normalized_script_path"]).lower().startswith("assets/")
    ]
    resolved = [item for item in qa_components if item["confidence"] in {"high", "medium"}]
    resolved_project_owned = [
        item for item in project_owned if item["confidence"] in {"high", "medium"}
    ]
    summary = {
        "schema_version": "unity-instance-model/v4",
        "project_id": args.project_id,
        "project_root": str(args.project_root.resolve()),
        "database": str(args.database.resolve()),
        "unity_analysis": str(args.unity_analysis.resolve()),
        "inventory_method_count": len(inventory),
        "ir_component_count": len(qa_components),
        "script_bearing_component_count": len(script_bearing),
        "project_owned_script_component_count": len(project_owned),
        "modeled_component_rows": len(component_rows),
        "modeled_component_instance_count": len(resolved),
        "modeled_lifecycle_entry_rows": len(entry_rows),
        "exact_node_binding_rows": len(node_rows),
        "exact_event_entry_binding_rows": len(entry_instance_rows),
        "inspector_binding_rows_modeled": inspector_modeled,
        "runtime_event_binding_rows": runtime_event_binding_rows,
        "serialized_event_flow_rows": len(serialized_event_rows),
        "serialized_event_invocation_rows": len(serialized_event_invocation_rows),
        "serialized_assets_scanned": serialized_assets_scanned,
        "serialized_reference_candidates": len(serialized_reference_qa),
        "serialized_component_reference_rows": len(serialized_reference_rows),
        "component_reference_rows": len(reference_rows),
        "instance_coverage_rows": len(coverage_rows),
        "complete_instance_coverage_rows": sum(
            1 for row in coverage_rows if str(row[2]) == "complete"
        ),
        "unknown_instance_fallback_preserved": any(
            str(row[2]) != "complete" for row in coverage_rows
        ) or not coverage_rows,
        "unresolved_component_count": sum(
            1 for item in qa_components if item["confidence"] == "unresolved"
        ),
        "all_component_coverage_ratio": (
            len(resolved) / len(qa_components) if qa_components else 0.0
        ),
        "script_bearing_coverage_ratio": (
            len(resolved) / len(script_bearing) if script_bearing else 0.0
        ),
        "project_owned_coverage_ratio": (
            len(resolved_project_owned) / len(project_owned) if project_owned else 0.0
        ),
        "model_pack": str(output_pack),
        "model_file": str(model_file),
    }
    (output_pack / "semantic_model_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with (output_pack / "component_join_qa.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fieldnames = list(qa_components[0].keys()) if qa_components else ["confidence"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(qa_components)
    with (output_pack / "serialized_reference_qa.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        fieldnames = [
            "asset_path", "line", "owner_file_id", "field_path", "target_file_id", "status"
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(serialized_reference_qa)

    with (output_pack / "runtime_event_binding_qa.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        fieldnames = [
            "asset_path", "event_field", "owner_type", "target_type",
            "target_method", "call_state", "runtime_executable",
            "codeql_materialization",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(runtime_event_binding_qa)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"[error] {error}", file=sys.stderr)
        raise

