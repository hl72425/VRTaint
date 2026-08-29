#!/usr/bin/env python3
"""Generic external semantic fact provider for Unity/CodeQL analyses.

The provider converts Unity scene/YAML bindings plus an existing scene IR into
stable, project-neutral facts.  No project name, callback name, or component
type is hard-coded.  The CodeQL layer consumes the headerless seed CSV through
an external predicate; the named CSV/JSON files are intended for inspection and
post-processing.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


SEED_COLUMNS = [
    "fact_id", "script_path", "type_name", "method_name", "parameter_index",
    "object_id", "access_path", "phase", "context", "source_kind",
    "influence_kind", "confidence",
]
EDGE_COLUMNS = [
    "edge_id", "caller_script_path", "caller_type", "caller_method",
    "caller_parameter_index", "callee_script_path", "callee_type", "callee_method",
    "callee_parameter_index", "edge_kind", "confidence",
]
EXPR_SEED_COLUMNS = [
    "fact_id", "script_path", "line", "object_id", "access_path", "phase",
    "context", "source_kind", "influence_kind", "confidence",
]
COMPONENT_COLUMNS = [
    "binding_id", "asset_kind", "asset_path", "game_object_id", "game_object_name",
    "component_id", "component_type", "script_guid", "script_path", "confidence",
]
CONTEXT_KEYS = [
    "schema", "project", "scene", "game_object", "component", "script",
    "entry", "callable", "event", "thread", "coroutine", "async",
]


@dataclass(frozen=True)
class SemanticSeedFact:
    fact_id: str
    script_path: str
    type_name: str
    method_name: str
    parameter_index: int
    object_id: str
    access_path: str
    phase: str
    context: str
    source_kind: str
    influence_kind: str
    confidence: str


@dataclass(frozen=True)
class SemanticMethodEdgeFact:
    edge_id: str
    caller_script_path: str
    caller_type: str
    caller_method: str
    caller_parameter_index: int
    callee_script_path: str
    callee_type: str
    callee_method: str
    callee_parameter_index: int
    edge_kind: str
    confidence: str


@dataclass(frozen=True)
class SemanticExprSeedFact:
    fact_id: str
    script_path: str
    line: int
    object_id: str
    access_path: str
    phase: str
    context: str
    source_kind: str
    influence_kind: str
    confidence: str


def discover_component_bindings(project_root: Path, source_root: Path,
                                guid_map: dict[str, str]) -> list[dict[str, Any]]:
    class_cache: dict[str, str] = {}
    bindings: dict[str, dict[str, Any]] = {}
    for pattern in ("*.unity", "*.prefab"):
        for asset in (project_root / "Assets").rglob(pattern):
            try:
                text = asset.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue
            blocks = split_unity_blocks(text)
            go_names = {fid: (find_scalar(body, "m_Name") or "UNKNOWN").strip()
                        for class_id, fid, body in blocks if class_id == 1}
            rel_asset = norm_path(asset.relative_to(project_root))
            for _, component_id, body in blocks:
                guid = find_script_guid(body)
                script = guid_map.get(guid or "", "")
                if not guid or not script:
                    continue
                go_id = find_file_id(body, "m_GameObject")
                component_type = class_name_for_script(project_root, script, class_cache)
                disk = (project_root / Path(script)).resolve()
                try:
                    relative_script = norm_path(disk.relative_to(source_root))
                except ValueError:
                    relative_script = norm_path(script)
                binding_id = stable_id("component", rel_asset, go_id, component_id, guid)
                bindings[binding_id] = {
                    "binding_id": binding_id,
                    "asset_kind": "Scene" if asset.suffix == ".unity" else "Prefab",
                    "asset_path": rel_asset,
                    "game_object_id": go_id if go_id is not None else "UNKNOWN",
                    "game_object_name": go_names.get(go_id, "UNKNOWN"),
                    "component_id": component_id, "component_type": component_type,
                    "script_guid": guid, "script_path": relative_script, "confidence": "high",
                }
    return sorted(bindings.values(), key=lambda b: (b["asset_path"], str(b["component_id"])))


class SemanticFactProvider(ABC):
    """Adapter interface. New engines only need to implement build()."""

    @abstractmethod
    def build(self) -> tuple[list[SemanticSeedFact], list[SemanticExprSeedFact], list[SemanticMethodEdgeFact], dict[str, Any]]:
        raise NotImplementedError


def norm_path(value: str | Path) -> str:
    return str(value).replace("\\", "/")


def canonical_asset_path(value: str) -> str:
    """Normalize absolute, project-relative, and dataset-relative GUID paths."""
    value = norm_path(value).lstrip("./")
    marker = "/Assets/"
    if marker in "/" + value:
        return "Assets/" + ("/" + value).split(marker, 1)[1]
    return value


def stable_id(*parts: object) -> str:
    raw = "\x1f".join(str(p) for p in parts).encode("utf-8")
    return "USF-" + hashlib.sha256(raw).hexdigest()[:16]


def make_context(*, project: str, scene: str, game_object: str, component: str,
                 script: str, entry: str, callable_name: str, event: str,
                 thread: str = "MainThread", coroutine: str = "NONE",
                 async_state: str = "NONE") -> str:
    values = {
        "schema": "unity-context/v1", "project": project, "scene": scene,
        "game_object": game_object, "component": component, "script": script,
        "entry": entry, "callable": callable_name, "event": event,
        "thread": thread, "coroutine": coroutine, "async": async_state,
    }
    normalized = {key: (values[key] if values[key] not in (None, "") else "UNKNOWN")
                  for key in CONTEXT_KEYS}
    return json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))


def read_guid_map(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            guid = (row.get("GUID") or row.get("guid") or "").strip()
            asset = (row.get("AssetPath") or row.get("asset_path") or "").strip()
            if guid and asset:
                out[guid] = canonical_asset_path(asset)
    return out


def load_ir(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("unity_analysis.json root must be an object keyed by scene path")
    return data


def split_unity_blocks(text: str) -> list[tuple[int, int, str]]:
    marker = re.compile(r"^--- !u!(\d+) &(\-?\d+).*$", re.MULTILINE)
    hits = list(marker.finditer(text))
    blocks: list[tuple[int, int, str]] = []
    for i, hit in enumerate(hits):
        end = hits[i + 1].start() if i + 1 < len(hits) else len(text)
        blocks.append((int(hit.group(1)), int(hit.group(2)), text[hit.start():end]))
    return blocks


def find_scalar(block: str, key: str) -> str | None:
    m = re.search(rf"^\s*{re.escape(key)}:\s*(.*?)\s*$", block, re.MULTILINE)
    return m.group(1) if m else None


def find_file_id(block: str, key: str) -> int | None:
    m = re.search(rf"^\s*{re.escape(key)}:\s*\{{fileID:\s*(\-?\d+)", block, re.MULTILINE)
    return int(m.group(1)) if m else None


def find_script_guid(block: str) -> str | None:
    m = re.search(r"^\s*m_Script:\s*\{fileID:\s*\d+,\s*guid:\s*([0-9a-fA-F]+)", block, re.MULTILINE)
    return m.group(1) if m else None


def class_name_for_script(project_root: Path, asset_path: str, cache: dict[str, str]) -> str:
    if asset_path in cache:
        return cache[asset_path]
    disk = project_root / Path(asset_path)
    name = Path(asset_path).stem
    try:
        source = disk.read_text(encoding="utf-8-sig", errors="replace")
        # Prefer the Unity component class matching the file stem; then use the
        # first declared class as a structural fallback.
        names = re.findall(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b", source)
        if name in names:
            value = name
        elif names:
            value = names[0]
        else:
            value = name
    except OSError:
        value = name
    cache[asset_path] = value
    return value


def method_parameter_count(project_root: Path, asset_path: str, method: str) -> int | None:
    disk = project_root / Path(asset_path)
    try:
        source = disk.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None
    # This is deliberately a declaration locator, not a C# parser. CodeQL does
    # final method/type/parameter matching against the compiled database.
    pattern = re.compile(rf"\b{re.escape(method)}\s*\(([^)]*)\)")
    m = pattern.search(source)
    if not m:
        return None
    body = m.group(1).strip()
    if not body:
        return 0
    return len([x for x in body.split(",") if x.strip()])


def matching_brace(text: str, opening: int) -> int | None:
    depth = 0
    state = "code"
    i = opening
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if ch == '"': state = "string"
            elif ch == "'": state = "char"
            elif ch == "/" and nxt == "/": state = "line"; i += 1
            elif ch == "/" and nxt == "*": state = "block"; i += 1
            elif ch == "{": depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0: return i
        elif state == "string":
            if ch == "\\": i += 1
            elif ch == '"': state = "code"
        elif state == "char":
            if ch == "\\": i += 1
            elif ch == "'": state = "code"
        elif state == "line" and ch == "\n": state = "code"
        elif state == "block" and ch == "*" and nxt == "/": state = "code"; i += 1
        i += 1
    return None


def discover_project_methods(project_root: Path, source_root: Path) -> list[dict[str, Any]]:
    methods: list[dict[str, Any]] = []
    method_re = re.compile(
        r"(?m)^\s*(?:\[[^\]]+\]\s*)*(?:(?:public|private|protected|internal|static|virtual|override|async|sealed|new|extern)\s+)*"
        r"[A-Za-z_][A-Za-z0-9_<>,.\[\]?\s]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}()]*)\)\s*\{")
    class_re = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b")
    scan_root = source_root if source_root.exists() else project_root
    for path in scan_root.rglob("*.cs"):
        if any(p.lower() in {"library", "temp", "obj", "bin", "packagecache"} for p in path.parts):
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        classes = list(class_re.finditer(text))
        for m in method_re.finditer(text):
            opening = m.end() - 1
            closing = matching_brace(text, opening)
            if closing is None:
                continue
            cls = next((c.group(1) for c in reversed(classes) if c.start() < m.start()), None)
            if not cls:
                continue
            params_raw = m.group(2).strip()
            params: list[str] = []
            if params_raw:
                for raw in params_raw.split(","):
                    raw = re.sub(r"\[[^\]]+\]", "", raw).strip()
                    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", raw.split("=")[0])
                    if tokens:
                        params.append(tokens[-1])
            try:
                relative = norm_path(path.resolve().relative_to(source_root))
            except ValueError:
                relative = norm_path(path.resolve().relative_to(project_root))
            methods.append({
                "script_path": relative, "type": cls, "method": m.group(1),
                "params": params, "body": text[opening + 1:closing],
                "body_start_line": text.count("\n", 0, opening + 1) + 1,
            })
    return methods


def discover_expression_seeds(project_root: Path, source_root: Path,
                              guid_map: dict[str, str]) -> list[SemanticExprSeedFact]:
    methods = discover_project_methods(project_root, source_root)
    lifecycle_names = {
        "Reset", "Awake", "OnEnable", "Start", "FixedUpdate", "Update", "LateUpdate",
        "OnGUI", "OnDisable", "OnDestroy", "OnApplicationPause", "OnApplicationQuit",
    }
    by_type: dict[str, list[dict[str, Any]]] = {}
    for method in methods:
        by_type.setdefault(method["type"], []).append(method)

    def entry_for(method: dict[str, Any]) -> str:
        if method["method"] in lifecycle_names or re.match(r"^On[A-Z0-9_]", method["method"]):
            return method["method"]
        frontier = [method["method"]]
        visited = set(frontier)
        while frontier:
            callee = frontier.pop(0)
            for candidate in by_type.get(method["type"], []):
                if not re.search(rf"\b{re.escape(callee)}\s*\(", candidate["body"]):
                    continue
                name = candidate["method"]
                if name in lifecycle_names or re.match(r"^On[A-Z0-9_]", name):
                    return name
                if name not in visited:
                    visited.add(name); frontier.append(name)
        return "Unbound"

    facts: dict[str, SemanticExprSeedFact] = {}
    guid_by_script = {canonical_asset_path(asset): guid for guid, asset in guid_map.items()}
    yaml_cache: list[tuple[Path, str]] = []
    for ext in ("*.unity", "*.prefab"):
        for asset in (project_root / "Assets").rglob(ext):
            try:
                yaml_cache.append((asset, asset.read_text(encoding="utf-8-sig", errors="replace")))
            except OSError:
                pass

    def bindings(script_path: str, type_name: str) -> list[tuple[str, str, str]]:
        asset_path = "Assets/" + script_path if not script_path.startswith("Assets/") else script_path
        guid = guid_by_script.get(asset_path)
        found: list[tuple[str, str, str]] = []
        if guid:
            for yaml_path, text in yaml_cache:
                if guid not in text:
                    continue
                rel = norm_path(yaml_path.relative_to(project_root))
                kind = "Scene" if yaml_path.suffix == ".unity" else "Prefab"
                for _, component_id, block in split_unity_blocks(text):
                    if find_script_guid(block) != guid:
                        continue
                    go_id = find_file_id(block, "m_GameObject")
                    name = "UNKNOWN"
                    for class_id, fid, go_block in split_unity_blocks(text):
                        if class_id == 1 and fid == go_id:
                            name = (find_scalar(go_block, "m_Name") or "UNKNOWN").strip(); break
                    found.append((rel, name, f"{type_name}#{component_id}"))
        return found or [("UNKNOWN", "UNKNOWN", f"{type_name}#*")]
    xr_pattern = re.compile(r"\bTryGetFeatureValue\s*\([^,]+,\s*out\s+(?:[A-Za-z_][A-Za-z0-9_.<>]*\s+)?([A-Za-z_][A-Za-z0-9_]*)")
    for method in methods:
        phase = entry_for(method)
        for match in xr_pattern.finditer(method["body"]):
            line = method["body_start_line"] + method["body"].count("\n", 0, match.start())
            fact_id = stable_id("expr", method["script_path"], line, match.group(1), "XRInput")
            for asset_path, go, component in bindings(method["script_path"], method["type"]):
                bound_id = stable_id(fact_id, asset_path, component)
                facts[bound_id] = SemanticExprSeedFact(
                    fact_id=bound_id, script_path=method["script_path"], line=line,
                    object_id=(f"asset:{asset_path}|gameObject:{go}|component:{component}" if asset_path != "UNKNOWN"
                               else f"{method['type']}#*"),
                    access_path=f"local.{match.group(1)}", phase=phase,
                    context=make_context(project=project_root.name,
                                         scene=asset_path if asset_path.endswith(".unity") else "UNKNOWN",
                                         game_object=go, component=component,
                                         script=method["script_path"], entry=phase,
                                         callable_name=method["method"], event="XRInput"),
                    source_kind="XRInput", influence_kind="data", confidence="high")
    return sorted(facts.values(), key=lambda f: (f.script_path, f.line, f.fact_id))


def discover_high_precision_edges(project_root: Path, source_root: Path) -> list[SemanticMethodEdgeFact]:
    methods = discover_project_methods(project_root, source_root)
    declarations: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for m in methods:
        declarations.setdefault((m["type"], m["method"], len(m["params"])), []).append(m)
    edges: dict[str, SemanticMethodEdgeFact] = {}
    # Receiver type is explicit in these common Unity forms. Calls without a
    # type anchor are excluded to prevent name-only edges.
    patterns = [
        ("unity-generic-receiver", re.compile(
            r"(?:FindObjectOfType|FindFirstObjectByType|FindAnyObjectByType|GetComponent|GetComponentInChildren|GetComponentInParent)\s*<\s*"
            r"(?P<type>[A-Za-z_][A-Za-z0-9_.]*)\s*>\s*\([^;]*?\)\s*\.\s*(?P<method>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^()]*)\)")),
        ("typed-singleton-receiver", re.compile(
            r"(?P<type>[A-Z][A-Za-z0-9_.]*)\s*\.\s*(?:GetInstance\s*\(\s*\)|instance|Instance)\s*\.\s*"
            r"(?P<method>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^()]*)\)")),
    ]
    for caller in methods:
        for edge_kind, pattern in patterns:
            for call in pattern.finditer(caller["body"]):
                callee_type = call.group("type").split(".")[-1]
                callee_method = call.group("method")
                args = [x.strip() for x in call.group("args").split(",")] if call.group("args").strip() else []
                candidates = declarations.get((callee_type, callee_method, len(args)), [])
                if len(candidates) != 1:
                    continue
                callee = candidates[0]
                for callee_index, arg in enumerate(args):
                    # Remove explicit casts and balanced superficial parentheses;
                    # accept only a single caller parameter identifier.
                    clean = re.sub(r"\([A-Za-z_][A-Za-z0-9_.<>]*\)", "", arg)
                    clean = clean.strip().strip("() ")
                    if clean not in caller["params"]:
                        continue
                    caller_index = caller["params"].index(clean)
                    edge_id = stable_id("edge", caller["script_path"], caller["type"], caller["method"],
                                        caller_index, callee["script_path"], callee_type, callee_method, callee_index)
                    edges[edge_id] = SemanticMethodEdgeFact(
                        edge_id, caller["script_path"], caller["type"], caller["method"], caller_index,
                        callee["script_path"], callee_type, callee_method, callee_index,
                        edge_kind, "high")
    return sorted(edges.values(), key=lambda e: (e.caller_script_path, e.caller_method,
                                                 e.callee_script_path, e.callee_method))


def scene_object_index(scene_ir: dict[str, Any]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    gos = scene_ir.get("gameobjects") or {}
    if isinstance(gos, dict):
        iterator = gos.values()
    elif isinstance(gos, list):
        iterator = gos
    else:
        iterator = []
    for item in iterator:
        if not isinstance(item, dict):
            continue
        raw_id = item.get("fileID", item.get("file_id", item.get("id")))
        try:
            out[int(raw_id)] = item
        except (TypeError, ValueError):
            pass
    return out


def go_name(go: dict[str, Any] | None, fallback: int | None) -> str:
    if go:
        for key in ("name", "m_Name", "gameObjectName"):
            if go.get(key) not in (None, ""):
                return str(go[key])
    return f"GameObject#{fallback}" if fallback is not None else "GameObject#*"


def persistent_calls(block: str) -> list[dict[str, Any]]:
    lines = block.splitlines()
    calls: list[dict[str, Any]] = []
    event_stack: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        key_match = re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*):\s*$", line)
        if key_match:
            indent = len(key_match.group(1))
            key = key_match.group(2)
            event_stack = [(d, k) for d, k in event_stack if d < indent]
            event_stack.append((indent, key))
        method_match = re.match(r"^(\s*)m_MethodName:\s*(.*?)\s*$", line)
        if not method_match or not method_match.group(2):
            i += 1
            continue
        start = max(0, i - 8)
        end = min(len(lines), i + 18)
        window = "\n".join(lines[start:end])
        target = re.search(r"m_Target:\s*\{fileID:\s*(\-?\d+)", window)
        mode = re.search(r"m_Mode:\s*(\d+)", window)
        event_name = next((k for _, k in reversed(event_stack)
                           if k not in {"m_Calls", "m_PersistentCalls", "m_Arguments",
                                        "m_IntArgument", "m_FloatArgument", "m_StringArgument",
                                        "m_BoolArgument", "m_ObjectArgument", "m_ObjectArgumentAssemblyTypeName"}),
                          "UnityEvent")
        args: dict[str, str] = {}
        for key in ("m_IntArgument", "m_FloatArgument", "m_StringArgument", "m_BoolArgument"):
            v = re.search(rf"{key}:[ \t]*([^\r\n]*)", window)
            if v:
                args[key] = v.group(1)
        calls.append({
            "method": method_match.group(2).strip(),
            "target_file_id": int(target.group(1)) if target else None,
            "mode": int(mode.group(1)) if mode else 0,
            "event": event_name,
            "arguments": args,
        })
        i += 1
    return calls


class UnityYamlFactProvider(SemanticFactProvider):
    def __init__(self, project_root: Path, unity_analysis: Path, guid_mapping: Path,
                 codeql_database: Path | None = None):
        self.project_root = project_root.resolve()
        self.ir = load_ir(unity_analysis)
        self.guid_map = read_guid_map(guid_mapping)
        self.codeql_source_root = self.project_root
        if codeql_database:
            yml = codeql_database / "codeql-database.yml"
            if yml.exists():
                raw = yml.read_text(encoding="utf-8-sig", errors="replace")
                m = re.search(r"^sourceLocationPrefix:\s*['\"]?(.*?)['\"]?\s*$", raw, re.MULTILINE)
                if m:
                    candidate = Path(m.group(1).strip())
                    if candidate.exists():
                        self.codeql_source_root = candidate.resolve()

    def codeql_relative_script(self, asset_path: str) -> str:
        disk = (self.project_root / Path(asset_path)).resolve()
        try:
            return norm_path(disk.relative_to(self.codeql_source_root))
        except ValueError:
            return norm_path(asset_path)

    def build(self) -> tuple[list[SemanticSeedFact], list[SemanticExprSeedFact], list[SemanticMethodEdgeFact], dict[str, Any]]:
        facts: list[SemanticSeedFact] = []
        callbacks: list[dict[str, Any]] = []
        class_cache: dict[str, str] = {}
        missing_scenes: list[str] = []

        for scene_key, scene_ir in sorted(self.ir.items()):
            scene_path = norm_path(scene_key)
            disk_scene = self.project_root / Path(scene_path)
            if not disk_scene.exists():
                missing_scenes.append(scene_path)
                continue
            text = disk_scene.read_text(encoding="utf-8-sig", errors="replace")
            blocks = split_unity_blocks(text)
            component_map: dict[int, dict[str, Any]] = {}
            go_blocks: dict[int, dict[str, Any]] = {}
            for class_id, file_id, body in blocks:
                if class_id == 1:
                    go_blocks[file_id] = {
                        "name": (find_scalar(body, "m_Name") or f"GameObject#{file_id}").strip(),
                        "active": (find_scalar(body, "m_IsActive") or "").strip(),
                    }
                guid = find_script_guid(body)
                if guid:
                    component_map[file_id] = {
                        "guid": guid,
                        "script_path": self.guid_map.get(guid, ""),
                        "game_object_id": find_file_id(body, "m_GameObject"),
                    }

            ir_objects = scene_object_index(scene_ir if isinstance(scene_ir, dict) else {})
            for class_id, owner_component_id, body in blocks:
                owner_go_id = find_file_id(body, "m_GameObject")
                owner_go = ir_objects.get(owner_go_id) or go_blocks.get(owner_go_id)
                for call in persistent_calls(body):
                    target_component = component_map.get(call["target_file_id"])
                    if not target_component or not target_component.get("script_path"):
                        callbacks.append({
                            "scene": scene_path, "owner_component_id": owner_component_id,
                            **call, "status": "unresolved_target_script",
                        })
                        continue
                    asset_path = target_component["script_path"]
                    target_go_id = target_component.get("game_object_id")
                    target_go = ir_objects.get(target_go_id) or go_blocks.get(target_go_id)
                    type_name = class_name_for_script(self.project_root, asset_path, class_cache)
                    parameter_count = method_parameter_count(self.project_root, asset_path, call["method"])
                    object_id = f"scene:{scene_path}|go:{target_go_id}|component:{call['target_file_id']}"
                    common_context = make_context(
                        project=self.project_root.name,
                        scene=scene_path,
                        game_object=go_name(target_go, target_go_id),
                        component=f"{type_name}#{call['target_file_id']}",
                        script=self.codeql_relative_script(asset_path),
                        entry="Unbound",
                        callable_name=call["method"],
                        event=call["event"],
                    )
                    mode = call["mode"]
                    # EventDefined (0) passes runtime event arguments. Other
                    # PersistentListenerMode values use serialized arguments.
                    if mode == 0:
                        source_kind = "UnityEventArgument"
                        influence = "data"
                        confidence = "high"
                    else:
                        source_kind = "UnitySerializedConstant"
                        influence = "configuration"
                        confidence = "high"
                    if parameter_count is None:
                        status = "method_declaration_unresolved"
                    else:
                        # Every resolved UnityEvent callback has a control fact,
                        # including zero-argument callbacks. parameter_index=-1
                        # marks a semantic-only fact that is not injected as a
                        # CodeQL data node.
                        facts.append(SemanticSeedFact(
                            fact_id=stable_id(scene_path, owner_component_id, call["event"],
                                              call["target_file_id"], call["method"], "control"),
                            script_path=self.codeql_relative_script(asset_path),
                            type_name=type_name,
                            method_name=call["method"],
                            parameter_index=-1,
                            object_id=object_id,
                            access_path="@control",
                            phase="Unbound",
                            context=common_context,
                            source_kind="UnityEventControl",
                            influence_kind="control",
                            confidence="high",
                        ))
                        status = "control_only_callback" if parameter_count == 0 else "seeded"
                    if parameter_count is not None and parameter_count > 0:
                        # Unity persistent listeners in this representation bind
                        # one serialized/dynamic argument; overload resolution is
                        # completed by CodeQL against this parameter index.
                        fact = SemanticSeedFact(
                            fact_id=stable_id(scene_path, owner_component_id, call["event"],
                                              call["target_file_id"], call["method"], mode, 0),
                            script_path=self.codeql_relative_script(asset_path),
                            type_name=type_name,
                            method_name=call["method"],
                            parameter_index=0,
                            object_id=object_id,
                            access_path="arg[0]",
                            phase="Unbound",
                            context=common_context,
                            source_kind=source_kind,
                            influence_kind=influence,
                            confidence=confidence,
                        )
                        facts.append(fact)
                    callbacks.append({
                        "scene": scene_path,
                        "owner_component_id": owner_component_id,
                        "owner_game_object_id": owner_go_id,
                        "target_component_id": call["target_file_id"],
                        "target_game_object_id": target_go_id,
                        "script_path": asset_path,
                        "type_name": type_name,
                        "parameter_count": parameter_count,
                        **call,
                        "status": status,
                    })

        unique = {asdict(f)["fact_id"]: f for f in facts}
        facts = sorted(unique.values(), key=lambda f: (f.script_path, f.method_name, f.context, f.fact_id))
        edges = discover_high_precision_edges(self.project_root, self.codeql_source_root)
        expr_facts = discover_expression_seeds(self.project_root, self.codeql_source_root, self.guid_map)
        component_bindings = discover_component_bindings(
            self.project_root, self.codeql_source_root, self.guid_map)
        status_counts: dict[str, int] = {}
        for callback in callbacks:
            status = callback.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
        zero_reason = "NONE"
        if not facts and not expr_facts:
            if not callbacks:
                zero_reason = "NO_SERIALIZED_CALLBACKS_IN_ANALYZED_SCENES_AND_NO_EXTERNAL_SEMANTIC_FACTS"
            elif status_counts.get("method_declaration_unresolved", 0) == len(callbacks):
                zero_reason = "SERIALIZED_METHODS_NOT_PRESENT_IN_CURRENT_SOURCE"
            elif status_counts.get("unresolved_target_script", 0) == len(callbacks):
                zero_reason = "CALLBACK_TARGETS_ARE_EXTERNAL_OR_GUID_UNRESOLVED"
            else:
                zero_reason = "NO_DATA_BEARING_OR_RESOLVED_CONTROL_FACTS"
        metadata = {
            "schema": "semantic-taint-facts/v1",
            "adapter": "unity-yaml-v1",
            "project_root": str(self.project_root),
            "codeql_source_root": str(self.codeql_source_root),
            "scene_count": len(self.ir),
            "missing_scenes": missing_scenes,
            "seed_count": len(facts),
            "codeql_seed_count": sum(1 for f in facts if f.parameter_index >= 0),
            "semantic_only_seed_count": sum(1 for f in facts if f.parameter_index < 0),
            "callback_count": len(callbacks),
            "method_edge_count": len(edges),
            "expression_seed_count": len(expr_facts),
            "component_binding_count": len(component_bindings),
            "callback_status_counts": status_counts,
            "external_fact_zero_reason": zero_reason,
            "callbacks": callbacks,
            "component_bindings": component_bindings,
        }
        return facts, expr_facts, edges, metadata


def write_outputs(output_dir: Path, facts: list[SemanticSeedFact], expr_facts: list[SemanticExprSeedFact],
                  edges: list[SemanticMethodEdgeFact], metadata: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = [asdict(f) for f in facts]
    with (output_dir / "semantic_seed_facts.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator="\n")
        for row in rows:
            writer.writerow([row[c] for c in SEED_COLUMNS])
    with (output_dir / "semantic_seed_facts_named.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SEED_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (output_dir / "semantic_seed_facts.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    expr_rows = [asdict(f) for f in expr_facts]
    with (output_dir / "semantic_expr_seed_facts.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator="\n")
        for row in expr_rows:
            writer.writerow([row[c] for c in EXPR_SEED_COLUMNS])
    with (output_dir / "semantic_expr_seed_facts_named.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=EXPR_SEED_COLUMNS, lineterminator="\n")
        writer.writeheader(); writer.writerows(expr_rows)
    component_rows = metadata.get("component_bindings", [])
    with (output_dir / "semantic_component_bindings.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COMPONENT_COLUMNS, lineterminator="\n")
        writer.writeheader(); writer.writerows(component_rows)
    (output_dir / "semantic_component_bindings.json").write_text(
        json.dumps(component_rows, ensure_ascii=False, indent=2), encoding="utf-8")
    codeql_rows = [row for row in rows if int(row["parameter_index"]) >= 0]
    with (output_dir / "semantic_codeql_seed_facts.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator="\n")
        for row in codeql_rows:
            writer.writerow([row[c] for c in SEED_COLUMNS])
    (output_dir / "semantic_callback_facts.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    edge_rows = [asdict(e) for e in edges]
    with (output_dir / "semantic_method_edge_facts.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator="\n")
        for row in edge_rows:
            writer.writerow([row[c] for c in EDGE_COLUMNS])
    with (output_dir / "semantic_method_edge_facts_named.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=EDGE_COLUMNS, lineterminator="\n")
        writer.writeheader(); writer.writerows(edge_rows)
    (output_dir / "semantic_method_edge_facts.json").write_text(
        json.dumps(edge_rows, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = {k: v for k, v in metadata.items() if k not in {"callbacks", "component_bindings"}}
    (output_dir / "semantic_fact_stats.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description="Generate generic Unity semantic taint facts")
    p.add_argument("--adapter", default="unity-yaml-v1", choices=["unity-yaml-v1"])
    p.add_argument("--project-root", required=True, type=Path)
    p.add_argument("--unity-analysis", required=True, type=Path)
    p.add_argument("--guid-mapping", required=True, type=Path)
    p.add_argument("--codeql-database", type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    a = p.parse_args()
    provider: SemanticFactProvider = UnityYamlFactProvider(
        a.project_root, a.unity_analysis, a.guid_mapping, a.codeql_database)
    facts, expr_facts, edges, metadata = provider.build()
    write_outputs(a.output_dir, facts, expr_facts, edges, metadata)
    print(json.dumps({"seed_count": len(facts), "expression_seed_count": len(expr_facts), "method_edge_count": len(edges),
                      "output_dir": str(a.output_dir.resolve())}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
