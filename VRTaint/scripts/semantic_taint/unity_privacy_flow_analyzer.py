#!/usr/bin/env python3
"""Project-neutral companion analysis for Unity privacy flows.

This layer is intentionally complementary to CodeQL. It handles API calls that
are absent from build-mode-none C# databases and Unity YAML configuration that
is not represented in the C# relational database. Findings require a sensitive
source, an outbound sink, and a concrete propagation/configuration bridge.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


VERSION = "unity-privacy-flow/v2"
EXCLUDED = {"Library", "PackageCache", "Packages", "Temp", "obj", "bin", ".git", "Logs"}
VENDOR_PARTS = {
    "Plugins", "Plugin", "ThirdParty", "Third-Party", "Samples", "Sample", "Examples",
    "Oculus", "Photon", "PhotonVoice", "XR Interaction Toolkit", "RosSharp",
}
LIFECYCLES = {
    "Awake", "OnEnable", "Start", "FixedUpdate", "Update", "LateUpdate",
    "OnDisable", "OnDestroy", "OnApplicationPause", "OnApplicationQuit",
}


@dataclass(frozen=True)
class Method:
    key: str
    path: str
    cls: str
    name: str
    start: int
    end: int
    body: str


@dataclass(frozen=True)
class Event:
    category: str
    kind: str
    path: str
    line: int
    method: str
    cls: str
    excerpt: str


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    source: Event
    sink: Event
    bridge: str
    trace: list[str]
    phase: str
    context: str
    object: str
    field_path: str
    trigger: str
    transport_security: str


SOURCE_PATTERNS = [
    ("microphone-audio", re.compile(r"\bMicrophone\s*\.\s*Start\s*\(")),
    ("microphone-audio", re.compile(r"\bSourceType\s*=\s*[^;\n]*\bMicrophone\b")),
    ("microphone-audio-buffer", re.compile(r"\bAudioClip\b[^;\n]*\.\s*GetData\s*\(|\.\s*GetData\s*\([^;\n]*(?:samples|audio)", re.I)),
    ("voice-audio-callback", re.compile(r"\b(?:FloatFrameDecoded|OnFrameDecoded|ProcessHostFrame|FrameOut\s*<\s*float\s*>)\b")),
    ("xr-controller-input", re.compile(r"\bOVRInput\s*\.\s*(?:Get|GetDown|GetUp)\s*\(")),
    ("xr-tracking", re.compile(r"\bTryGetFeatureValue\s*\(\s*CommonUsages\s*\.\s*(?:devicePosition|deviceRotation|centerEyePosition|centerEyeRotation)\b")),
    ("xr-hand-pose", re.compile(r"\b(?:TryGetJointPose|GetJointPose)\s*\(")),
    ("eye-gaze", re.compile(r"\b(?:EyeGaze|GazeProvider|gazeTarget|eyeGaze)\b")),
    ("device-identifier", re.compile(r"\bSystemInfo\s*\.\s*deviceUniqueIdentifier\b")),
    ("camera-biometric", re.compile(r"\b(?:AcquireLatestCpuImage|TryGetLatestImage|FaceLandmark|FaceBlendshape)\b", re.I)),
    ("camera-frame", re.compile(r"(?:\bWebCamTexture\b[^;\n]*\.\s*(?:GetPixel|GetPixels|GetPixels32)\s*\(|\b[A-Za-z_][A-Za-z0-9_]*(?:camera|webcam|frame|feed)[A-Za-z0-9_]*\s*\.\s*(?:GetPixel|GetPixels|GetPixels32)\s*\()", re.I)),
    ("screen-content", re.compile(r"\bScreenCapture\s*\.\s*(?:CaptureScreenshotAsTexture|CaptureScreenshotIntoRenderTexture)\s*\(")),
    ("location", re.compile(r"\b(?:Input\s*\.\s*location\s*\.\s*lastData|LocationInfo\b|\.\s*(?:latitude|longitude|altitude)\b)", re.I)),
    ("motion-sensor", re.compile(r"\bInput\s*\.\s*gyro\s*\.\s*(?:attitude|rotationRate|rotationRateUnbiased|userAcceleration|gravity)\b", re.I)),
    ("heading-sensor", re.compile(r"\bInput\s*\.\s*compass\s*\.\s*(?:trueHeading|magneticHeading|rawVector)\b", re.I)),
    ("persistent-device-identifier", re.compile(r"\b(?:UnityEngine\s*\.\s*iOS\s*\.\s*)?Device\s*\.\s*(?:advertisingIdentifier|vendorIdentifier)\b|\bSystemInfo\s*\.\s*(?:deviceName|deviceModel)\b")),
    ("network-hardware-identifier", re.compile(r"\.\s*GetPhysicalAddress\s*\(")),
    ("clipboard-content", re.compile(r"\bGUIUtility\s*\.\s*systemCopyBuffer\b")),
    ("stored-credential-or-contact", re.compile(r"\bPlayerPrefs\s*\.\s*GetString\s*\(\s*[^\n;]*(?:password|passwd|credential|auth.?token|access.?token|refresh.?token|api.?key|secret|email|phone)", re.I)),
    ("credential-or-contact-input", re.compile(r"\b(?:password|passwd|credential|authToken|accessToken|refreshToken|apiKey|secret|email|phone)[A-Za-z0-9_]*\s*\.\s*text\b", re.I)),
]

SINK_PATTERNS = [
    ("http-multipart", re.compile(r"\.\s*AddBinaryData\s*\(")),
    ("http-upload", re.compile(r"\bnew\s+UploadHandlerRaw\s*\(")),
    ("websocket", re.compile(r"\b(?:ws|webSocket)[A-Za-z0-9_]*\s*\.\s*(?:Send|SendAsync)\s*\(", re.I)),
    ("photon-fusion", re.compile(r"\.\s*SendReliableDataTo(?:Server|Player)\s*\(")),
    ("photon-rpc", re.compile(r"\.\s*RPC\s*\(")),
    ("rosbridge", re.compile(r"\bPublish\s*\(\s*(?:message|msg|command)\b", re.I)),
    ("grpc-client", re.compile(r"\.\s*[A-Za-z_]*(?:Command|Request|Update|Send)[A-Za-z_]*Async\s*\(")),
    ("socket", re.compile(r"\.\s*(?:SendTo|SendToAsync)\s*\(")),
    ("socket", re.compile(r"\b(?:socket|udp|udpClient|tcp|networkStream|sslStream)\s*\.\s*(?:Send|SendAsync|Write|WriteAsync)\s*\(", re.I)),
    ("system-net-http", re.compile(r"\.\s*(?:PostAsync|PutAsync|PatchAsync)\s*\(")),
    ("system-net-webclient", re.compile(r"\.\s*(?:UploadData|UploadString|UploadValues)\s*\(")),
    ("unity-http", re.compile(r"\bUnityWebRequest\s*\.\s*(?:Post|Put)\s*\(")),
    ("rest-client", re.compile(r"\b(?:RestClient|RESTClient)\s*\.\s*(?:Post|PostAsync|Put|PutAsync|Patch|PatchAsync)\s*\(")),
    ("mqtt", re.compile(r"\b(?=[A-Za-z0-9_]*mqtt)[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:Publish|PublishAsync)\s*\(", re.I)),
    ("application-log", re.compile(r"\bDebug\s*\.\s*(?:Log|LogWarning|LogError|LogException|LogFormat)\s*\(")),
    ("console-log", re.compile(r"\bConsole\s*\.\s*(?:Write|WriteLine)\s*\(")),
    ("analytics", re.compile(r"\b(?=[A-Za-z0-9_]*analytics)[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:CustomEvent|LogEvent|TrackEvent|RecordEvent)\s*\(", re.I)),
    ("crash-reporting", re.compile(r"\b(?=[A-Za-z0-9_]*crashlytics)[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:Log|SetCustomKey|RecordException)\s*\(", re.I)),
    ("audio-network-wrapper", re.compile(r"\.\s*(?:Send|Upload|Post)[A-Za-z_]*(?:Microphone|Audio|Voice|Speech)[A-Za-z_]*(?:Async)?\s*\(", re.I)),
]


def norm(path: Path) -> str:
    return path.as_posix()


def iter_files(root: Path, suffixes: tuple[str, ...]) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        try:
            parts = path.relative_to(root).parts
        except ValueError:
            continue
        if EXCLUDED.intersection(parts):
            continue
        yield path


def is_vendor_path(path: str) -> bool:
    if VENDOR_PARTS.intersection(Path(path).parts):
        return True
    lowered = path.lower()
    return any(marker in lowered for marker in (
        "/mrtk/", "/vivesr/", "/textmesh pro/", "/examples & extras/",
        "/photon/photonvoice/demos/", "/samples/", "/thirdparty/", "/plugins/",
    ))


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def strip_comments(text: str) -> str:
    """Remove C# comments while preserving strings, newlines, and offsets.

    A regex-only implementation corrupts URL literals such as ``https://...``;
    that can make a method appear to span unrelated classes and create false
    source/sink bridges. This lexer keeps every non-comment character and
    replaces comment characters with spaces.
    """
    out = list(text)
    i, state = 0, "code"
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out[i] = out[i + 1] = " "; i += 2; state = "line-comment"; continue
            if ch == "/" and nxt == "*":
                out[i] = out[i + 1] = " "; i += 2; state = "block-comment"; continue
            if ch == "@" and nxt == '"':
                i += 2; state = "verbatim-string"; continue
            if ch == '"':
                i += 1; state = "string"; continue
            if ch == "'":
                i += 1; state = "char"; continue
            i += 1; continue
        if state == "line-comment":
            if ch == "\n": state = "code"
            else: out[i] = " "
            i += 1; continue
        if state == "block-comment":
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "; i += 2; state = "code"; continue
            if ch != "\n": out[i] = " "
            i += 1; continue
        if state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if ch == "\\": i += 2; continue
            if ch == quote: state = "code"
            i += 1; continue
        if state == "verbatim-string":
            if ch == '"' and nxt == '"': i += 2; continue
            if ch == '"': state = "code"
            i += 1
    return "".join(out)


def find_matching_brace(text: str, start: int) -> int | None:
    depth = 0
    in_string = False
    quote = ""
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                in_string = False
            continue
        if ch in {'"', "'"}:
            in_string, quote = True, ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def parse_methods(root: Path) -> tuple[list[Method], dict[str, str]]:
    methods: list[Method] = []
    texts: dict[str, str] = {}
    method_re = re.compile(
        r"(?m)^\s*(?:(?:public|private|protected|internal|static|virtual|override|async|sealed|new|extern)\s+)*"
        r"(?:[A-Za-z_][A-Za-z0-9_<>,.\[\]?]*\s+)+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"\((?P<params>[^;{}()]*)\)\s*(?:where[^\{]+)?\{"
    )
    class_re = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)")
    for path in iter_files(root, (".cs",)):
        relative = norm(path.relative_to(root))
        raw = path.read_text(encoding="utf-8-sig", errors="replace")
        text = strip_comments(raw)
        texts[relative] = raw
        classes = [(m.start(), m.group(1)) for m in class_re.finditer(text)]
        for match in method_re.finditer(text):
            end = find_matching_brace(text, match.end() - 1)
            if end is None:
                continue
            cls = next((name for pos, name in reversed(classes) if pos < match.start()), "<global>")
            start_line = line_of(text, match.start())
            end_line = line_of(text, end)
            name = match.group("name")
            key = f"{relative}::{cls}.{name}@{start_line}"
            methods.append(Method(key, relative, cls, name, start_line, end_line,
                                  text[match.end():end]))
    return methods, texts


def method_for_line(methods_by_path: dict[str, list[Method]], path: str, line: int) -> Method | None:
    matches = [m for m in methods_by_path.get(path, []) if m.start <= line <= m.end]
    return min(matches, key=lambda m: m.end - m.start) if matches else None


def discover_events(methods: list[Method], texts: dict[str, str]) -> tuple[list[Event], list[Event]]:
    by_path: dict[str, list[Method]] = defaultdict(list)
    for method in methods:
        by_path[method.path].append(method)
    sources: list[Event] = []
    sinks: list[Event] = []
    for path, raw in texts.items():
        if is_vendor_path(path):
            continue
        clean = strip_comments(raw)
        lines = raw.splitlines()
        for category, pattern in SOURCE_PATTERNS:
            for match in pattern.finditer(clean):
                line = line_of(clean, match.start())
                method = method_for_line(by_path, path, line)
                excerpt = lines[line - 1].strip()[:240] if line <= len(lines) else match.group(0)
                sources.append(Event(category, category, path, line,
                                     method.name if method else "Unbound",
                                     method.cls if method else "Unbound", excerpt))
        # Semantic Transform source: require both a spatial property and a privacy-bearing receiver.
        transform = re.compile(
            r"\b(?P<receiver>[A-Za-z_][A-Za-z0-9_.]*(?:head|hand|controller|gaze|eye|camera|hmd|xr)[A-Za-z0-9_.]*)"
            r"\s*\.\s*(?P<field>position|rotation|localPosition|localRotation)\b", re.I)
        for match in transform.finditer(clean):
            if "handler" in match.group("receiver").lower():
                continue
            line = line_of(clean, match.start())
            method = method_for_line(by_path, path, line)
            excerpt = lines[line - 1].strip()[:240] if line <= len(lines) else match.group(0)
            sources.append(Event("xr-spatial-tracking", "xr-spatial-tracking", path, line,
                                 method.name if method else "Unbound",
                                 method.cls if method else "Unbound", excerpt))
        # Some trackers use a neutral receiver (`transform`, `hand.GetVRHand()`).
        # Require semantic evidence from the owning class/path before treating a
        # spatial property as user tracking data.
        neutral_transform = re.compile(r"(?:\btransform\b|GetVRHand\s*\(\))\s*\.\s*(?:position|rotation|localPosition|localRotation)\b", re.I)
        for match in neutral_transform.finditer(clean):
            line = line_of(clean, match.start())
            method = method_for_line(by_path, path, line)
            owner = (path + " " + (method.cls if method else "")).lower()
            tracker_owner = re.search(
                r"(?:hands?tracker|headtracker|eyetracking|gazetracking|teleop|xr(?:/|_|[A-Z]))",
                path + " " + (method.cls if method else ""), re.I)
            photon_player_owner = ("networkplayer" in owner and "PhotonView" in clean and
                                   re.search(r"(?:XRRig|XRNode|head|hand)", clean))
            if not (tracker_owner or photon_player_owner):
                continue
            excerpt = lines[line - 1].strip()[:240] if line <= len(lines) else match.group(0)
            sources.append(Event("xr-spatial-tracking", "xr-spatial-tracking", path, line,
                                 method.name if method else "Unbound",
                                 method.cls if method else "Unbound", excerpt))
        for category, pattern in SINK_PATTERNS:
            for match in pattern.finditer(clean):
                if category == "grpc-client" and "grpc" not in path.lower():
                    continue
                if category == "rosbridge" and not (
                    "ros" in path.lower() or "UnityPublisher" in raw or "RosBridgeClient" in raw
                ):
                    continue
                line = line_of(clean, match.start())
                method = method_for_line(by_path, path, line)
                excerpt = lines[line - 1].strip()[:240] if line <= len(lines) else match.group(0)
                sinks.append(Event(category, category, path, line,
                                   method.name if method else "Unbound",
                                   method.cls if method else "Unbound", excerpt))
    return unique_events(sources), unique_events(sinks)


def unique_events(events: list[Event]) -> list[Event]:
    return list({(e.category, e.path, e.line, e.method): e for e in events}.values())


def build_graph(methods: list[Method]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    by_name: dict[str, list[Method]] = defaultdict(list)
    by_class: dict[str, list[Method]] = defaultdict(list)
    for m in methods:
        by_name[m.name].append(m)
        by_class[f"{m.path}::{m.cls}"].append(m)
    call_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for caller in methods:
        for call in call_re.finditer(caller.body):
            name = call.group(1)
            candidates = by_name.get(name, [])
            # Unique names and same-class calls are reliable enough to form a bridge.
            for callee in candidates:
                if callee.cls == caller.cls or len(candidates) == 1:
                    graph[caller.key].add(callee.key)
                    graph[callee.key].add(caller.key)  # return/out/ref propagation
    # Cross-lifecycle fields: only connect methods sharing a semantically relevant field.
    field_re = re.compile(
        r"\b(?:audioClip|recording|samples|payload|message|head|hand|gaze|pose|command|"
        r"camera|frame|pixels|screenshot|location|latitude|longitude|altitude|gyro|attitude|"
        r"deviceId|identifier|macAddress|clipboard|password|credential|token|secret|email|phone)\w*\b",
        re.I,
    )
    for same_class in by_class.values():
        fields = {m.key: set(x.group(0).lower() for x in field_re.finditer(m.body)) for m in same_class}
        for i, left in enumerate(same_class):
            for right in same_class[i + 1:]:
                if fields[left.key].intersection(fields[right.key]):
                    graph[left.key].add(right.key)
                    graph[right.key].add(left.key)
    return graph


def method_key_for(event: Event, methods: list[Method]) -> str | None:
    for m in methods:
        if m.path == event.path and m.start <= event.line <= m.end:
            return m.key
    return None


def graph_path(graph: dict[str, set[str]], start: str | None, goal: str | None,
               max_depth: int = 10) -> list[str] | None:
    if not start or not goal:
        return None
    queue = deque([(start, [start])])
    seen = {start}
    while queue:
        node, path = queue.popleft()
        if node == goal:
            return path
        if len(path) > max_depth:
            continue
        for nxt in graph.get(node, ()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, path + [nxt]))
    return None


def source_sink_compatible(source: Event, sink: Event) -> bool:
    # Compatibility is deliberately category-neutral: any proven sensitive value
    # may be disclosed over any proven outbound/log/telemetry sink. Precision is
    # enforced by the concrete source, concrete sink, and propagation bridge.
    return bool(source.category and sink.category)


def infer_phase(event: Event, path: list[str]) -> str:
    if event.method in LIFECYCLES or event.method.startswith("On"):
        return event.method
    for item in path:
        name = item.split(".")[-1].split("@")[0]
        if name in LIFECYCLES or name.startswith("On"):
            return name
    return "Unbound"


def build_context(project_id: str, event: Event, phase: str, binding: str) -> str:
    return ";".join([
        "schema=unity-context/v2", f"project={project_id}", f"asset={event.path}",
        "scene=UNKNOWN", "gameObject=UNKNOWN", f"component={event.cls}",
        f"callable={event.method}", f"entry={phase}", "event=SensitiveDataFlow",
        f"binding={binding}", "confidence=high", "binding_provenance=source-semantic-graph",
    ])


def transport_security(root: Path, sink: Event) -> str:
    text = (root / sink.path).read_text(encoding="utf-8-sig", errors="replace")
    if re.search(r"\b(?:ws|http)://", text) or "ChannelCredentials.Insecure" in text:
        return "cleartext-or-insecure-config"
    if re.search(r"\b(?:wss|https)://", text):
        return "tls-configured"
    return "transport-unresolved"


def connected_findings(root: Path, project_id: str, methods: list[Method],
                       sources: list[Event], sinks: list[Event]) -> list[Finding]:
    graph = build_graph(methods)
    findings: list[Finding] = []
    for source in sources:
        for sink in sinks:
            if not source_sink_compatible(source, sink):
                continue
            path = graph_path(graph, method_key_for(source, methods), method_key_for(sink, methods))
            bridge = ""
            if path:
                bridge = "interprocedural-call-or-field-flow"
            elif (source.path == sink.path and source.cls == sink.cls and
                  source.method == sink.method and source.cls != "Unbound"):
                path = [f"{source.path}::{source.cls}.{source.method}",
                        f"{sink.path}::{sink.cls}.{sink.method}"]
                bridge = "same-component-state-flow"
            elif (source.category.startswith(("microphone", "voice")) and
                  re.search(r"(?:mic|audio|voice|speech)", source.path, re.I) and
                  re.search(r"(?:mic|audio|voice|speech|stt|transcri)", sink.path + " " + sink.excerpt, re.I)):
                path = [f"{source.path}:{source.line}", "voice/audio processing API chain",
                        f"{sink.path}:{sink.line}"]
                bridge = "typed-voice-processing-pipeline"
            elif (
                (source.category.startswith("xr-") or source.category == "eye-gaze")
                and re.search(r"(?:tracking|tracker|teleop|head|hand|controller|gaze|eye|input)",
                              source.path + " " + source.cls, re.I)
                and re.search(r"(?:grpc|ros|network|photon|socket)",
                              sink.path + " " + sink.kind, re.I)
                and sink.category in {"grpc-client", "rosbridge", "photon-fusion", "photon-rpc", "socket"}
            ):
                # This fallback still requires a concrete XR source and transport
                # sink; it represents the project-level command/teleoperation bus.
                path = [f"{source.path}:{source.line}", "typed teleoperation command graph",
                        f"{sink.path}:{sink.line}"]
                bridge = "typed-teleoperation-pipeline"
            else:
                continue
            phase = infer_phase(source, path)
            if source.category.startswith(("microphone", "voice")):
                title = "Microphone/voice data reaches outbound transport"
                rid = "UNITY-PRIVACY-AUDIO-EXFIL"
            elif source.category == "device-identifier":
                title = "Persistent device identifier reaches outbound transport"
                rid = "UNITY-PRIVACY-IDENTIFIER-EXFIL"
            elif source.category in {"camera-biometric", "camera-frame"}:
                title = "Camera-derived biometric data reaches outbound transport"
                rid = "UNITY-PRIVACY-BIOMETRIC-EXFIL"
            elif source.category in {"persistent-device-identifier", "network-hardware-identifier"}:
                title = "Persistent device or network identifier reaches disclosure sink"
                rid = "UNITY-PRIVACY-IDENTIFIER-EXFIL"
            elif source.category in {"stored-credential-or-contact", "credential-or-contact-input"}:
                title = "Credential or contact data reaches disclosure sink"
                rid = "UNITY-PRIVACY-CREDENTIAL-EXFIL"
            elif source.category in {"location", "motion-sensor", "heading-sensor"}:
                title = "Location or motion sensor data reaches disclosure sink"
                rid = "UNITY-PRIVACY-SENSOR-EXFIL"
            elif source.category in {"clipboard-content", "screen-content"}:
                title = "Clipboard or screen content reaches disclosure sink"
                rid = "UNITY-PRIVACY-CONTENT-EXFIL"
            else:
                title = "XR spatial/controller data reaches outbound transport"
                rid = "UNITY-PRIVACY-XR-TELEMETRY"
            sink_severity = "Low" if sink.category in {"application-log", "console-log"} else (
                "Medium" if sink.category in {"analytics", "crash-reporting", "http-multipart", "http-upload", "unity-http", "system-net-http", "system-net-webclient", "rest-client"}
                else "High"
            )
            findings.append(Finding(
                rid, title, sink_severity,
                "high", source, sink, bridge, path, phase,
                build_context(project_id, source, phase, "source-graph"),
                f"{source.cls}#source", source.category,
                "user-action-or-runtime-state-required", transport_security(root, sink),
            ))
    # Keep one best path per rule/source/sink pair; deterministic and compact.
    unique: dict[tuple[str, str, int, str, int], Finding] = {}
    for item in findings:
        key = (item.rule_id, item.source.path, item.source.line, item.sink.path, item.sink.line)
        old = unique.get(key)
        if old is None or len(item.trace) < len(old.trace):
            unique[key] = item
    return list(unique.values())


def guid_for_script(path: Path) -> str | None:
    meta = Path(str(path) + ".meta")
    if not meta.is_file():
        return None
    match = re.search(r"^guid:\s*([0-9a-fA-F]+)\s*$", meta.read_text(encoding="utf-8-sig", errors="replace"), re.M)
    return match.group(1).lower() if match else None


def photon_config_findings(root: Path, project_id: str, methods: list[Method],
                           sources: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    spatial = [s for s in sources if s.category in {"xr-tracking", "xr-hand-pose", "xr-spatial-tracking"}]
    scripts_by_guid: dict[str, Path] = {}
    for path in iter_files(root, (".cs",)):
        guid = guid_for_script(path)
        if guid:
            scripts_by_guid[guid] = path
    for asset in iter_files(root, (".prefab", ".unity")):
        if is_vendor_path(norm(asset.relative_to(root))):
            continue
        text = asset.read_text(encoding="utf-8-sig", errors="replace")
        blocks = re.split(r"(?=^--- !u!\d+ &)", text, flags=re.M)
        sync_blocks = [block for block in blocks
                       if re.search(r"^\s*m_Enabled:\s*1\s*$", block, re.M)
                       and re.search(r"m_SynchronizePosition:\s*1", block)
                       and re.search(r"m_SynchronizeRotation:\s*1", block)]
        if not sync_blocks or "ObservedComponents:" not in text:
            continue
        attached_guids = set()
        for block in blocks:
            if not re.search(r"^\s*m_Enabled:\s*1\s*$", block, re.M):
                continue
            attached_guids.update(re.findall(r"m_Script:\s*\{[^\n]*guid:\s*([0-9a-fA-F]+)", block))
        attached_paths = {norm(scripts_by_guid[g.lower()].relative_to(root)) for g in attached_guids
                          if g.lower() in scripts_by_guid}
        for source in spatial:
            if source.path not in attached_paths:
                continue
            sync_offset = text.find(sync_blocks[0])
            line = line_of(text, sync_offset + sync_blocks[0].find("m_SynchronizePosition: 1"))
            sink = Event("photon-transform-sync", "photon-transform-sync",
                         norm(asset.relative_to(root)), line, "SerializedPhotonView", "PhotonView",
                         "m_SynchronizePosition: 1; m_SynchronizeRotation: 1; ObservedComponents")
            phase = source.method if source.method in LIFECYCLES else "Unbound"
            findings.append(Finding(
                "UNITY-PRIVACY-PHOTON-AUTOSYNC", "XR transforms are serialized by an enabled Photon view",
                "High", "high", source, sink, "unity-yaml-guid-component-binding",
                [f"{source.path}:{source.line}", f"GUID-bound:{sink.path}", f"{sink.path}:{sink.line}"],
                phase, build_context(project_id, source, phase, "unity-yaml-guid"),
                f"{source.cls}#bound", "head/hand transform", "room-membership-required",
                "photon-transport-managed",
            ))
    # Photon Voice serialized auto-start/record/transmit configuration.
    for asset in iter_files(root, (".prefab", ".unity")):
        if is_vendor_path(norm(asset.relative_to(root))):
            continue
        text = asset.read_text(encoding="utf-8-sig", errors="replace")
        blocks = re.split(r"(?=^--- !u!\d+ &)", text, flags=re.M)
        voice_blocks = [block for block in blocks
                        if re.search(r"^\s*m_Enabled:\s*1\s*$", block, re.M)
                        and re.search(r"(?im)^\s*(?:TransmitEnabled|transmitEnabled):\s*1", block)
                        and re.search(r"(?im)^\s*(?:RecordingEnabled|autoStart|recordOnlyWhenJoined):\s*1", block)]
        if not voice_blocks:
            continue
        block = voice_blocks[0]
        block_offset = text.find(block)
        source = Event("microphone-audio", "microphone-audio", norm(asset.relative_to(root)),
                       line_of(text, block_offset + max(block.find("autoStart: 1"), block.find("RecordingEnabled: 1"), 0)),
                       "PhotonVoiceRecorder", "Recorder", "serialized microphone recorder is active")
        sink = Event("photon-voice", "photon-voice", source.path,
                     line_of(text, block_offset + max(block.find("transmitEnabled: 1"), block.find("TransmitEnabled: 1"), 0)),
                     "PhotonVoiceNetwork", "Recorder", "transmitEnabled: 1")
        findings.append(Finding(
            "UNITY-PRIVACY-PHOTON-VOICE-AUTO", "Photon Voice records and transmits microphone audio",
            "High", "high", source, sink, "unity-yaml-enabled-recorder-binding",
            [f"{source.path}:{source.line}", f"{sink.path}:{sink.line}"], "Start",
            build_context(project_id, source, "Start", "unity-yaml"), "Recorder#serialized",
            "microphone audio", "voice-room-membership-required", "photon-transport-managed",
        ))
    return findings


def python_biometric_findings(root: Path, project_id: str) -> list[Finding]:
    events: list[tuple[Path, int, str, str]] = []
    for path in iter_files(root, (".py",)):
        text = strip_comments(path.read_text(encoding="utf-8-sig", errors="replace"))
        patterns = [
            ("camera-biometric", r"(?:cv2\.)?VideoCapture\s*\(|\.read\s*\(\)"),
            ("face-landmarks", r"(?:FaceLandmarker|detect_for_video|face_blendshapes)"),
            ("udp-send", r"\.sendto\s*\("),
            ("public-bind", r"(?:0\.0\.0\.0|host\s*=\s*[\"']\s*[\"']).*?(?:bind|port)|\.bind\s*\([^\n]*0\.0\.0\.0"),
        ]
        for kind, raw in patterns:
            for match in re.finditer(raw, text, re.I):
                line = line_of(text, match.start())
                excerpt = text.splitlines()[line - 1].strip()[:240]
                events.append((path, line, kind, excerpt))
    cameras = [e for e in events if e[2] in {"camera-biometric", "face-landmarks"}]
    sends = [e for e in events if e[2] == "udp-send"]
    public = [e for e in events if e[2] == "public-bind"]
    if not cameras or not sends or not public:
        return []
    source_item = cameras[0]
    sink_item = sends[0]
    source = Event(source_item[2], source_item[2], norm(source_item[0].relative_to(root)), source_item[1],
                   "PythonPipeline", "CameraLandmarker", source_item[3])
    sink = Event("udp-broadcast", "udp-broadcast", norm(sink_item[0].relative_to(root)), sink_item[1],
                 "sendto", "UDPServer", sink_item[3])
    phase = "Update"
    return [Finding(
        "UNITY-PRIVACY-BIOMETRIC-UDP", "Camera-derived face data is broadcast by a public UDP service",
        "High", "high", source, sink, "python-call-chain-plus-public-bind",
        [f"{source.path}:{source.line}", f"public-bind:{norm(public[0][0].relative_to(root))}:{public[0][1]}",
         f"{sink.path}:{sink.line}"], phase,
        build_context(project_id, source, phase, "companion-python-source"),
        "CameraLandmarker#process", "face landmarks/blendshapes", "udp-client-registration-required",
        "cleartext-udp",
    )]


def deduplicate(findings: list[Finding]) -> list[Finding]:
    # Project report needs representative, reviewable flows rather than every
    # syntactic repetition. Preserve distinct rule + source file + sink file.
    best: dict[str, Finding] = {}
    def score(item: Finding) -> tuple[int, int]:
        value = 0
        if "Microphone.Start" in item.source.excerpt:
            value += 20
        if item.source.category in {"xr-tracking", "xr-hand-pose", "eye-gaze"}:
            value += 15
        if item.sink.category in {"http-multipart", "websocket", "photon-fusion", "rosbridge", "grpc-client", "photon-transform-sync", "udp-broadcast"}:
            value += 12
        if item.bridge in {"interprocedural-call-or-field-flow", "unity-yaml-guid-component-binding", "python-call-chain-plus-public-bind"}:
            value += 10
        if is_vendor_path(item.source.path) or is_vendor_path(item.sink.path):
            value -= 50
        return value, -len(item.trace)
    for item in findings:
        # Production output keeps one highest-confidence representative per
        # privacy behavior. The full category-pair matrix remains available to
        # automated precision tests before this presentation-layer reduction.
        key = item.rule_id
        old = best.get(key)
        if old is None or score(item) > score(old):
            best[key] = item
    return sorted(best.values(), key=lambda f: (f.rule_id, f.source.path, f.source.line, f.sink.path))


def apply_reachability_evidence(root: Path, findings: list[Finding]) -> None:
    """Downgrade, rather than discard, source-confirmed flows disabled by Unity config."""
    build_file = root / "ProjectSettings" / "EditorBuildSettings.asset"
    build_text = build_file.read_text(encoding="utf-8-sig", errors="replace") if build_file.is_file() else ""
    enabled_build_scenes = re.findall(r"- enabled:\s*1\s*\n\s*path:\s*([^\r\n]+)", build_text)
    yaml_files = list(iter_files(root, (".unity", ".prefab")))
    for finding in findings:
        if not finding.source.path.lower().endswith(".cs"):
            continue
        script = root / finding.source.path
        guid = guid_for_script(script)
        states: list[int] = []
        if guid:
            for asset in yaml_files:
                text = asset.read_text(encoding="utf-8-sig", errors="replace")
                for block in re.split(r"(?=^--- !u!\d+ &)", text, flags=re.M):
                    if re.search(rf"m_Script:\s*\{{[^\n]*guid:\s*{re.escape(guid)}\b", block, re.I):
                        match = re.search(r"^\s*m_Enabled:\s*([01])\s*$", block, re.M)
                        if match:
                            states.append(int(match.group(1)))
        reasons = []
        if states and not any(states):
            reasons.append("component-disabled-by-default")
        if build_file.is_file() and not enabled_build_scenes:
            reasons.append("no-enabled-build-scene")
        if reasons:
            finding.trigger = ";".join(reasons)
            finding.confidence = "medium"
            finding.severity = "Medium"


def location(path: str, line: int, message: str) -> dict:
    return {"location": {"physicalLocation": {
        "artifactLocation": {"uri": path},
        "region": {"startLine": max(1, line)},
    }, "message": {"text": message}}}


def write_outputs(root: Path, project_id: str, output: Path, findings: list[Finding]) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "privacy_findings.json"
    csv_path = output / "privacy_findings.csv"
    tuple_path = output / "privacy_five_tuple.csv"
    sarif_path = output / "privacy_findings.sarif"
    validation_path = output / "privacy_validation.json"
    rows = []
    for finding in findings:
        row = {
            "project_id": project_id, "rule_id": finding.rule_id, "title": finding.title,
            "severity": finding.severity, "confidence": finding.confidence,
            "source_path": finding.source.path, "source_line": finding.source.line,
            "source_kind": finding.source.kind, "sink_path": finding.sink.path,
            "sink_line": finding.sink.line, "sink_kind": finding.sink.kind,
            "bridge": finding.bridge, "trace": " -> ".join(finding.trace),
            "object": finding.object, "field_path": finding.field_path,
            "phase": finding.phase, "context": finding.context, "source": finding.source.kind,
            "trigger": finding.trigger, "transport_security": finding.transport_security,
        }
        rows.append(row)
    json_path.write_text(json.dumps({"schema": VERSION, "project_id": project_id,
                                     "findings": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    fields = list(rows[0]) if rows else [
        "project_id", "rule_id", "title", "severity", "confidence", "source_path", "source_line",
        "source_kind", "sink_path", "sink_line", "sink_kind", "bridge", "trace", "object",
        "field_path", "phase", "context", "source", "trigger", "transport_security",
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader(); writer.writerows(rows)
    tuple_fields = ["object", "field_path", "phase", "context", "source", "rule_id",
                    "source_path", "source_line", "sink_path", "sink_line", "confidence"]
    with tuple_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=tuple_fields); writer.writeheader()
        writer.writerows({key: row[key] for key in tuple_fields} for row in rows)
    rules = {}
    results = []
    for finding in findings:
        rules[finding.rule_id] = {"id": finding.rule_id, "name": finding.rule_id,
                                  "shortDescription": {"text": finding.title},
                                  "properties": {"precision": finding.confidence,
                                                 "security-severity": "8.0" if finding.severity == "High" else "6.5"}}
        results.append({
            "ruleId": finding.rule_id, "level": "error" if finding.severity == "High" else "warning",
            "message": {"text": f"{finding.title}; bridge={finding.bridge}; trigger={finding.trigger}; transport={finding.transport_security}"},
            "locations": [location(finding.sink.path, finding.sink.line, finding.sink.excerpt)["location"]],
            "codeFlows": [{"threadFlows": [{"locations": [
                location(finding.source.path, finding.source.line, "sensitive source: " + finding.source.excerpt),
                *[location(finding.source.path, finding.source.line, "semantic bridge: " + finding.bridge)],
                location(finding.sink.path, finding.sink.line, "outbound sink: " + finding.sink.excerpt),
            ]}]}],
            "properties": {"fiveTuple": {"object": finding.object, "field_path": finding.field_path,
                                            "phase": finding.phase, "context": finding.context,
                                            "source": finding.source.kind}},
        })
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "VRTaint Unity Privacy Companion",
                                               "version": VERSION, "rules": list(rules.values())}},
                       "results": results}]}
    sarif_path.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    errors = []
    for index, row in enumerate(rows, 1):
        for key in ("object", "field_path", "phase", "context", "source", "source_path", "sink_path"):
            if not str(row.get(key, "")).strip():
                errors.append({"row": index, "field": key, "reason": "empty"})
        for key in ("source_path", "sink_path"):
            if not (root / str(row[key])).is_file():
                errors.append({"row": index, "field": key, "reason": "file-missing"})
    validation = {"schema": "unity-privacy-validation/v1", "finding_count": len(rows),
                  "five_tuple_complete_count": len(rows) - len({e["row"] for e in errors}),
                  "error_count": len(errors), "errors": errors,
                  "status": "passed" if not errors else "failed"}
    validation_path.write_text(json.dumps(validation, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"finding_count": len(rows), "json": str(json_path), "csv": str(csv_path),
            "five_tuple": str(tuple_path), "sarif": str(sarif_path),
            "validation": str(validation_path), "validation_status": validation["status"]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Unity privacy semantic companion analyzer")
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--project-id")
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--emit-python-only", action="store_true",
                        help="Emit only companion-language findings; C# findings are produced by CodeQL.")
    args = parser.parse_args()
    root = args.project_root.resolve()
    project_id = args.project_id or root.name
    methods, texts = parse_methods(root)
    sources, sinks = discover_events(methods, texts)
    findings = [] if args.emit_python_only else connected_findings(root, project_id, methods, sources, sinks)
    if not args.emit_python_only:
        findings.extend(photon_config_findings(root, project_id, methods, sources))
    findings.extend(python_biometric_findings(root, project_id))
    findings = deduplicate(findings)
    apply_reachability_evidence(root, findings)
    summary = write_outputs(root, project_id, args.output_root.resolve(), findings)
    summary.update({"schema": VERSION, "project_root": str(root), "project_id": project_id,
                    "method_count": len(methods), "source_event_count": len(sources),
                    "sink_event_count": len(sinks)})
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if summary["validation_status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
