#!/usr/bin/env python3
"""Generate VRTaint wrappers for official C# Query libraries with standard flow classes."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path


CLASS_RE = re.compile(r"(?m)^\s*(?:abstract\s+)?(?:private\s+)?class\s+(Source|Sink|Sanitizer)\b")


QUERY = '''/**
 * @name VRTaint lifecycle extension for official {family} flow model
 * @description Preserves the official Source, Sink, and Sanitizer model and adds VRTaint
 *              lifecycle, event, coroutine, asynchronous, field, and owned-object propagation.
 * @kind path-problem
 * @id cs/vrtaint-official-{slug}
 * @problem.severity warning
 * @security-severity 8.0
 * @precision high
 * @tags security
 */

import csharp
import {import_path}
import lib.VRTaintFlowFramework
import lib.UnityExternalInput

module Config implements ProjectConfigSig {{
  predicate isSource(DataFlow::Node source) {{ {source_predicate} }}
  predicate isSink(DataFlow::Node sink) {{
    sink instanceof Sink and
    exists(Callable c | c = sink.getEnclosingCallable() and c.fromSource())
  }}
  predicate isBarrier(DataFlow::Node node) {{ node instanceof Sanitizer }}
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {{ none() }}
}}

module VRTaintConfig = VRTaintFlow<Config>;
module Flow = TaintTracking::Global<VRTaintConfig>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Official {family} source reaches its official sink through Unity semantic propagation."
'''


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


EXTERNAL_INPUT_FAMILIES = {
    "CodeInjection", "CommandInjection", "ConditionalBypass", "LDAPInjection",
    "LogForging", "MissingXMLValidation", "ReDoS", "RegexInjection",
    "ResourceInjection", "SqlInjection", "TaintedPath", "UnsafeDeserialization",
    "UrlRedirect", "XMLEntityInjection", "XPathInjection", "ZipSlip",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csharp-all", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    model_root = args.csharp_all / "semmle" / "code" / "csharp" / "security" / "dataflow"
    if not model_root.is_dir():
        raise FileNotFoundError(model_root)
    if args.output_dir.exists():
        shutil.rmtree(args.output_dir)
    args.output_dir.mkdir(parents=True)
    generated = []
    structural = []
    for path in sorted(model_root.glob("*Query.qll")):
        content = path.read_text(encoding="utf-8", errors="replace")
        classes = set(CLASS_RE.findall(content))
        family = path.stem.removesuffix("Query")
        import_path = "semmle.code.csharp.security.dataflow." + path.stem
        if {"Source", "Sink", "Sanitizer"}.issubset(classes):
            output = args.output_dir / f"VRTaintOfficial{family}.ql"
            source_predicate = "source instanceof Source"
            if family in EXTERNAL_INPUT_FAMILIES:
                source_predicate = (
                    "source instanceof Source or "
                    "UnityExternalInput::isExternalSource(source) and "
                    "UnityExternalInput::isRuntimeNode(source)"
                )
            output.write_text(QUERY.format(
                family=family, slug=slug(family), import_path=import_path,
                source_predicate=source_predicate), encoding="utf-8")
            generated.append({
                "family": family, "official_library": str(path.resolve()),
                "import": import_path, "query": str(output.resolve()),
                "query_id": f"cs/vrtaint-official-{slug(family)}",
                "compatibility": "vrtaint-standard-source-sink-sanitizer",
                "source_policy": "official-plus-unity-external" if family in EXTERNAL_INPUT_FAMILIES else "official-only",
            })
        else:
            structural.append({
                "family": family, "official_library": str(path.resolve()),
                "classes": sorted(classes), "compatibility": "official-native-only",
                "reason": "standard public Source/Sink/Sanitizer triple is not exposed",
            })
    suite = args.output_dir.parent / "UnityOfficialDeepAdapters.qls"
    suite.write_text(
        "- description: Auto-generated VRTaint wrappers for compatible official CSharp flow libraries\n"
        "- queries: queries/generated_official_adapters\n",
        encoding="utf-8")
    payload = {
        "schema": "vrtaint-official-deep-adapter/v1",
        "official_model_library_count": len(generated) + len(structural),
        "vrtaint_adapter_count": len(generated),
        "official_native_only_count": len(structural),
        "suite": str(suite.resolve()), "generated": generated,
        "official_native_only": structural,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"generated": len(generated), "native_only": len(structural),
                      "suite": str(suite.resolve())}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
