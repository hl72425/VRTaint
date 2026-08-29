"""HISTORICAL REFERENCE (one-time setup script, not intended to be re-run).

This script generated the isolated-source evaluation project (csproj + mirrored
source tree) used to build the benchmark CodeQL database. It depends on
intermediate build artifacts that no longer exist, so it is kept only for
traceability. The actual benchmark database ships with the U-VRFlow-Benchmark
release (analysis/db/), and RQ1 scoring is done by ``score_accuracy.py``.
"""

from __future__ import annotations

import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path


STAMP = "20260824_183648_v001"
DATASET = Path(r"E:\lqs\1_my_project\dataset")
ACTIVE = DATASET / "vulnerability_dataset" / "TryNotDie" / "Assets" / "Scripts" / "_TestCases"
OUT = DATASET / "_benchmark_fix" / "benchmark_nine_category_integration_20260824_172722_v001"
OLD_PROJECT = (
    DATASET / "vulnerability_dataset" / "TryNotDie" / "VRTaint-Unified-Benchmark"
    / "evaluation_20260822_051500_v001" / "intermediate"
    / "20260822_052300_v001_benchmark_trace.csproj"
)
EVAL = OUT / "intermediate" / f"benchmark_accuracy_evaluation_{STAMP}"
PROJECT = EVAL / f"{STAMP}_benchmark_accuracy.csproj"
SOURCE_ROOT = EVAL / "source"
MIRROR = SOURCE_ROOT / "Assets" / "Scripts" / "_TestCases"


def main() -> None:
    EVAL.mkdir(parents=True, exist_ok=True)
    (EVAL / "bin").mkdir(exist_ok=True)
    (EVAL / "obj").mkdir(exist_ok=True)

    active_categories = sorted(
        path for directory in ACTIVE.glob("Category*-*") if directory.is_dir()
        for path in directory.rglob("*.cs")
    )
    active_helpers = sorted((ACTIVE / "Helper").rglob("*.cs"))
    if MIRROR.exists():
        shutil.rmtree(MIRROR)
    MIRROR.mkdir(parents=True)
    for source in active_categories + active_helpers:
        target = MIRROR / source.relative_to(ACTIVE)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    categories = sorted(
        path for directory in MIRROR.glob("Category*-*") if directory.is_dir()
        for path in directory.rglob("*.cs")
    )
    helpers = sorted((MIRROR / "Helper").rglob("*.cs"))
    sources = categories + helpers
    if (len(categories), len(helpers), len(sources)) != (160, 8, 168):
        raise SystemExit(
            f"unexpected source inventory: categories={len(categories)}, helpers={len(helpers)}, total={len(sources)}"
        )

    ET.register_namespace("", "http://schemas.microsoft.com/developer/msbuild/2003")
    tree = ET.parse(OLD_PROJECT)
    root = tree.getroot()
    ns = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}

    for item_group in root.findall("m:ItemGroup", ns):
        for compile_node in list(item_group.findall("m:Compile", ns)):
            item_group.remove(compile_node)

    for node in root.findall(".//m:AssemblyName", ns):
        node.text = "VRTaintNineCategoryAccuracy"
    for node in root.findall(".//m:BaseIntermediateOutputPath", ns):
        node.text = str(EVAL / "obj") + "\\"
    for node in root.findall(".//m:OutputPath", ns):
        if node.text and "Release" not in node.text:
            node.text = str(EVAL / "bin") + "\\"

    source_group = ET.SubElement(root, "{http://schemas.microsoft.com/developer/msbuild/2003}ItemGroup")
    for source in sources:
        ET.SubElement(
            source_group,
            "{http://schemas.microsoft.com/developer/msbuild/2003}Compile",
            {"Include": str(source)},
        )

    ET.indent(tree, space="  ")
    tree.write(PROJECT, encoding="utf-8", xml_declaration=True)

    metadata = {
        "stamp": STAMP,
        "active_root": str(ACTIVE),
        "project": str(PROJECT),
        "source_root": str(SOURCE_ROOT),
        "source_mirror": str(MIRROR),
        "category_sources": len(categories),
        "helper_sources": len(helpers),
        "total_sources": len(sources),
        "manifest": str(ACTIVE / "BenchmarkSupport" / "manifests" / "benchmark_manifest.csv"),
        "model_pack": str(ACTIVE / "BenchmarkSupport" / "model_pack"),
    }
    (EVAL / f"{STAMP}_run_metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(metadata, ensure_ascii=False))


if __name__ == "__main__":
    main()
