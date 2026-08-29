#!/usr/bin/env python3
"""Discover installed official CodeQL query packs and generate deduplicated alert suites."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


META = re.compile(r"(?m)^\s*\*?\s*@(id|kind|name|problem\.severity|security-severity)\s+(.+?)\s*$")
PACK_FIELD = re.compile(r"(?m)^\s*(name|version|extractor|library):\s*['\"]?([^'\"\r\n]+)")


def version_key(value: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", value)
    return tuple(map(int, nums)) if nums else (0,)


def pack_info(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return {key: value.strip() for key, value in PACK_FIELD.findall(text)}


def discover(package_root: Path) -> list[tuple[Path, dict[str, str]]]:
    candidates: dict[str, list[tuple[Path, dict[str, str]]]] = {}
    for qlpack in package_root.glob("*/**/qlpack.yml"):
        info = pack_info(qlpack)
        name = info.get("name", "")
        if not name.startswith("codeql/") or not name.endswith("-queries"):
            continue
        if info.get("library", "false").lower() == "true":
            continue
        candidates.setdefault(name, []).append((qlpack.parent, info))
    result = []
    for name, versions in candidates.items():
        result.append(max(versions, key=lambda item: version_key(item[1].get("version", item[0].name))))
    return sorted(result, key=lambda item: item[1]["name"])


def write_suite(path: Path, pack_path: Path, pack_name: str) -> None:
    normalized = pack_path.resolve().as_posix()
    path.write_text(
        f"- description: All alert queries from {pack_name}\n"
        f"- queries: {normalized}\n"
        "- include:\n"
        "    kind:\n"
        "      - problem\n"
        "      - path-problem\n",
        encoding="utf-8",
    )


def resolve(codeql: str, suite: Path) -> list[Path]:
    proc = subprocess.run([codeql, "resolve", "queries", str(suite.resolve())],
                          text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode:
        raise RuntimeError(f"resolve failed for {suite}: {proc.stderr}")
    return [Path(line.strip()) for line in proc.stdout.splitlines() if Path(line.strip()).is_file()]


def query_entry(path: Path) -> dict[str, object]:
    content = path.read_text(encoding="utf-8", errors="replace")
    metadata = {key: value.strip() for key, value in META.findall(content[:16000])}
    return {
        "id": metadata.get("id", "ID_SLOT"), "kind": metadata.get("kind", "KIND_SLOT"),
        "name": metadata.get("name", "NAME_SLOT"),
        "problem_severity": metadata.get("problem.severity", "SEVERITY_SLOT"),
        "security_severity": metadata.get("security-severity", "SECURITY_SEVERITY_SLOT"),
        "path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "adapter": "sarif-five-tuple/v1",
        "deep_vrtaint_candidate": metadata.get("kind") == "path-problem",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--codeql", default="codeql")
    parser.add_argument("--extractor", action="append", default=[],
                        help="optional extractor allow-list; repeatable")
    args = parser.parse_args()
    suites = args.output_root / "suites"
    registries = args.output_root / "registries"
    suites.mkdir(parents=True, exist_ok=True)
    registries.mkdir(parents=True, exist_ok=True)
    manifests = []
    allowed = {item.lower() for item in args.extractor}
    for pack_path, info in discover(args.package_root.resolve()):
        extractor = info.get("extractor", info["name"].removeprefix("codeql/").removesuffix("-queries"))
        if allowed and extractor.lower() not in allowed:
            continue
        slug = info["name"].replace("codeql/", "").replace("-queries", "")
        suite = suites / f"official_{slug}_all_alerts_v001.qls"
        registry = registries / f"official_{slug}_query_registry_v001.json"
        write_suite(suite, pack_path, info["name"])
        queries = [query_entry(path) for path in resolve(args.codeql, suite)]
        ids = [str(item["id"]) for item in queries]
        registry.write_text(json.dumps({
            "schema": "vrtaint-official-query-registry/v1", "pack": info["name"],
            "version": info.get("version", pack_path.name),
            "extractor": extractor, "pack_path": str(pack_path),
            "suite": str(suite.resolve()), "query_count": len(queries),
            "unique_id_count": len(set(ids)),
            "duplicate_ids": sorted({item for item in ids if ids.count(item) > 1}),
            "queries": queries,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        manifests.append({
            "pack": info["name"], "version": info.get("version", pack_path.name),
            "extractor": extractor, "pack_path": str(pack_path),
            "suite": str(suite.resolve()), "registry": str(registry.resolve()),
            "query_count": len(queries), "unique_id_count": len(set(ids)),
        })
    manifest = args.output_root / "official_pack_adapter_manifest_v001.json"
    manifest.write_text(json.dumps({
        "schema": "vrtaint-official-pack-adapter/v1", "pack_count": len(manifests),
        "total_alert_query_count": sum(int(item["query_count"]) for item in manifests),
        "packs": manifests,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"pack_count": len(manifests),
                      "total_alert_query_count": sum(int(item["query_count"]) for item in manifests),
                      "manifest": str(manifest.resolve())}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
