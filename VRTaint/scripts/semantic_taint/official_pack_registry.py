#!/usr/bin/env python3
"""Discover every official CodeQL alert query and emit a versioned adapter registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


META = re.compile(r"(?m)^\s*\*?\s*@(id|kind|name|problem\.severity|security-severity)\s+(.+?)\s*$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--codeql", default="codeql")
    args = parser.parse_args()
    proc = subprocess.run([args.codeql, "resolve", "queries", str(args.suite.resolve())],
                          text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode:
        raise RuntimeError(proc.stderr)
    entries = []
    for raw in proc.stdout.splitlines():
        path = Path(raw.strip())
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        metadata = {key: value.strip() for key, value in META.findall(content[:12000])}
        entries.append({
            "id": metadata.get("id", "ID_SLOT"), "kind": metadata.get("kind", "KIND_SLOT"),
            "name": metadata.get("name", "NAME_SLOT"),
            "problem_severity": metadata.get("problem.severity", "SEVERITY_SLOT"),
            "security_severity": metadata.get("security-severity", "SECURITY_SEVERITY_SLOT"),
            "path": str(path.resolve()),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "adapter": "sarif-five-tuple/v1",
            "deep_vrtaint_extension": metadata.get("kind") == "path-problem",
        })
    ids = [entry["id"] for entry in entries]
    payload = {
        "schema": "vrtaint-official-query-registry/v1",
        "suite": str(args.suite.resolve()), "query_count": len(entries),
        "unique_id_count": len(set(ids)), "duplicate_ids": sorted({x for x in ids if ids.count(x) > 1}),
        "queries": entries,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"query_count": len(entries), "unique_ids": len(set(ids)),
                      "output": str(args.output.resolve())}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
