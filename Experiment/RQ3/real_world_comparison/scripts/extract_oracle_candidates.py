#!/usr/bin/env python3
"""Extract alerts located in oracle-relevant files for manual semantic scoring."""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FILES = {
    "S01": ["FileImportManager.IO.cs", "MacroLuaEnvironment.cs", "LuaRunner.cs"],
    "S02": ["LevelManager.cs"],
    "S03": ["Extensions.cs"],
    "S04": ["ConfigServer.cs"],
    "S05": ["ApiMethods.cs", "LuaManager.cs"],
    "S06": ["SaveManager_Users.cs"],
    "S07": ["UnityCardGame.cs", "UnityFileMethods.cs"],
    "S08": ["ModelCreator.cs", "server.ts"],
    "S09": ["SaveManager.cs"],
    "S10": ["RPCAgent.cs"],
    "S11": ["PackageExtractor.cs"],
    "S12": ["ClientHandle.cs", "Config.cs"],
    "P01": ["FusionSession.cs", "VoicePhraseSync.cs"],
    "P02": ["HeadTracker.cs", "gRPCDataController.cs"],
    "P03": ["NetworkPlayer.cs", "Network Player.prefab", "Game.unity"],
    "P04": ["GipperPosePublisher.cs"],
    "P05": ["config.py", "server.py"],
    "P06": ["NetworkPlayer.cs", "Network Player.prefab"],
}


def loc_from_sarif(result: dict) -> tuple[str, int]:
    locs = result.get("locations") or []
    if not locs:
        return "", 0
    physical = locs[0].get("physicalLocation", {})
    return physical.get("artifactLocation", {}).get("uri", ""), physical.get("region", {}).get("startLine", 0)


def main() -> None:
    rows: list[dict[str, object]] = []
    for fid, names in FILES.items():
        native = ROOT / "intermediate" / "native_codeql" / f"{fid}.sarif"
        if native.is_file():
            doc = json.loads(native.read_text(encoding="utf-8-sig"))
            for result in doc.get("runs", [{}])[0].get("results", []):
                path, line = loc_from_sarif(result)
                if any(name.lower() in path.lower() for name in names):
                    rows.append({"id": fid, "tool": "Native CodeQL", "rule": result.get("ruleId", ""),
                                 "path": path, "line": line, "message": result.get("message", {}).get("text", "")})
        semgrep = ROOT / "intermediate" / "semgrep_equal_corpus" / f"{fid}.json"
        if semgrep.is_file() and semgrep.stat().st_size:
            doc = json.loads(semgrep.read_text(encoding="utf-8-sig"))
            for result in doc.get("results", []):
                path = result.get("path", "")
                if any(name.lower() in path.lower() for name in names):
                    rows.append({"id": fid, "tool": "Semgrep", "rule": result.get("check_id", ""),
                                 "path": path, "line": result.get("start", {}).get("line", 0),
                                 "message": result.get("extra", {}).get("message", "")})
    out = ROOT / "results" / "oracle_location_candidates.csv"
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "tool", "rule", "path", "line", "message"])
        w.writeheader(); w.writerows(rows)
    print(f"rows={len(rows)} output={out}")


if __name__ == "__main__":
    main()
