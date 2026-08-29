#!/usr/bin/env python3
"""Build a project model pack containing local source/configuration facts.

The generated source facts identify locations that a buildless C# database may
not resolve to Unity/XR SDK symbols. Serialized exposure facts represent direct
SDK configuration semantics recovered from scene/prefab data. They do not
encode code-to-code source-to-sink paths; those are computed by VRTaint.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PACK_NAME = "my-org/vrtaint-unity-instance-models"
LOCAL_FACT_PREDICATES = {
    "unityPrivacySourceLocationModel",
    "unitySerializedPrivacyExposureModel",
}


def run(command: list[object]) -> None:
    subprocess.run([str(item) for item in command], check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--output-pack", type=Path, required=True)
    parser.add_argument("--base-pack", type=Path)
    parser.add_argument("--source-generator", type=Path, required=True)
    args = parser.parse_args()

    output = args.output_pack.resolve()
    if args.base_pack and args.base_pack.resolve() != output:
        shutil.copytree(args.base_pack.resolve(), output, dirs_exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    model_dir = output / "models"
    model_dir.mkdir(exist_ok=True)
    (output / "qlpack.yml").write_text(
        f"name: {PACK_NAME}\nversion: 1.0.0\nlibrary: true\n"
        "extensionTargets:\n  my-org/csharp-custom-queries: ^0.3.0\n"
        "dataExtensions:\n  - models/*.model.yml\n",
        encoding="utf-8",
    )

    with tempfile.TemporaryDirectory(prefix="vrtaint_privacy_sources_") as temp:
        generated = Path(temp) / "source-model"
        run([
            sys.executable,
            args.source_generator,
            "--project-root", args.project_root,
            "--output-pack", generated,
            "--pack-name", "vrtaint/privacy-source-temp",
        ])
        raw = json.loads((generated / "models.yml").read_text(encoding="utf-8"))
        summary = json.loads((generated / "summary.json").read_text(encoding="utf-8"))

    extensions = [
        extension
        for extension in raw.get("extensions", [])
        if extension.get("addsTo", {}).get("extensible") in LOCAL_FACT_PREDICATES
    ]
    (model_dir / "privacy-source.model.yml").write_text(
        json.dumps({"extensions": extensions}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    result = {
        "schema": "vrtaint-privacy-local-model/v1",
        "source_fact_count": summary.get("source_fact_count", 0),
        "serialized_exposure_count": summary.get("serialized_exposure_count", 0),
        "sources": summary.get("sources", []),
        "serialized_exposures": summary.get("exposures", []),
        "encodes_code_to_code_flows": False,
    }
    (output / "privacy_model_summary.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
