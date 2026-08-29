# VRTaint — Source Scripts

Core Python scripts for the **VRTaint** Unity/VR taint-analysis system.

This directory contains only the scripts the system actually needs at runtime,
plus the dataset-construction tools used to build its project corpus.

## Layout

```
src/
├── vrtaint_cli.py                    # Unified pipeline entry point (copy of the main CLI)
├── Unity_preprocessing/              # Runtime core — required by the VRTaint semantic layer
│   ├── UnityInspectorBindingAnalyzer.py   # Scene/Prefab Inspector persistent-event binding analysis
│   ├── semantic_preprocess_cli.py         # Generates unity_analysis.json + guid_mapping.csv
│   └── UnityScenePreprocessor.py          # Scene/serialized-YAML parsing core
└── data_build/                       # Dataset construction tools
    ├── batch_clone_github_repos.py        # Batch-clone GitHub repos from a CSV
    ├── build_codeql_db.py                 # Batch-create CodeQL C# databases (resumable)
    ├── identify_vr_projects.py            # Classify projects (Unity / Unreal / WebXR / NativeVR)
    ├── make_dataset.py                    # Dataset construction helpers (URL-list clone, folder->URL map)
    └── project_version_dependence.py      # Scan project build method / Unity version
```

## Quick Start

### Run the full VRTaint pipeline

```powershell
python src/vrtaint_cli.py `
  --pipeline full `
  --project "<UNITY_PROJECT_ROOT>" `
  --project-id "<REPOSITORY_ID>" `
  --database "<CODEQL_CSHARP_DATABASE>" `
  --output-root "<OUTPUT_ROOT>" `
  --non-interactive
```

`vrtaint_cli.py` locates the VRTaint query pack automatically (relative to this
file), or you can override it with the `VRTRAINT_PACK_ROOT` environment variable.

### Build the dataset (one-time, optional)

```powershell
python src/data_build/batch_clone_github_repos.py   # clone repos -> new5_dataset
python src/data_build/build_codeql_db.py            # build CodeQL DBs -> new5_codeql_database
```

## Notes

- All scripts use relative/anchored paths (no hardcoded absolute paths); they can
  be moved together with the dataset root.
- `vrtaint_cli.py` is a copy of the canonical entry point at
  `query_test/VRTaint/.../scripts/20260815_003557_v001_vrtaint_cli.py`; keep the
  two in sync if you modify either one.
- Third-party runtime dependencies: `PyYAML`, `ruamel.yaml`, `chardet`, `tqdm`
  (see each script's imports).
