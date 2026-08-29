# VRTaint Standalone Runtime Package

This directory is the **runtime-essential subset** of the VRTaint analysis system.
It excludes the main driver CLI, project databases, and historical snapshots.
All files use relative references only (verified: zero absolute paths), so the
package can be relocated or copied without path dependency issues.

## Layout

```
VRTaint/
├── qlpack.yml                     # C# query pack definition (my-org/csharp-custom-queries)
├── codeql-pack.lock.yml           # dependency lock
├── models/                        # data extensions (extensible-predicate sentinels; required)
├── model_pack/                    # standard Unity flow summaries for --model-packs
├── instance_model_pack/           # instance model pack
├── config/                        # official-adapter policy / manifest / pack lock / taint policy
├── lib/                           # QL libraries (privacy + generic vulnerability chains)
├── queries/                       # production queries, suites, generated adapters, preflight
├── scripts/semantic_taint/        # semantic layer + privacy model generators
└── python_queries/python_privacy_pack/   # Python privacy query (used for the Python-side leak)
```

## Runtime conventions

1. **Main driver CLI** is maintained separately (not included here).
   It locates this pack root through the environment variable:
   ```
   set VRTRAINT_PACK_ROOT=<VRTRAINT_ROOT>
   ```
   (or its `--pack-root` option, if supported). The CLI also expects the
   preprocessing analyzer at `<SRC_ROOT>/Unity_preprocessing/UnityInspectorBindingAnalyzer.py`.

2. **CodeQL CLI**: provide the CodeQL toolchain directory via
   `--search-path <CODEQL_HOME>` and the pack itself via
   `--additional-packs <VRTRAINT_ROOT>`.

3. **Project databases** are provided externally; run queries with `-d <database>`.

## Typical commands

```powershell
$codeql = "<CODEQL_HOME>\codeql.exe"
$pack   = "<VRTRAINT_ROOT>"

# Compile check
& $codeql query compile "$pack\queries\UnitySensitiveDataExposure.ql" `
  --additional-packs $pack --search-path "<CODEQL_HOME>" --threads=4 --ram=8000

# Run the fast privacy query against one project database
& $codeql query run -d <database> --output=<out.bqrs> --additional-packs $pack `
  --search-path "<CODEQL_HOME>" --threads=4 --ram=6000 `
  "$pack\queries\UnitySensitiveDataExposureFast.ql"
& $codeql bqrs decode --format=csv <out.bqrs>

# Python privacy query (build a Python database first)
& $codeql database create <python-db> --language=python --source-root <server-source>
& $codeql query run -d <python-db> --output=<out.bqrs> `
  --additional-packs "$pack\python_queries\python_privacy_pack" `
  --search-path "<CODEQL_HOME>" "$pack\python_queries\python_privacy_pack\PythonBiometricNetworkExposure.ql"
```

## Source-location facts for buildless databases

Buildless (none-mode) databases lose Unity/XR engine symbol names, so the
privacy pipeline first scans project source text to emit source-location facts,
then CodeQL computes the propagation to sinks. Generate facts per project:

```powershell
python "$pack\scripts\semantic_taint\unity_privacy_model_pack.py" `
  --project-root <project-source> --output-pack <temp-pack> --pack-name vrtaint/privacy-model
```

Place the generated `models/privacy.model.yml` rows into the query pack's
`models/` directory before running the queries (external extension packs are
not loaded via `--additional-packs` in the current toolchain).

## File renames (timestamp stripping)

The following files were renamed from their timestamped forms. If any external
tooling (for example the main driver CLI) references the old names, update it:

| Old name | New name |
|---|---|
| `python_queries/20260829_053000_v001_python_privacy_pack` | `python_queries/python_privacy_pack` |
| `.../20260829_053000_v001_PythonBiometricNetworkExposure.ql` | `.../PythonBiometricNetworkExposure.ql` |
| `queries/20260829_040000_v001_UnityPrivacy.qls` | `queries/UnityPrivacy.qls` |
| `queries/20260829_040000_v001_UnityRecoveredSensitiveDataExposure.ql` | `queries/UnityRecoveredSensitiveDataExposure.ql` |
| `queries/20260829_040000_v001_UnitySensitiveDataExposureFast.ql` | `queries/UnitySensitiveDataExposureFast.ql` |
| `queries/20260829_040000_v001_UnitySerializedSensitiveDataExposure.ql` | `queries/UnitySerializedSensitiveDataExposure.ql` |
| `scripts/semantic_taint/20260829_040000_v001_unity_privacy_model_pack.py` | `scripts/semantic_taint/unity_privacy_model_pack.py` |
| `scripts/semantic_taint/20260829_040000_v001_unity_recovered_privacy_model_pack.py` | `scripts/semantic_taint/unity_recovered_privacy_model_pack.py` |
| `scripts/semantic_taint/20260829_145900_v001_unity_privacy_source_model_pack.py` | `scripts/semantic_taint/unity_privacy_source_model_pack.py` |

## Sanitization notes

- Timestamps were removed from file and directory names.
- User-specific absolute paths were replaced with placeholders
  (`<VRTRAINT_ROOT>`, `<CODEQL_HOME>`, `<SRC_ROOT>`, `<database>`, ...).
- Content is English; runtime-generated output names such as
  `{stamp}_v001_*.log` are functional and intentionally preserved.
