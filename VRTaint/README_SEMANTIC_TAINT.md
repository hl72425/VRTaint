# Generic Unity Semantic Taint Layer

This extension keeps CodeQL as the path engine and attaches the tuple
`<object, field/path, phase, context, source>` through stable external facts.

## Reusable API

- `lib/SemanticTaintFacts.qll`: external fact contract and standard code-source projection.
- `lib/SemanticTaintDomain.qll`: endpoint object/path/phase/context projection.
- `queries/SemanticTaintTrace.ql`: semantic evidence rows; these are not vulnerability alerts.
- `queries/SemanticTaintSecurity.ql`: high-precision data source to compatible security sink paths.
- `scripts/semantic_taint/semantic_fact_provider.py`: adapter interface and `unity-yaml-v1` implementation.
- `scripts/semantic_taint/semantic_taint_api.py`: stable public interface; changing projects only changes three paths.
- `scripts/semantic_taint/semantic_taint_runner.py`: internal orchestration layer.
- `scripts/semantic_taint/semantic_validate.py`: five-tuple and context-contract validator.

## Command

```powershell
# Invoke with relative/placeholder paths (this script lives under <pack_root>/scripts/semantic_taint/)
$api = Join-Path $PSScriptRoot "scripts\semantic_taint\semantic_taint_api.py"
python $api `
  --project-root "PROJECT_ROOT" `
  --codeql-database "CODEQL_DB" `
  --output-root "OUTPUT_ROOT"
```

The public API auto-discovers `unity_analysis.json` and `guid_mapping.csv`. If either is absent,
it generates the minimum generic IR from `.unity` files and the GUID map from `.meta` files under
the run's `intermediate/generated_inputs` directory. Use `--unity-analysis` and `--guid-mapping`
only to select a specific precomputed representation when a project has multiple candidates.
Use `--regenerate-inputs` when the checked-in IR/GUID files may be stale; this rebuilds both
generic inputs from the current project checkout before analysis. Generated preprocessing uses
enabled `EditorBuildSettings` scenes by default; pass `--scene-scope all` to include every
`.unity` file under `Assets` (including demos/samples).

## Stable result contract

Each row is `<object, field/path, phase, context, source>`:

- `object`: YAML-proven scene/prefab component instance where available; otherwise an explicit `Type#*` summary.
- `field/path`: the observed endpoint slot, for example `field.value`, `call.Parse.arg[0]`, or `@control`.
- `phase`: an actual Unity lifecycle entry (`Awake`, `Start`, `Update`, etc.); `Unbound` means no lifecycle call-chain was proven.
- `context`: canonical JSON with the fixed ordered keys `schema, project, scene, game_object, component, script, entry, callable, event, thread, coroutine, async`.
- `source`: source category such as `XRInput`, `file-content`, `network`, or `UnitySerializedConstant`.

Primary artifacts are `semantic_taint_tuples.csv/json`, `semantic_taint_evidence.json`,
`semantic_validation.json`, `semantic_security.sarif`, `run_summary.json`, and
`provenance_manifest.json`. Trace rows are semantic evidence; SARIF rows are the separately
filtered security findings.

The provider contains no project names or callback allowlists. It resolves serialized callbacks,
class declarations, CodeQL source roots, and high-confidence unresolved receiver edges from the
inputs. Fixed Unity persistent arguments are marked `configuration`; only runtime data-bearing
sources participate in the security query.
