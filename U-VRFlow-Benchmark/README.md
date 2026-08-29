# U-VRFlow Benchmark

**A Unity/VR-specific taint-flow benchmark for evaluating static analysis tools on
Unity lifecycle, asynchronous, dynamic-invocation, event-dispatch, configuration-recovered,
and privacy data flows.**

This repository hosts the benchmark as a **minimal, self-contained Unity project**
(hosted on top of the open-source game *[Try Not to Die](https://github.com/ShinjiMC/TryNotDie)*,
Apache-2.0). All game assets, third-party packages, scenes, and scripts unrelated to the
benchmark have been **removed**; only the test-case code, its helper infrastructure, the
benchmark manifest, the CodeQL model pack, and one minimal scene for the
configuration-recovered-edge cases are shipped.

---

## 1. Overview

The benchmark is organized around **nine semantic control variables** that are known to
break naive taint analysis in Unity projects:

| # | Category | Semantics under test | Cases |
|---|---|---|---|
| 1 | **CoreDataflow** | Plain language-level propagation, sanitization, multi-source/multi-sink | 19 |
| 2 | **ObjectIdentityHeap** | Object state, instance identity, Unity object resolution, heap precision | 31 |
| 3 | **UnityLifecycle** | Lifecycle ordering, inheritance, re-entry, cross-frame closures | 25 |
| 4 | **AsyncTemporal** | Coroutine / delayed-scheduling temporal relations, await continuation | 12 |
| 5 | **DynamicInvocation** | Dynamic targets, reflection argument resolution, `SendMessage` | 26 |
| 6 | **RuntimeEventDispatch** | Listener relations registered via C# `AddListener` | 6 |
| 7 | **ConfigurationRecoveredEdges** | Propagation edges recovered from **Inspector serialized bindings** | 10 |
| 8 | **Composite** | Cases spanning at least two core mechanisms | 3 |
| 9 | **Privacy** | Sensitive source/sink and exfiltration paths | 9 |
| | **Total logical cases** | | **141** |

Each logical case is either **Positive (P)** — a real taint flow that a sound analyzer
should report — or **Negative (N)** — a near-miss that should *not* be reported. The
label of every case is defined in the manifest.

### 1.1 What the benchmark measures

- **Precision / Recall / F1** of a tool's taint engine on Unity-specific propagation,
  compared against a **native-CodeQL** and a **Semgrep** baseline.
- How well a tool recovers edges that **cannot be seen from C# source alone**:
  - Unity lifecycle callbacks (`Awake` → `Start` → `Update` → …) invoked by the engine;
  - Coroutines and `async` continuations;
  - Dynamic invocation (`SendMessage`, reflection);
  - Serialized `UnityEvent` bindings configured in scene/prefab YAML (Category 7);
  - Object identity across scene objects (Category 2).

---

## 2. Repository Layout

```
U-VRFlow-Benchmark/
├── Assets/
│   └── Scripts/
│       └── _TestCases/                     # the benchmark itself
│           ├── Category1-CoreDataflow/      # 19 cases
│           ├── Category2-ObjectIdentityHeap/ # 31 cases (+ Fixtures/*.unity)
│           ├── Category3-UnityLifecycle/     # 25 cases
│           ├── Category4-AsyncTemporal/      # 12 cases
│           ├── Category5-DynamicInvocation/  # 26 cases
│           ├── Category6-RuntimeEventDispatch/ # 6 cases
│           ├── Category7-ConfigurationRecoveredEdges/ # 10 cases
│           ├── Category8-Composite/          # 3 cases
│           ├── Category9-Privacy/            # 9 cases
│           ├── Helper/                       # TestSources / TestSinks / support classes
│           └── BenchmarkSupport/
│               ├── manifests/benchmark_manifest.csv   # ground truth (141 logical cases)
│               ├── model_pack/                        # CodeQL data-extension pack
│               │   └── models/TryNotDie.model.yml     # component/lifecycle/binding facts
│               └── reports/benchmark_design.md
├── Assets/Scenes/
│   └── VRTaintBenchmark.unity               # minimal scene for Category 7 (7.1) bindings
├── analysis/
│   └── db/
│       └── db-true-nine-category-benchmark/ # prebuilt, anonymized CodeQL database (168 files)
├── Packages/manifest.json                   # minimal Unity package set (core modules only)
├── ProjectSettings/                         # Unity project settings (2022.3 LTS)
├── LICENSE                                  # Apache-2.0
└── README.md
```

> **Why is there a Unity scene at all?**
> 133 of 141 cases are analyzed purely from C# source plus the model-pack facts and need
> **no scene**. Only cases **7.1P / 7.1N** (Inspector serialized UnityEvent bindings) are
> instantiated in the minimal scene `VRTaintBenchmark.unity`, which contains exactly the
> two GameObjects (`EventSource32` / `EventListener32`) and their serialized event bindings.
> Category 2's four `Fixtures/*.unity` files are tiny self-contained scenes (one per case)
> that carry object-identity facts.

---

## 3. Ground Truth Manifest

`Assets/Scripts/_TestCases/BenchmarkSupport/manifests/benchmark_manifest.csv` — one row
per **logical case** (multi-file owner/target cases share a single `case_id`):

| Column | Description |
|---|---|
| `case_id` | canonical id, e.g. `7.1P` |
| `legacy_case_id` / `legacy_category` | traceability to the earlier category naming |
| `category` | one of the nine categories above |
| `polarity` | `P` (flow expected) or `N` (no flow) |
| `expected` | `FLOW` / `NO_FLOW` |
| `semantic_obligation` | what propagation semantics the case exercises |
| `source` / `sink` | the endpoint profile used by the case |
| `requires_model_pack` | whether the case needs the model-pack facts to be analyzable |
| `source_file_count` / `relative_paths` | the case's C# files (relative to `_TestCases/`) |

---

## 4. The CodeQL Model Pack

`Assets/Scripts/_TestCases/BenchmarkSupport/model_pack/` is a CodeQL **data-extension
pack** (`my-org/vrtaint-benchmark-models`) that supplies the Unity semantic facts the
analyzer consumes:

| Extensible predicate | Facts provided |
|---|---|
| `unityComponentInstanceModel` | scene components (name, asset path, script) |
| `unityLifecycleEntryModel` | lifecycle entries (`Start`, `SafeHandler`, …) |
| `unityEntryInstanceModel` | concrete component bindings for lifecycle entries |
| `unityComponentReferenceModel` | owner→target edges (event / field) |
| `unityInstanceCoverageModel` | completeness of instance facts |
| `unitySerializedUnityEventBindingModel` | serialized UnityEvent listener bindings |
| `unitySerializedUnityEventInvocationModel` | source-confirmed `.Invoke()` call sites |

The pack targets `my-org/csharp-custom-queries` (the **VRTaint query pack**, v0.3.0+).
It is consumed at analysis time via `--model-packs` / `--additional-packs` (see §6).

---

## 5. Reproducing the Evaluation

### 5.0 Quick Start (prebuilt database, single query file)

This repository ships a **prebuilt, anonymized CodeQL database** of the 141-case
benchmark, so you can run the full evaluation **without Unity and without building a
database**:

```
analysis/db/db-true-nine-category-benchmark/     # prebuilt C# CodeQL database (168 source files)
```

You only need:

1. **CodeQL CLI** (≥ 2.14, C# support);
2. **The VRTaint query pack** (`my-org/csharp-custom-queries` v0.3.0+) — distributed
   separately; its single query file `queries/UnityTaint.ql` covers **all nine
   categories** (the query's `TestSources` / `TestSinks` endpoints are the benchmark's
   source/sink model, so one query suffices for all 141 cases);
3. The model pack inside this repository
   (`Assets/Scripts/_TestCases/BenchmarkSupport/model_pack`).

```bash
# One command, one query file, prebuilt database:
codeql database analyze \
  analysis/db/db-true-nine-category-benchmark \
  --format=sarif-latest \
  --output=vrtaint.sarif \
  --threads=4 --ram=8192 \
  --additional-packs=Assets/Scripts/_TestCases/BenchmarkSupport/model_pack \
  --model-packs=my-org/vrtaint-benchmark-models@1.0.0 \
  <path-to-vrtaint>/queries/UnityTaint.ql
```

> - The prebuilt database's `sourceLocationPrefix` is the neutral value `src` (paths
>   anonymized); all 168 source files are stored under `src/Assets/Scripts/_TestCases/`
>   in the database archive, so no local absolute paths are required.
> - The model pack must be on `--additional-packs` so the extensible predicates resolve;
>   `--model-packs` selects it by name.
> - Optionally append `<path-to-vrtaint>/queries/UnitySensitiveDataExposure.ql` if you
>   want the dedicated privacy query in addition to UnityTaint.

### 5.1 Prerequisites (building your own database)

- **Unity 2022.3 LTS** (project was authored with `2022.3.22f1`) — only needed to
  (re)build the project or regenerate the CodeQL database from scenes; analysis itself
  runs headless.
- **CodeQL CLI** (≥ 2.14) with the **C#** support.
- **VRTaint query pack** (`my-org/csharp-custom-queries`, v0.3.0) — the custom query
  library the benchmark targets. It is distributed separately from this repository.

### 5.2 Build the CodeQL database (optional — only if you change the cases)

The prebuilt database already reflects the current `_TestCases` tree. Rebuild only if
you modify cases:

```bash
# Build a none-mode database straight from the C# sources (no Unity needed):
codeql database create db-csharp \
  --language=csharp \
  --source-root=Assets/Scripts/_TestCases \
  --build-mode=none \
  --overwrite
```

### 5.3 Run VRTaint on the benchmark

With your own database (`db-csharp`) — or swap in the prebuilt one from §5.0:

```bash
codeql database analyze db-csharp \          # or: analysis/db/db-true-nine-category-benchmark
  --format=sarif-latest \
  --output=vrtaint.sarif \
  --threads=4 --ram=8192 \
  --additional-packs=Assets/Scripts/_TestCases/BenchmarkSupport/model_pack \
  --model-packs=my-org/vrtaint-benchmark-models@1.0.0 \
  <path-to-vrtaint>/queries/UnityTaint.ql
```

> `UnityTaint.ql` alone covers **all nine categories** (its `TestSources` / `TestSinks`
> endpoints are the benchmark's source/sink model). Append
> `<path-to-vrtaint>/queries/UnitySensitiveDataExposure.ql` for the dedicated privacy
> query if desired. The model pack must be on the additional-packs path so the
> extensible predicates resolve.

### 5.4 Score the results

1. Map every SARIF alert to a `case_id` via `relative_paths` (a case is hit if any of its
   files/lines is reported).
2. Classify per case: **TP** if a Positive case is reported, **FP** if a Negative case is
   reported, **FN** if a Positive case is missed, **TN** otherwise.
3. Report Precision, Recall, F1, FPR, and Accuracy per category and overall.

Reference results (native CodeQL vs. Semgrep vs. VRTaint on this benchmark, 141 cases):

| Tool | TP/P | FP/N | Precision | Recall | F1 | FPR | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|
| Native CodeQL | 19/80 | 2/61 | 90.48% | 23.75% | 37.62% | 3.28% | 55.32% |
| Semgrep | 5/80 | 0/61 | 100.00% | 6.25% | 11.76% | 0.00% | 46.81% |
| **VRTaint** | **77/80** | **6/61** | **92.77%** | **96.25%** | **94.48%** | **9.84%** | **93.62%** |

---

## 6. Integrating the Model Pack with Your Own Analyzer

The model pack is analyzer-agnostic as long as your analyzer understands CodeQL data
extensions:

- **With VRTaint**: pass `--additional-packs` + `--model-packs` as in §5.3.
- **With native CodeQL**: the facts can be read by any C# query that declares the same
  extensible predicates; add the pack to `--additional-packs` and import the predicates.
- **With other tools**: the model-pack YAML is a plain, documented fact file; you can
  transpile the component/lifecycle/binding rows into your tool's own facts.

---

## 7. Extending the Benchmark

To add a case:

1. Create `CategoryN-*/<case>.cs` using `TestSources` / `TestSinks` from `Helper/`.
2. If the case needs instance/lifecycle/configuration facts, add rows to
   `BenchmarkSupport/model_pack/models/TryNotDie.model.yml`.
3. Add one row to `benchmark_manifest.csv` with the correct `polarity` and `expected`.
4. For Category-7-style serialized bindings, add the binding to
   `Assets/Scenes/VRTaintBenchmark.unity` (or a new fixture scene).
5. Re-run the analysis and confirm the new case is scored as designed.

**Design rule**: every case must be **minimal** — it should isolate exactly one semantic
control variable. Negatives differ from their positive twin only in the condition under
test (barrier, wrong receiver, wrong argument index, disabled event, etc.).

---

## 8. License and Attribution

- The host game *Try Not to Die* is by Braulio Nayap Maldonado Casilla, Sergio Daniel
  Mogollon Caceres, and Nelzon Jorge Apaza Apaza, licensed under **Apache-2.0**
  (see `LICENSE`).
- The benchmark test cases, model pack, manifest, and minimal scene in this repository
  are distributed under the same **Apache-2.0** license.

---

## 9. Citation

If you use this benchmark in your research, please cite the accompanying paper
(placeholder — insert the VRTaint paper reference here).
