# Comparative Evaluation: Native CodeQL, Semgrep, and VRTaint

## 1. Evaluation Setup

- **Dataset**: nine-category benchmark, 141 logical cases total (80 positives, 61 negatives).
- **Scoring unit**: the logical case in `benchmark_manifest.csv`; a multi-file case is counted once.
- **Source/Sink**: native CodeQL, Semgrep, and VRTaint use the same benchmark source/sink and privacy endpoints.
- **Native CodeQL**: uses the official CodeQL `TaintTracking::Global` with the same endpoints and sanitizers, but without VRTaint's lifecycle, asynchronous, dynamic-invocation, event, configuration-recovery, and instance-context propagation edges.
- **Semgrep**: uses Semgrep OSS `mode: taint` with the same endpoints; at runtime it has no cross-lifecycle, serialized-configuration, or instance-context model.
- **VRTaint**: `UnityTaint.ql`, `UnitySensitiveDataExposure.ql`, and the benchmark data extension.
- The CodeQL database and all three tool inputs come from the same isolated source tree (168 C# files).

## 2. Overall Results

| Tool | TP/P | FP/N | Precision | Recall | F1 | FPR | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|
| Native CodeQL | 19/80 | 2/61 | 90.48% | 23.75% | 37.62% | 3.28% | 55.32% |
| Semgrep | 5/80 | 0/61 | 100.00% | 6.25% | 11.76% | 0.00% | 46.81% |
| VRTaint | 77/80 | 6/61 | 92.77% | 96.25% | 94.48% | 9.84% | 93.62% |

Native CodeQL emitted 21 valid alerts, mapped to 19 TP and 2 FP. Semgrep emitted
5 valid alerts, mapped to 5 TP. VRTaint emitted 95 alerts, mapped to 77 TP and 6 FP.
All alerts mapped to the manifest; 0 unmapped alerts.

## 3. Results by Category

| Category | Tool | TP/P | FP/N | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| C1-CoreDataflow | CodeQL | 3/10 | 0/9 | 100.00% | 30.00% | 46.15% | 0.00% | 63.16% |
|  | Semgrep | 2/10 | 0/9 | 100.00% | 20.00% | 33.33% | 0.00% | 57.89% |
|  | VRTaint | 10/10 | 0/9 | 100.00% | 100.00% | 100.00% | 0.00% | 100.00% |
| C2-ObjectIdentityHeap | CodeQL | 4/18 | 1/13 | 80.00% | 22.22% | 34.78% | 7.69% | 51.61% |
|  | Semgrep | 0/18 | 0/13 | --- | 0.00% | 0.00% | 0.00% | 41.94% |
|  | VRTaint | 17/18 | 4/13 | 80.95% | 94.44% | 87.18% | 30.77% | 83.87% |
| C3-UnityLifecycle | CodeQL | 0/15 | 0/10 | --- | 0.00% | 0.00% | 0.00% | 40.00% |
|  | Semgrep | 0/15 | 0/10 | --- | 0.00% | 0.00% | 0.00% | 40.00% |
|  | VRTaint | 14/15 | 1/10 | 93.33% | 93.33% | 93.33% | 10.00% | 92.00% |
| C4-AsyncTemporal | CodeQL | 5/6 | 1/6 | 83.33% | 83.33% | 83.33% | 16.67% | 83.33% |
|  | Semgrep | 0/6 | 0/6 | --- | 0.00% | 0.00% | 0.00% | 50.00% |
|  | VRTaint | 6/6 | 1/6 | 85.71% | 100.00% | 92.31% | 16.67% | 91.67% |
| C5-DynamicInvocation | CodeQL | 1/14 | 0/12 | 100.00% | 7.14% | 13.33% | 0.00% | 50.00% |
|  | Semgrep | 0/14 | 0/12 | --- | 0.00% | 0.00% | 0.00% | 46.15% |
|  | VRTaint | 13/14 | 0/12 | 100.00% | 92.86% | 96.30% | 0.00% | 96.15% |
| C6-RuntimeEventDispatch | CodeQL | 0/3 | 0/3 | --- | 0.00% | 0.00% | 0.00% | 50.00% |
|  | Semgrep | 0/3 | 0/3 | --- | 0.00% | 0.00% | 0.00% | 50.00% |
|  | VRTaint | 3/3 | 0/3 | 100.00% | 100.00% | 100.00% | 0.00% | 100.00% |
| C7-ConfigurationRecoveredEdges | CodeQL | 0/5 | 0/5 | --- | 0.00% | 0.00% | 0.00% | 50.00% |
|  | Semgrep | 0/5 | 0/5 | --- | 0.00% | 0.00% | 0.00% | 50.00% |
|  | VRTaint | 5/5 | 0/5 | 100.00% | 100.00% | 100.00% | 0.00% | 100.00% |
| C8-Composite | CodeQL | 0/2 | 0/1 | --- | 0.00% | 0.00% | 0.00% | 33.33% |
|  | Semgrep | 0/2 | 0/1 | --- | 0.00% | 0.00% | 0.00% | 33.33% |
|  | VRTaint | 2/2 | 0/1 | 100.00% | 100.00% | 100.00% | 0.00% | 100.00% |
| C9-Privacy | CodeQL | 6/7 | 0/2 | 100.00% | 85.71% | 92.31% | 0.00% | 88.89% |
|  | Semgrep | 3/7 | 0/2 | 100.00% | 42.86% | 60.00% | 0.00% | 55.56% |
|  | VRTaint | 7/7 | 0/2 | 100.00% | 100.00% | 100.00% | 0.00% | 100.00% |

## 4. Result Boundaries

- **Native CodeQL** here is a controlled ablation baseline: it uses the official CodeQL
  dataflow engine with the same source/sink endpoints, not the 172/227 generic official
  alert rules. The generic rules do not expose the `TestSources` / `TestSinks` benchmark
  endpoints, so running the full rule set would not form a same-endpoint comparison.
- **Semgrep**'s input root contains all 168 source files; Semgrep's rule pre-filter
  eventually runs two taint rules on the 27 files that contain the relevant endpoint
  syntax. This pre-filtering is part of Semgrep's own execution flow, not a manual
  removal of test cases.

## 5. Artifacts

- LaTeX table: `comparative_table.tex`
- Metrics CSV: `comparative_metrics.csv`
- Per-case results: `comparative_case_results.csv`
- JSON summary: `comparative_summary.json`
- Native CodeQL inputs: `native_codeql_standard_entities.csv`, `native_codeql_privacy_entities.csv`
- Semgrep results: `semgrep_final.json`
