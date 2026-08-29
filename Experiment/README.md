# VRTaint — Experiments

Reproducible evaluation materials for the VRTaint paper, organized by research
question (RQ). All data has been anonymized (no local absolute paths, no user
names) and uses English file names and field names.

## Research Questions

| RQ | Question | Folder | Key results |
|---|---|---|---|
| **RQ1** | Accuracy of VRTaint on the U-VRFlow benchmark | `RQ1/` | Precision 92.77%, Recall 96.25%, F1 94.48% |
| **RQ2** | Real-world vulnerabilities found by VRTaint | `RQ2/` | 18 confirmed findings (12 security + 6 privacy); added-edge statistics for 70 projects |
| **RQ3** | Comparison against baseline tools (Native CodeQL, Semgrep) | `RQ3/` | Two dimensions: benchmark-level and real-world-level comparison |
| **RQ4** | Runtime/performance comparison | `RQ4/` | Runtime comparison over 80 projects |

---

## Root Files

### `unity_vr_sensitive_apis_98_projects.csv` (~9 MB)

The **98-project Unity VR API corpus** used as the real-world evaluation
ground. It lists Unity-sensitive API usages (callbacks, coroutines, dynamic
invocation, reflection, UnityEvent, etc.) per project.

**Origin**: the 98 projects are drawn from **VRExplorer: A Model-based
Approach for Semi-Automated Testing of Virtual Reality Scenes**
(the VRExplorer dataset), and then **screened/filtered** for VRTaint's
evaluation:

- filtered to projects with a standard Unity structure (`Assets/`,
  `ProjectSettings/`) and C# source;
- deduplicated (owner/repo normalized, renamed to `owner_repo`);
- kept projects with meaningful API-usage signal (sensitive API counts);
- each row records the project, an absolute-free location
  (`<project>/Assets/...:line:col`), the semantic category, mechanism, API,
  owning class, and a detail note.

Columns: `project, loc, category, mechanism, api, owner, detail`.

### `api_frequency_by_project.csv`

Per-project frequency of the target Unity-sensitive APIs (coroutines,
`InvokeRepeating`, `SendMessage`, `BroadcastMessage`, `UnityEvent`,
reflection, `async`/`await`, `Task`/`Awaitable`, …) plus a `total_target_apis`
column. Used by RQ2/RQ4 analyses.

---

## RQ1 — VRTaint Accuracy on U-VRFlow Benchmark

```
RQ1/
├── RQ1 results.xlsx
├── scripts/
│   ├── score_accuracy.py                 # scoring: logical cases -> confusion matrix / metrics
│   └── prepare_accuracy_evaluation.py    # historical one-time setup (reference only)
└── results/
    ├── benchmark_accuracy_report.md / benchmark_accuracy_summary.json
    ├── benchmark_case_results.csv / benchmark_misclassifications.csv
    ├── unitytaint_entities.csv           # VRTaint UnityTaint.ql raw findings
    └── privacy_entities.csv              # VRTaint privacy findings
```

**Overall result** (141 logical cases: 80 P / 61 N):

| Metric | Value |
|---|---:|
| Precision | 92.77% |
| Recall | 96.25% |
| F1 | 94.48% |
| Accuracy | 93.62% |

---

## RQ2 — Real-World Findings

```
RQ2/
├── RQ2_70_projects_added_edges_statistics.xlsx   # added propagation edges over 70 projects
└── RQ2_vulnerability_findings_table.csv          # 18 confirmed findings (S01–S12, P01–P06)
```

- **18 findings**: 12 security (Zip Slip, BinaryFormatter deserialization,
  path traversal, command injection, unbounded gRPC decompression,
  UnityPackage traversal, …) and 6 privacy (microphone, head/hand tracking,
  Photon autosync, biometric UDP exfiltration, …).
- **70-project added-edge statistics**: counts of lifecycle / async /
  configuration-event edges VRTaint recovers beyond native analysis.

---

## RQ3 — Baseline Comparison (two dimensions)

```
RQ3/
├── benchmark_comparison/        # benchmark-level comparison (9 categories, 141 cases)
│   ├── baseline_comparison_18_issues.xlsx
│   ├── scripts/score_comparative_baselines.py
│   └── results/                 # comparative metrics/summary/cases + native_codeql + semgrep inputs
└── real_world_comparison/       # real-world comparison (18-finding oracle)
    ├── scripts/                 # extract_oracle_candidates, run_baselines, run_vrtaint_oracle, resume_semgrep_gitroot
    ├── intermediate/finding_manifest.csv
    ├── reports/                 # detection_summary.md (+ C# scope variant)
    └── results/                 # tool_oracle_comparison.csv, oracle_location_candidates.csv, vrtaint_rerun_findings.csv
```

### Benchmark level (141 logical cases)

| Tool | TP/P | FP/N | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|
| Native CodeQL | 19/80 | 2/61 | 90.48% | 23.75% | 37.62% | 55.32% |
| Semgrep | 5/80 | 0/61 | 100.00% | 6.25% | 11.76% | 46.81% |
| **VRTaint** | **77/80** | **6/61** | **92.77%** | **96.25%** | **94.48%** | **93.62%** |

### Real-world level (18-finding oracle on 98-project corpus)

| Tool | Target hits | Rate | Notes |
|---|---:|---:|---|
| Native CodeQL (official C#/JS suites) | 3/18 | 16.67% | S01/S06 zipslip + S08 JS command injection |
| Semgrep (official registry rules) | 3/18 | 16.67% | sink/location hits only; no full source-to-sink chain |
| **VRTaint** | **9/18** | **50.00%** | 6 security + 3 privacy confirmed via rerun |

Neither baseline detects any of the six privacy flows. Baselines hit isolated
sink locations but cannot reconstruct Unity lifecycle/async/configuration
source-to-sink chains — the core contribution of VRTaint.

---

## RQ4 — Runtime Comparison

```
RQ4/
└── RQ4-80_projects_runtime_comparison.xlsx   # runtime over 80 projects
```

Runtime (wall-clock) comparison of VRTaint vs. baseline tools across 80
real-world projects.

---

## Reproducing

- **RQ1 / RQ3 benchmark**: run `score_accuracy.py` (RQ1) and
  `score_comparative_baselines.py` (RQ3) — both resolve paths relative to
  their own location and read the U-VRFlow benchmark manifest under
  `vulnerability_dataset/TryNotDie`.
- **RQ3 real-world**: scripts are historical run scripts kept for
  traceability; the oracle manifest and final comparison CSVs are the
  authoritative results.
- All scripts require Python 3.10+ and CodeQL CLI for re-runs.

## Notes

- The U-VRFlow benchmark itself (test cases, prebuilt CodeQL database) ships
  in `../U-VRFlow-Benchmark/`.
- 98-project corpus is a **filtered subset** of the VRExplorer dataset
  (*VRExplorer: A Model-based Approach for Semi-Automated Testing of Virtual
  Reality Scenes*); see `unity_vr_sensitive_apis_98_projects.csv` for the
  per-project API inventory used in the evaluation.
