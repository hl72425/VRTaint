# Nine-Category Benchmark Accuracy Evaluation

## Overall Results

| Metric | Value |
|---|---:|
| Logical cases | 141 |
| TP | 77 |
| TN | 55 |
| FP | 6 |
| FN | 3 |
| Precision | 92.77% |
| Recall | 96.25% |
| Accuracy | 93.62% |
| F1 | 94.48% |

The scoring unit is the logical case in the manifest; multi-file cases are counted once. The two queries emitted 95 alert rows in total, of which 95 mapped to cases and 0 remained unmapped.

## Results by Category

| Category | TP | TN | FP | FN | Accuracy |
|---|---:|---:|---:|---:|---:|
| Category1-CoreDataflow | 10 | 9 | 0 | 0 | 100.00% |
| Category2-ObjectIdentityHeap | 17 | 9 | 4 | 1 | 83.87% |
| Category3-UnityLifecycle | 14 | 9 | 1 | 1 | 92.00% |
| Category4-AsyncTemporal | 6 | 5 | 1 | 0 | 91.67% |
| Category5-DynamicInvocation | 13 | 12 | 0 | 1 | 96.15% |
| Category6-RuntimeEventDispatch | 3 | 3 | 0 | 0 | 100.00% |
| Category7-ConfigurationRecoveredEdges | 5 | 5 | 0 | 0 | 100.00% |
| Category8-Composite | 2 | 1 | 0 | 0 | 100.00% |
| Category9-Privacy | 7 | 2 | 0 | 0 | 100.00% |

## Misclassifications

- FP: 2.2N, 2.13N, 2.18N, 2.20N, 3.7N, 4.1N
- FN: 2.3P, 3.13P, 5.10P

Detailed per-case results are in `benchmark_case_results.csv`; the misclassification list is in `benchmark_misclassifications.csv`.
