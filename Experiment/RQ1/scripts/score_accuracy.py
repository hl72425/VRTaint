from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


STAMP = "v1"
# Anchor: this script lives under <root>/Experiment/RQ1/scripts/.
HERE = Path(__file__).resolve()
RESULTS = HERE.parent.parent / "results"                          # <root>/Experiment/RQ1/results
DATASET = HERE.parents[3]                                          # <root>
MANIFEST = DATASET / "vulnerability_dataset" / "TryNotDie" / "Assets" / "Scripts" / "_TestCases" / "BenchmarkSupport" / "manifests" / "benchmark_manifest.csv"
QUERY_RESULTS = {
    "UnityTaint.ql": RESULTS / "unitytaint_entities.csv",
    "UnitySensitiveDataExposure.ql": RESULTS / "privacy_entities.csv",
}


def source_path_from_url(value: str) -> str | None:
    normalized = value.replace("\\", "/")
    match = re.search(r"/Assets/Scripts/_TestCases/(.+?\.cs)(?::\d+|$)", normalized, re.IGNORECASE)
    return match.group(1) if match else None


def metric(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def main() -> None:
    manifest = list(csv.DictReader(MANIFEST.open(encoding="utf-8-sig")))
    path_to_case: dict[str, str] = {}
    for row in manifest:
        for path in row["relative_paths"].split(";"):
            if path in path_to_case and path_to_case[path] != row["case_id"]:
                raise ValueError(f"source belongs to multiple logical cases: {path}")
            path_to_case[path] = row["case_id"]

    alert_counts: Counter[tuple[str, str]] = Counter()
    unmapped_alerts: list[dict[str, str]] = []
    query_row_counts: dict[str, int] = {}
    for query_name, csv_path in QUERY_RESULTS.items():
        rows = list(csv.DictReader(csv_path.open(encoding="utf-8-sig")))
        query_row_counts[query_name] = len(rows)
        for index, row in enumerate(rows, start=1):
            # A benchmark classification belongs to the sink-side logical case.
            # This avoids crediting a source case when a deliberately imprecise
            # cross-case edge reaches a sink in another case.
            candidates = [
                row.get("URL for sink", ""),
                row.get("URL for col0", ""),
                row.get("col3", ""),
            ]
            extracted = [path for value in candidates if (path := source_path_from_url(value))]
            relative = next((path for path in extracted if path in path_to_case), extracted[0] if extracted else None)
            case_id = path_to_case.get(relative or "")
            if case_id:
                alert_counts[(case_id, query_name)] += 1
            else:
                unmapped_alerts.append({
                    "query": query_name,
                    "row": str(index),
                    "relative_path": relative or "",
                    "sink": row.get("sink", ""),
                })

    scored: list[dict[str, str | int | bool]] = []
    matrix = Counter()
    category_matrix: dict[str, Counter] = defaultdict(Counter)
    for row in manifest:
        per_query = {query: alert_counts[(row["case_id"], query)] for query in QUERY_RESULTS}
        detected = sum(per_query.values()) > 0
        positive = row["polarity"] == "P"
        classification = "TP" if positive and detected else "FN" if positive else "FP" if detected else "TN"
        matrix[classification] += 1
        category_matrix[row["category"]][classification] += 1
        scored.append({
            **row,
            "detected": detected,
            "classification": classification,
            "unitytaint_alerts": per_query["UnityTaint.ql"],
            "privacy_alerts": per_query["UnitySensitiveDataExposure.ql"],
            "total_alerts": sum(per_query.values()),
        })

    tp, tn, fp, fn = (matrix[key] for key in ("TP", "TN", "FP", "FN"))
    precision = metric(tp, tp + fp)
    recall = metric(tp, tp + fn)
    accuracy = metric(tp + tn, len(manifest))
    f1 = metric(2 * precision * recall, precision + recall)

    case_result_path = RESULTS / "benchmark_case_results.csv"
    with case_result_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(scored[0].keys()))
        writer.writeheader()
        writer.writerows(scored)

    misclassified = [row for row in scored if row["classification"] in {"FP", "FN"}]
    misclassified_path = RESULTS / "benchmark_misclassifications.csv"
    with misclassified_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(scored[0].keys()))
        writer.writeheader()
        writer.writerows(misclassified)

    summary = {
        "status": "PASS",
        "scoring_unit": "logical manifest case",
        "logical_cases": len(manifest),
        "positive_cases": sum(row["polarity"] == "P" for row in manifest),
        "negative_cases": sum(row["polarity"] == "N" for row in manifest),
        "query_alert_rows": query_row_counts,
        "mapped_alert_rows": sum(alert_counts.values()),
        "unmapped_alert_rows": len(unmapped_alerts),
        "confusion_matrix": dict(matrix),
        "precision": precision,
        "recall": recall,
        "accuracy": accuracy,
        "f1": f1,
        "category_matrix": {category: dict(counts) for category, counts in sorted(category_matrix.items())},
        "false_positive_case_ids": [str(row["case_id"]) for row in misclassified if row["classification"] == "FP"],
        "false_negative_case_ids": [str(row["case_id"]) for row in misclassified if row["classification"] == "FN"],
        "unmapped_alerts": unmapped_alerts,
    }
    summary_path = RESULTS / "benchmark_accuracy_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    report_path = RESULTS / "benchmark_accuracy_report.md"
    category_lines = []
    for category, counts in sorted(category_matrix.items()):
        total = sum(counts.values())
        category_accuracy = metric(counts["TP"] + counts["TN"], total)
        category_lines.append(
            f"| {category} | {counts['TP']} | {counts['TN']} | {counts['FP']} | {counts['FN']} | {category_accuracy:.2%} |"
        )
    report = f"""# Nine-Category Benchmark Accuracy Evaluation

## Overall Results

| Metric | Value |
|---|---:|
| Logical cases | {len(manifest)} |
| TP | {tp} |
| TN | {tn} |
| FP | {fp} |
| FN | {fn} |
| Precision | {precision:.2%} |
| Recall | {recall:.2%} |
| Accuracy | {accuracy:.2%} |
| F1 | {f1:.2%} |

The scoring unit is the logical case in the manifest; multi-file cases are counted once. The two queries emitted {sum(query_row_counts.values())} alert rows in total, of which {sum(alert_counts.values())} mapped to cases and {len(unmapped_alerts)} remained unmapped.

## Results by Category

| Category | TP | TN | FP | FN | Accuracy |
|---|---:|---:|---:|---:|---:|
{chr(10).join(category_lines)}

## Misclassifications

- FP: {', '.join(summary['false_positive_case_ids']) or 'none'}
- FN: {', '.join(summary['false_negative_case_ids']) or 'none'}

Detailed per-case results are in `{case_result_path.name}`; the misclassification list is in `{misclassified_path.name}`.
"""
    report_path.write_text(report, encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
