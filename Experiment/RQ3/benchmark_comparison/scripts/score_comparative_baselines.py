from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


STAMP = "v1"
# Anchor: this script lives under <root>/Experiment/RQ3/benchmark_comparison/scripts/.
HERE = Path(__file__).resolve()
RESULTS = HERE.parent.parent / "results"                             # <root>/Experiment/RQ3/benchmark_comparison/results
VRTRAINT_RESULTS = HERE.parents[3] / "RQ1" / "results"                # <root>/Experiment/RQ1/results (VRTaint precision inputs)
DATASET = HERE.parents[4]                                              # <root>
MANIFEST = DATASET / "vulnerability_dataset" / "TryNotDie" / "Assets" / "Scripts" / "_TestCases" / "BenchmarkSupport" / "manifests" / "benchmark_manifest.csv"

CODEQL_INPUTS = {
    "CodeQL": [
        RESULTS / "native_codeql_standard_entities.csv",
        RESULTS / "native_codeql_privacy_entities.csv",
    ],
    "VRTaint": [
        VRTRAINT_RESULTS / "unitytaint_entities.csv",
        VRTRAINT_RESULTS / "privacy_entities.csv",
    ],
}
SEMGREP_INPUT = RESULTS / "semgrep_final.json"

CATEGORY_LABELS = {
    "Category1-CoreDataflow": "C1-CoreDataflow",
    "Category2-ObjectIdentityHeap": "C2-ObjectIdentityHeap",
    "Category3-UnityLifecycle": "C3-UnityLifecycle",
    "Category4-AsyncTemporal": "C4-AsyncTemporal",
    "Category5-DynamicInvocation": "C5-DynamicInvocation",
    "Category6-RuntimeEventDispatch": "C6-RuntimeEventDispatch",
    "Category7-ConfigurationRecoveredEdges": "C7-ConfigurationRecoveredEdges",
    "Category8-Composite": "C8-Composite",
    "Category9-Privacy": "C9-Privacy",
}
TOOLS = ("CodeQL", "Semgrep", "VRTaint")


def relative_source_path(value: str) -> str | None:
    normalized = value.replace("\\", "/")
    match = re.search(r"/Assets/Scripts/_TestCases/(.+?\.cs)(?::\d+|$)", normalized, re.IGNORECASE)
    return match.group(1) if match else None


def ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def percent(value: float) -> str:
    return f"{value * 100:.2f}\\%"


def metric_record(tp: int, tn: int, fp: int, fn: int) -> dict[str, int | float | None]:
    positive = tp + fn
    negative = tn + fp
    precision = None if tp + fp == 0 else ratio(tp, tp + fp)
    recall = ratio(tp, positive)
    f1 = 0.0 if precision is None or precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "P": positive,
        "N": negative,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": ratio(fp, negative),
        "accuracy": ratio(tp + tn, positive + negative),
    }


def main() -> None:
    manifest = list(csv.DictReader(MANIFEST.open(encoding="utf-8-sig")))
    path_to_case: dict[str, str] = {}
    for row in manifest:
        for path in row["relative_paths"].split(";"):
            if path in path_to_case and path_to_case[path] != row["case_id"]:
                raise ValueError(f"ambiguous benchmark source path: {path}")
            path_to_case[path] = row["case_id"]

    detected: dict[str, set[str]] = {tool: set() for tool in TOOLS}
    alert_rows = Counter()
    unmapped: list[dict[str, str]] = []

    for tool, inputs in CODEQL_INPUTS.items():
        for input_path in inputs:
            for index, row in enumerate(csv.DictReader(input_path.open(encoding="utf-8-sig")), start=1):
                alert_rows[tool] += 1
                candidates = [
                    row.get("URL for sink", ""),
                    row.get("URL for col0", ""),
                    row.get("col3", ""),
                    row.get("URL for source", ""),
                ]
                paths = [path for value in candidates if (path := relative_source_path(value))]
                case_id = next((path_to_case[path] for path in paths if path in path_to_case), None)
                if case_id:
                    detected[tool].add(case_id)
                else:
                    unmapped.append({"tool": tool, "input": input_path.name, "row": str(index)})

    semgrep_document = json.loads(SEMGREP_INPUT.read_text(encoding="utf-8"))
    if semgrep_document.get("errors"):
        raise ValueError(f"Semgrep errors: {semgrep_document['errors']}")
    for index, result in enumerate(semgrep_document["results"], start=1):
        alert_rows["Semgrep"] += 1
        path = relative_source_path(result["path"])
        case_id = path_to_case.get(path or "")
        if case_id:
            detected["Semgrep"].add(case_id)
        else:
            unmapped.append({"tool": "Semgrep", "input": SEMGREP_INPUT.name, "row": str(index)})

    cases_by_id = {row["case_id"]: row for row in manifest}
    classifications: list[dict[str, str | bool]] = []
    matrices: dict[str, dict[str, Counter]] = {
        category: {tool: Counter() for tool in TOOLS} for category in CATEGORY_LABELS
    }
    overall = {tool: Counter() for tool in TOOLS}
    for case_id, row in cases_by_id.items():
        positive = row["polarity"] == "P"
        for tool in TOOLS:
            hit = case_id in detected[tool]
            classification = "TP" if positive and hit else "FN" if positive else "FP" if hit else "TN"
            matrices[row["category"]][tool][classification] += 1
            overall[tool][classification] += 1
            classifications.append({
                "case_id": case_id,
                "legacy_case_id": row["legacy_case_id"],
                "category": row["category"],
                "polarity": row["polarity"],
                "tool": tool,
                "detected": hit,
                "classification": classification,
                "relative_paths": row["relative_paths"],
            })

    metrics: dict[str, dict[str, dict[str, int | float | None]]] = {}
    flat_rows: list[dict[str, str | int | float | None]] = []
    for category in CATEGORY_LABELS:
        metrics[category] = {}
        for tool in TOOLS:
            counts = matrices[category][tool]
            record = metric_record(counts["TP"], counts["TN"], counts["FP"], counts["FN"])
            metrics[category][tool] = record
            flat_rows.append({"category": category, "tool": tool, **record})
    metrics["Overall"] = {}
    for tool in TOOLS:
        counts = overall[tool]
        record = metric_record(counts["TP"], counts["TN"], counts["FP"], counts["FN"])
        metrics["Overall"][tool] = record
        flat_rows.append({"category": "Overall", "tool": tool, **record})

    case_output = RESULTS / "comparative_case_results.csv"
    with case_output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(classifications[0].keys()))
        writer.writeheader()
        writer.writerows(classifications)

    metric_output = RESULTS / "comparative_metrics.csv"
    with metric_output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(flat_rows[0].keys()))
        writer.writeheader()
        writer.writerows(flat_rows)

    summary = {
        "status": "PASS" if not unmapped else "FAIL",
        "logical_cases": len(manifest),
        "positive_cases": sum(row["polarity"] == "P" for row in manifest),
        "negative_cases": sum(row["polarity"] == "N" for row in manifest),
        "alert_rows": dict(alert_rows),
        "detected_logical_cases": {tool: len(detected[tool]) for tool in TOOLS},
        "unmapped_alerts": unmapped,
        "metrics": metrics,
    }
    summary_output = RESULTS / "comparative_summary.json"
    summary_output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    latex_lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Quantitative Evaluation Results across Different Vulnerability Categories (RQ1)}",
        r"\label{tab:rq1_results}",
        r"\small",
        r"\setlength{\tabcolsep}{5pt}",
        r"\begin{tabular}{l|l|c|c|c|c|c|c|c}",
        r"\hline",
        r"Category & Tools & TP/P & FP/N & Precision & Recall & F1 & FPR & Accuracy \\ \hline",
    ]
    for category, label in [*CATEGORY_LABELS.items(), ("Overall", "Overall")]:
        for index, tool in enumerate(TOOLS):
            record = metrics[category][tool]
            tool_label = r"\sys{}" if tool == "VRTaint" else tool
            values = [
                f"{record['TP']}/{record['P']}",
                f"{record['FP']}/{record['N']}",
                "---" if record["precision"] is None else percent(float(record["precision"])),
                percent(float(record["recall"])),
                percent(float(record["f1"])),
                percent(float(record["fpr"])),
                percent(float(record["accuracy"])),
            ]
            if tool == "VRTaint":
                values = [rf"\textbf{{{value}}}" for value in values]
            prefix = rf"\multirow{{3}}{{*}}{{{label}}}" if index == 0 else ""
            latex_lines.append(f"{prefix} & {tool_label} & " + " & ".join(values) + r" \\")
        latex_lines.append(r"\hline")
    latex_lines.extend([r"\end{tabular}", r"\end{table*}"])
    latex_output = RESULTS / "comparative_table.tex"
    latex_output.write_text("\n".join(latex_lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False))
    if unmapped:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
