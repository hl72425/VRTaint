import os
import re
import ast
import pandas as pd
from tqdm import tqdm
import glob


CODEQL_BASE_DIR = r"E:\1_my_project\dataset\vulnerability_dataset\CWE-465\Null Pointer"
COMMIT_INFO_PATH = r"E:\1_my_project\dataset\commit_info\commit_info_with_diffs_all.xlsx"
OUTPUT_SUMMARY_PATH = r"E:\1_my_project\dataset\results\eval_results_CWE465_summary.xlsx"
OUTPUT_DETAILS_PATH = r"E:\1_my_project\dataset\results\eval_results_CWE465_details.xlsx"
database_ver = "v1"
# ==========================================================


# ------------------ 工具函数 ------------------

def normalize_path(path: str) -> str:
    """统一路径格式（兼容Win/Linux）"""
    return os.path.normpath(path).replace("\\", "/").lower()


def extract_project_commit(folder_name: str):
    """
    从文件夹名中提取项目名和commit哈希
    e.g. leapmotion_Paint_e5f71744a571013ad63f2b623fa40c9b4a07d1f0_pre
    """
    match = re.match(r"(.+)_([0-9a-f]{8,40})_pre", folder_name)
    if not match:
        return None, None
    return match.group(1), match.group(2)


def line_in_ranges(line: int, ranges):
    """判断行号是否命中修改范围"""
    for start, end in ranges:
        if start <= line <= end:
            return True
    return False


def load_commit_info(path: str) -> pd.DataFrame:
    """加载真实标签表"""
    print(f"[INFO] 正在加载真实标签文件：{path}")
    df = pd.read_excel(path)
    df['project'] = df['project'].astype(str)
    df['commit_hash'] = df['commit_hash'].astype(str)

    # 解析 added_lines / removed_lines JSON 字段
    for col in ['added_lines', 'removed_lines']:
        df[col] = df[col].apply(
            lambda x: ast.literal_eval(x) if isinstance(x, str) and x.startswith('[[') else []
        )

    df['file_path_norm'] = df['file_path'].apply(lambda p: normalize_path(str(p)) if pd.notna(p) else "")
    print(f"[INFO] 已加载 {len(df)} 条 commit 信息。")
    return df


def find_latest_codeql_result(project_folder: str) -> str | None:
    try:
        db_dirs = glob.glob(os.path.join(project_folder, "codeql-db_*"))

        if not db_dirs:
            print(f"[WARN] 在 '{project_folder}' 中没有找到 'codeql-db_*' 目录。")
            return None

        # 2. 按名称排序以找到最新的目录（时间戳在末尾，默认字符串排序即可）
        latest_db_dir = sorted(db_dirs)[-1]

        # 确保它是一个目录
        if not os.path.isdir(latest_db_dir):
            print(f"[WARN] 找到的路径 '{latest_db_dir}' 不是一个目录。")
            return None

        # 3. 从目录名中提取公共版本号
        # 例如, 从 '.../codeql-db_v1_20251014_0004' 提取 'v1_20251014_0004'
        dir_basename = os.path.basename(latest_db_dir)
        version_stamp = dir_basename.replace("codeql-db_", "", 1)  # 只替换第一个匹配项

        # 4. 构建结果文件的搜索模式
        result_file_pattern = os.path.join(latest_db_dir, f"{version_stamp}_result.csv")

        # 5. 查找匹配的结果文件
        result_files = glob.glob(result_file_pattern)

        if not result_files:
            print(f"[WARN] 在目录 '{latest_db_dir}' 中没有找到匹配的结果文件 '{os.path.basename(result_file_pattern)}'。")
            return None

        # 假设每个数据库只有一个结果文件，返回第一个找到的
        return result_files[0]

    except Exception as e:
        print(f"[ERROR] 在查找 CodeQL 结果文件时发生错误: {e}")
        return None


# ========== 新增：辅助函数，用于解析CodeQL的描述字符串 ==========
def parse_ql_description(description_str):
    """
    使用正则表达式从 CodeQL 的描述字符串中提取文件路径和行号。
    示例输入: "access to property... file: Editor/MyFile.cs line: 14 method: OnEnable..."
    示例输出: ('Editor/MyFile.cs', 14)
    """
    if not isinstance(description_str, str):
        return None, -1

    file_path = None
    line_number = -1

    # 正则表达式来匹配 "file: [路径]" 和 "line: [数字]"
    # r"file:\s*(.*?)\s*(?:line:|method:|object:|issue:|$)"
    # - file:\s* -> 匹配 "file:" 和任意空格
    # - (.*?)            -> 非贪婪地捕获所有字符（这就是文件路径），直到...
    # - \s* -> 任意空格
    # - (?:...|...|$)    -> 遇到 "line:", "method:", 或字符串结尾为止
    file_match = re.search(r"file:\s*(.*?)\s*(?:line:|method:|object:|issue:|$)", description_str)
    if file_match:
        file_path = file_match.group(1).strip()

    # r"line:\s*(\d+)"
    # - line:\s* -> 匹配 "line:" 和任意空格
    # - (\d+)            -> 捕获一个或多个数字（这就是行号）
    line_match = re.search(r"line:\s*(\d+)", description_str)
    if line_match:
        line_number = int(line_match.group(1))

    return file_path, line_number


def evaluate_single_project(project_folder: str, commit_df: pd.DataFrame):
    """
    Evaluates a single project's CodeQL scan results against the ground truth.
    Returns a tuple containing (metrics_dict, details_list).
    """
    folder_name = os.path.basename(project_folder)
    project, commit_hash = extract_project_commit(folder_name)
    if not project or not commit_hash:
        print(f"[WARN] Skipping invalid folder name format: {folder_name}")
        return None

    # Find CodeQL result file dynamically
    ql_path = find_latest_codeql_result(project_folder)
    if not ql_path:
        return {
                   "project": project, "commit_hash": commit_hash, "TP": 0, "FP": 0, "FN": 1,
                   "Precision": 0.0, "Recall": 0.0, "F1": 0.0, "has_result_file": False
               }, []

    # Read and parse CodeQL output
    try:
        ql_df = pd.read_csv(ql_path, header=None, names=['type', 'description'])
    except Exception as e:
        print(f"[ERROR] Reading CodeQL result failed: {ql_path}, {e}")
        return None

    if ql_df.empty:
        # If CodeQL found nothing, it's 1 FN if there's a real vulnerability
        truth_exists = not commit_df[
            (commit_df['project'] == project) & (commit_df['commit_hash'] == commit_hash)].empty
        return {
                   "project": project, "commit_hash": commit_hash, "TP": 0, "FP": 0, "FN": 1 if truth_exists else 0,
                   "Precision": 0.0, "Recall": 0.0, "F1": 0.0, "has_result_file": True
               }, []

    parsed_data = ql_df['description'].apply(parse_ql_description)
    ql_df[['file', 'line']] = pd.DataFrame(parsed_data.tolist(), index=ql_df.index)
    ql_df.dropna(subset=['file'], inplace=True)

    if ql_df.empty:
        truth_exists = not commit_df[
            (commit_df['project'] == project) & (commit_df['commit_hash'] == commit_hash)].empty
        return {
                   "project": project, "commit_hash": commit_hash, "TP": 0, "FP": 0, "FN": 1 if truth_exists else 0,
                   "Precision": 0.0, "Recall": 0.0, "F1": 0.0, "has_result_file": True
               }, []

    ql_df['file_norm'] = ql_df['file'].apply(normalize_path)
    ql_df['line'] = ql_df['line'].fillna(-1).astype(int)

    # Get ground truth for this specific project and commit
    truth_subset = commit_df[(commit_df['project'] == project) & (commit_df['commit_hash'] == commit_hash)]

    if truth_subset.empty:
        # No ground truth means all CodeQL alerts are false positives
        return {
                   "project": project, "commit_hash": commit_hash, "TP": 0, "FP": len(ql_df), "FN": 0,
                   "Precision": 0.0, "Recall": 0.0, "F1": 0.0, "has_result_file": True
               }, []

    # Alert-level evaluation
    tp_alerts, fp_alerts, detailed_records = [], [], []
    for _, qrow in ql_df.iterrows():
        q_file, q_line = qrow['file_norm'], qrow['line']
        is_match = False
        for _, truth in truth_subset.iterrows():
            if q_file.endswith(truth['file_path_norm']) and line_in_ranges(q_line, truth['added_lines'] or truth[
                'removed_lines']):
                is_match = True
                break

        detailed_records.append({
            "project": project, "commit_hash": commit_hash, "file": q_file,
            "line": q_line, "source_file": ql_path, "matched": is_match
        })
        if is_match:
            tp_alerts.append(qrow)
        else:
            fp_alerts.append(qrow)

    # Calculate final metrics based on alert-level results
    TP = len(tp_alerts)
    FP = len(fp_alerts)
    FN = 1 if TP == 0 else 0

    total_alerts = TP + FP
    precision = TP / total_alerts if total_alerts > 0 else 0.0
    found_vuln = 1 if TP > 0 else 0
    recall = found_vuln / (found_vuln + FN) if (found_vuln + FN) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"[RESULT] {project}-{commit_hash[:8]} | TP={TP}, FP={FP}, FN={FN} | "
          f"P={precision:.3f}, R={recall:.3f}, F1={f1:.3f}")

    metrics = {
        "project": project, "commit_hash": commit_hash, "TP": TP, "FP": FP, "FN": FN,
        "Precision": round(precision, 3), "Recall": round(recall, 3), "F1": round(f1, 3), "has_result_file": True
    }
    return metrics, detailed_records


# ------------------ Main Execution Flow ------------------

def main():
    """Main function to run the entire evaluation process."""
    commit_df = load_commit_info(COMMIT_INFO_PATH)
    project_folders = [d for d in glob.glob(os.path.join(CODEQL_BASE_DIR, "*")) if os.path.isdir(d)]

    if not project_folders:
        print(f"[ERROR] No project folders found in '{CODEQL_BASE_DIR}'. Please check the path.")
        return

    print(f"\n[INFO] Found {len(project_folders)} project folders to evaluate.")

    all_metrics, all_details = [], []
    for folder in tqdm(project_folders, desc="Evaluating Projects"):
        result = evaluate_single_project(folder, commit_df)
        if result:
            metrics, details = result
            all_metrics.append(metrics)
            all_details.extend(details)

    if not all_metrics:
        print("\n[ERROR] No projects were successfully evaluated. No output files will be generated.")
        return

    # Create DataFrames from results
    metrics_df = pd.DataFrame(all_metrics)
    details_df = pd.DataFrame(all_details)

    # Calculate overall summary metrics
    total_tp = metrics_df["TP"].sum()
    total_fp = metrics_df["FP"].sum()
    total_fn = metrics_df["FN"].sum()

    # Micro-average Precision: Correct alerts out of all alerts
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    # Micro-average Recall: Found vulnerabilities out of all vulnerabilities
    overall_recall = total_tp / (total_tp + total_fn) if (
                                                                     total_tp + total_fn) > 0 else 0.0  # Note: this is a different interpretation than per-project recall

    if (overall_precision + overall_recall) > 0:
        overall_f1 = 2 * overall_precision * overall_recall / (overall_precision + overall_recall)
    else:
        overall_f1 = 0.0

    summary_row = {
        "project": "OVERALL", "commit_hash": "-", "TP": total_tp, "FP": total_fp, "FN": total_fn,
        "Precision": round(overall_precision, 3), "Recall": round(overall_recall, 3), "F1": round(overall_f1, 3),
        "has_result_file": "-"
    }
    metrics_df = pd.concat([metrics_df, pd.DataFrame([summary_row])], ignore_index=True)

    # Save results to Excel files
    metrics_df.to_excel(OUTPUT_SUMMARY_PATH, index=False)
    details_df.to_excel(OUTPUT_DETAILS_PATH, index=False)

    print("\n✅ Evaluation complete!")
    print(f"📊 Summary metrics saved to: {OUTPUT_SUMMARY_PATH}")
    print(f"📜 Detailed results saved to: {OUTPUT_DETAILS_PATH}")
    print("\n--- Overall Performance ---")
    print(summary_row)


if __name__ == "__main__":
    main()
