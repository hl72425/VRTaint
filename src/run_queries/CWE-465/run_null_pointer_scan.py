import os
import subprocess
import csv
import re
import datetime

# === 配置区 ===
base_dir = r"E:/VR_project/dataset/vulnerability_dataset/CWE-465/Null Pointer/"
ql_query = r"E:/VR_project/dataset/queries/Extract_Candidate/unity-vr-sensitive-apis.ql"  # 查询文件路径

database_v = "v1"
DB_PATTERN = re.compile(rf"^codeql-db_{database_v}_[0-9]{{8}}_[0-9]{{4}}$")

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
results_csv = f"E:/VR_project/dataset/results/unity-vr-sensitive-apis_query_{database_v}_{timestamp}.csv"


def log(msg: str):
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}")


def run_query_on_db(db_path, db_name):
    """在指定 CodeQL 数据库上运行查询"""
    out_bqrs = os.path.join(db_path, f"{db_name}_unity-vr-sensitive-apis.bqrs")
    out_csv = os.path.join(db_path, f"{db_name}_unity-vr-sensitive-apis.csv")

    try:
        # 1️⃣ 执行 CodeQL 查询
        subprocess.run([
            "codeql", "query", "run", ql_query,
            "--database", db_path,
            "--output", out_bqrs
        ], check=True)

        # 2️⃣ 导出结果为 CSV
        subprocess.run([
            "codeql", "bqrs", "decode", out_bqrs,
            "--format=csv", "--output", out_csv
        ], check=True)

        log(f"✅ 查询完成: {db_name}")
        return out_csv

    except subprocess.CalledProcessError as e:
        log(f"❌ 查询失败: {db_name}, 错误: {e}")
        return None


def batch_scan(base_dir, results_csv):
    """递归遍历所有项目，识别并运行匹配版本的 CodeQL 数据库"""
    all_results = []
    failed_projects = []  # 用于记录未建库的项目

    for root, dirs, files in os.walk(base_dir):
        # 检查该目录下是否有匹配的数据库
        matched_dbs = [d for d in dirs if DB_PATTERN.match(d)]

        if not matched_dbs:
            # 若该目录下没有 codeql-db_v_1_*，则认为数据库未建立
            project_name = os.path.basename(root)
            if project_name.endswith("_pre"):  # 仅标记项目根目录
                failed_projects.append(project_name)
            continue

        # 若有多个匹配数据库，依次执行查询
        for db_dir in matched_dbs:
            db_path = os.path.join(root, db_dir)
            db_name = db_dir.replace("codeql-db_", "")
            log(f"🚀 开始执行查询: {db_name}")

            out_csv = run_query_on_db(db_path, db_name)
            if out_csv:
                all_results.append((db_name, out_csv))

    # === 汇总结果 ===
    with open(results_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Database_Version", "ResultFile"])
        for db_name, out_csv in all_results:
            writer.writerow([db_name, out_csv])

    log(f"🏁 批量查询完成，结果索引保存到: {results_csv}")

    # === 记录未建立数据库的项目 ===
    if failed_projects:
        fail_log = results_csv.replace(".csv", "_failed_projects.txt")
        with open(fail_log, "w", encoding="utf-8") as f:
            f.write("以下项目未建立数据库:\n")
            f.write("\n".join(failed_projects))
        log(f"⚠️ 未建立数据库的项目列表已保存: {fail_log}")


if __name__ == "__main__":
    log(f"🌍 CodeQL 批量分析启动: 版本={database_v}, 时间戳={timestamp}")
    batch_scan(base_dir, results_csv)
