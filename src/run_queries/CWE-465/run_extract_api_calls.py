import os
import subprocess
import csv
import re
import datetime

# === Config ===
base_dir = r"E:/1_my_project/dataset/vulnerability_dataset/"
ql_external = r"E:/1_my_project/dataset/queries/Extract_Candidate/fetch_external_apis.ql"
ql_internal = r"E:/1_my_project/dataset/queries/Extract_Candidate/fetch_func_params.ql"

database_v = "v1"
DB_PATTERN = re.compile(rf"^codeql-db_{database_v}_[0-9]{{8}}_[0-9]{{4}}$")

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
results_dir = f"E:/1_my_project/dataset/results/api_extraction_{database_v}_{timestamp}"
os.makedirs(results_dir, exist_ok=True)


def log(msg: str):
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}")


def run_query(db_path, db_name, ql_file, query_type):
    """Run a specific CodeQL query (external/internal)"""
    out_bqrs = os.path.join(db_path, f"{db_name}_{query_type}.bqrs")
    out_csv = os.path.join(db_path, f"{db_name}_{query_type}.csv")

    try:
        # 1️⃣ Run CodeQL query
        subprocess.run([
            "codeql", "query", "run", ql_file,
            "--database", db_path,
            "--output", out_bqrs
        ], check=True)

        # 2️⃣ Decode BQRS → CSV
        subprocess.run([
            "codeql", "bqrs", "decode", out_bqrs,
            "--format=csv", "--output", out_csv
        ], check=True)

        log(f"✅ {query_type.capitalize()} query completed: {db_name}")
        return out_csv

    except subprocess.CalledProcessError as e:
        log(f"❌ Query failed ({query_type}): {db_name}, error: {e}")
        return None


def batch_extract(base_dir, results_dir):
    """Batch run external/internal API queries"""
    all_results = []
    failed_projects = []

    for root, dirs, files in os.walk(base_dir):
        matched_dbs = [d for d in dirs if DB_PATTERN.match(d)]

        if not matched_dbs:
            project_name = os.path.basename(root)
            if project_name.endswith("_pre"):
                failed_projects.append(project_name)
            continue

        for db_dir in matched_dbs:
            db_path = os.path.join(root, db_dir)
            db_name = db_dir.replace("codeql-db_", "")
            log(f"🚀 Start querying: {db_name}")

            # External API query
            ext_csv = run_query(db_path, db_name, ql_external, "external_api")
            # Internal function query
            int_csv = run_query(db_path, db_name, ql_internal, "internal_func")

            if ext_csv or int_csv:
                all_results.append((db_name, ext_csv, int_csv))

    # === Save combined index ===
    results_csv = os.path.join(results_dir, "api_extraction_index.csv")
    with open(results_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Database_Version", "ExternalAPI_CSV", "InternalFunc_CSV"])
        for db_name, ext_csv, int_csv in all_results:
            writer.writerow([db_name, ext_csv or "", int_csv or ""])

    log(f"🏁 All queries completed, index saved: {results_csv}")

    # === Save failed projects ===
    if failed_projects:
        fail_log = os.path.join(results_dir, "failed_projects.txt")
        with open(fail_log, "w", encoding="utf-8") as f:
            f.write("Projects without CodeQL DB:\n")
            f.write("\n".join(failed_projects))
        log(f"⚠️ Missing databases saved: {fail_log}")


if __name__ == "__main__":
    log(f"🌍 API Extraction Start — Version={database_v}, Time={timestamp}")
    batch_extract(base_dir, results_dir)
