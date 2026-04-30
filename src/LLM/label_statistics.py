import yaml
import csv
import json
import subprocess
import datetime
import time
import os
import re


TARGET_CWE_ID = "465"
base_dir = r"E:/1_my_project/dataset/vulnerability_dataset/CWE-465/Null Pointer/"
database_v = "v1"
DB_PATTERN = re.compile(rf"^codeql-db_{database_v}_[0-9]{{8}}_[0-9]{{4}}$")


def log(msg: str):
    """统一日志输出"""
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}")


def json_to_csv_converter(labeled_json, output_filename):
    try:
        with open(labeled_json, 'r', encoding='utf-8') as f:
            json_list = json.load(f)
    except FileNotFoundError:
        print(f"错误：未找到文件 {labeled_json}")
        return

    fieldnames = list(json_list[0].keys())
    processed_list = []
    for item in json_list:
        row = item.copy()
        for key, value in row.items():
            if isinstance(value, list):
                row[key] = ','.join(map(str, value))
            if value is None:
                row[key] = ''
        processed_list.append(row)

    try:
        with open(output_filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(processed_list)

        print(f"成功将 {len(json_list)} 条记录转换并保存到文件: {output_filename}")

    except IOError:
        print(f"错误：无法写入文件 {output_filename}")


def process_db(db_path, db_name):
    """处理单个数据库目录"""
    label_json = os.path.join(db_path, f"{db_name}_labeled.json")
    output_filename = os.path.join(db_path, f"{db_name}_labeled.csv")
    json_to_csv_converter(label_json, output_filename)


def process_project(project_path):
    """处理单个项目"""
    project_name = os.path.basename(project_path)
    log(f"=== 🧩 Processing project: {project_name} ===")

    dirs = [d for d in os.listdir(project_path) if DB_PATTERN.match(d)]
    if not dirs:
        log(f"⚠️ No CodeQL DB found for {project_name}")
        return

    for db_dir in dirs:
        db_path = os.path.join(project_path, db_dir)
        db_name = db_dir.replace("codeql-db_", "")
        process_db(db_path, db_name)


def main():
    for project in os.listdir(base_dir):
        if project.endswith("_pre"):
            project_path = os.path.join(base_dir, project)
            process_project(project_path)


if __name__ == "__main__":
    main()

