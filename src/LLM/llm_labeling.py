import yaml
import csv
import json
import subprocess
import datetime
import time
import os
import re
from openai import OpenAI
from strict_prompt import (
    API_LABELLING_SYSTEM_PROMPT,
    API_LABELLING_USER_PROMPT,
    FUNC_PARAM_LABELLING_SYSTEM_PROMPT,
    FUNC_PARAM_LABELLING_USER_PROMPT
)

# ========================
# === 全局配置部分 ===
# ========================
BATCH_SIZE = 10  # 每次模型调用处理的 API 数量
TARGET_CWE_ID = "465"
base_dir = r"E:/1_my_project/dataset/vulnerability_dataset/CWE-465/Null Pointer/"
yaml_path = r"E:\1_my_project\dataset\src\LLM\cwe_info_unity.yaml"
database_v = "v1"
DB_PATTERN = re.compile(rf"^codeql-db_{database_v}_[0-9]{{8}}_[0-9]{{4}}$")

# LLM 客户端配置
client = OpenAI(
    api_key=os.getenv("DASHSCOPE_API_KEY"),
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
)


# ========================
# === 通用函数部分 ===
# ========================
def log(msg: str):
    """统一日志输出"""
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}")


def load_cwe_definitions(yaml_path):
    """读取 YAML CWE 定义文件"""
    with open(yaml_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_api_list(csv_path):
    """读取 CSV 文件并返回 API 列表"""
    apis = []
    with open(csv_path, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            apis.append(row)
    return apis


# ========================
# === Prompt 构造部分 ===
# ========================
def build_user_prompt_external(cwe_key, cwe_info, api_batch):
    methods_str = "\n".join([
        f"{a['package_name']},{a['class_name']},{a['method_name']},{a['full_signature']}"
        for a in api_batch
    ])
    example_dict = {
        "sources": cwe_info["examples"].get("sources", []),
        "sinks": cwe_info["examples"].get("sinks", []),
        "taint_propagators": cwe_info["examples"].get("taint_propagators", [])
    }

    print(methods_str)

    return API_LABELLING_USER_PROMPT.format(
        cwe_id=cwe_info["id"],
        cwe_description=cwe_info["short_description"],
        cwe_long_description=cwe_info["long_description"],
        cwe_examples=json.dumps(example_dict, indent=2),
        methods=methods_str
    )


def build_user_prompt_internal(cwe_key, cwe_info, api_batch):
    methods_str = "\n".join([
        f"{a['package_name']},{a['class_name']},{a['method_name']},{a['full_signature']}"
        for a in api_batch
    ])

    print(methods_str)

    return FUNC_PARAM_LABELLING_USER_PROMPT.format(
        cwe_id=cwe_info["id"],
        cwe_description=cwe_info["short_description"],
        cwe_long_description=cwe_info["long_description"],
        methods=methods_str
    )


# ========================
# === 模型调用部分 ===
# ========================
def label_api_with_llm(cwe_key, cwe_info, apis, api_type):
    """使用 LLM 对 API 批量打标签"""
    results = []
    total_batches = (len(apis) + BATCH_SIZE - 1) // BATCH_SIZE

    for i in range(0, len(apis), BATCH_SIZE):
        batch = apis[i:i + BATCH_SIZE]

        log(f"🚀 Processing CWE-{cwe_info['id']} batch {i // BATCH_SIZE + 1}/{total_batches} [{api_type}]")

        user_prompt = (
            build_user_prompt_external(cwe_key, cwe_info, batch)
            if api_type == "external"
            else build_user_prompt_internal(cwe_key, cwe_info, batch)
        )

        try:
            response = client.chat.completions.create(
                model="qwen3-max",
                temperature=0,
                messages=[
                    {"role": "system",
                     "content": API_LABELLING_SYSTEM_PROMPT if api_type == "external" else FUNC_PARAM_LABELLING_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ]
            )
            content = response.choices[0].message.content.strip()
            content = content.strip().replace("```json", "").replace("```", "").strip()

            try:
                batch_result = json.loads(content)
                for r in batch_result:
                    r["CWE-id"] = cwe_info["id"]
                    r["api_type"] = api_type
                results.extend(batch_result)
            except json.JSONDecodeError:
                log("⚠️ JSON decode failed, skipped this batch.")
        except Exception as e:
            log(f"❌ Error in batch {i // BATCH_SIZE}: {e}")
            time.sleep(5)
    return results


# ========================
# === 主逻辑部分 ===
# ========================
def label_api_file(cwe_key, cwe_info, csv_path, api_type):
    """针对单个 CSV 文件执行打标签"""
    if not os.path.exists(csv_path):
        log(f"⚠️ Missing file: {csv_path}")
        return []

    apis = load_api_list(csv_path)
    if not apis:
        log(f"⚠️ Empty CSV: {csv_path}")
        return [], 0

    results = label_api_with_llm(cwe_key, cwe_info, apis, api_type)
    return results, len(apis)


def process_db(cwe_key, cwe_info, db_path, db_name):
    """处理单个数据库目录"""
    external_csv = os.path.join(db_path, f"{db_name}_external_api.csv")
    internal_csv = os.path.join(db_path, f"{db_name}_internal_func.csv")

    results = []
    total_input_count = 0
    external_results, external_count = label_api_file(cwe_key, cwe_info, external_csv, "external")
    results.extend(external_results)
    total_input_count += external_count

    internal_results, internal_count = label_api_file(cwe_key, cwe_info, internal_csv, "internal")
    results.extend(internal_results)
    total_input_count += internal_count

    # 结果文件直接保存在数据库目录下
    save_path = os.path.join(db_path, f"{db_name}_labeled.json")
    save_results(results, save_path)
    output_count = len(results)

    log(f"📊 Input total: {total_input_count} (external={external_count}, internal={internal_count})")
    log(f"📊 Output total: {output_count}")

    if output_count < total_input_count:
        diff = total_input_count - output_count
        log(f"⚠️ Mismatch detected: LLM output fewer results ({diff} missing).")
    elif output_count > total_input_count:
        log("⚠️ Warning: LLM output more results than input (possible duplication).")
    else:
        log("✅ Output count matches input count perfectly.")

    log(f"✅ Results saved to DB folder: {save_path}")


def process_project(project_path, cwe_key, cwe_info):
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
        process_db(cwe_key, cwe_info, db_path, db_name)


def save_results(results, output_path):
    """保存 JSON 结果"""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def main():
    """主入口"""
    cwe_data = load_cwe_definitions(yaml_path)

    # 根据指定 CWE ID 过滤
    filtered = {
        key: info
        for key, info in cwe_data.items()
        if str(info.get("id")) == TARGET_CWE_ID
    }

    if not filtered:
        log(f"⚠️ No CWE with id={TARGET_CWE_ID} found in {yaml_path}")
        return

    for cwe_key, cwe_info in filtered.items():
        for project in os.listdir(base_dir):
            if project.endswith("_pre"):
                project_path = os.path.join(base_dir, project)
                process_project(project_path, cwe_key, cwe_info)


if __name__ == "__main__":
    main()
