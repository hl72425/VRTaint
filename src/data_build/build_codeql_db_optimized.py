import os
import subprocess
import shutil
import concurrent.futures
from datetime import datetime
import re

# === 配置 ===
BASE_DIR = r"E:/1_my_project/dataset/vulnerability_dataset/CWE-465/Null Pointer/"
UNITY_MANAGED_DIR = r"C:/Program Files/Unity/Hub/Editor/2018.1.0f2/Editor/Data/Managed"
MAX_WORKERS = 3  # 并行线程数
MIN_CS_FILES = 1  # 至少有多少个C#文件才认定为有效代码目录


def get_next_db_version(project_path):
    """获取下一个版本号"""
    existing_dbs = [d for d in os.listdir(project_path)
                    if d.startswith("codeql-db_v") and os.path.isdir(os.path.join(project_path, d))]

    if not existing_dbs:
        return "v1"
    
    # 提取现有版本号
    versions = []
    for db in existing_dbs:
        match = re.search(r'v(\d+)', db)
        if match:
            versions.append(int(match.group(1)))

    next_version = max(versions) + 1 if versions else 1
    return f"v{next_version}"


# ======== 1. 动态识别代码目录 ========
def find_code_dirs(project_path):
    """
    自动识别该 Unity 项目下的主要代码目录。
    """
    code_dirs = []
    for root, dirs, files in os.walk(project_path):
        cs_files = [f for f in files if f.endswith(".cs")]
        if len(cs_files) >= MIN_CS_FILES:
            code_dirs.append(root)

    # 去重并过滤非核心目录
    filtered = [d for d in code_dirs if not any(x in d for x in ["Library", "Temp", "Build", "Tests", ".git", "Logs"])]
    return filtered


# ======== 2. 构建 CodeQL 数据库 ========
def build_codeql_db(project_path):
    version = get_next_db_version(project_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    db_path = os.path.join(project_path, f"codeql-db_{version}_{timestamp}")

    if os.path.exists(db_path):
        print(f"⚠️ 删除旧数据库: {db_path}")
        shutil.rmtree(db_path, ignore_errors=True)

    # 识别代码密集目录
    code_dirs = find_code_dirs(project_path)
    if not code_dirs:
        print(f"⏭️ 跳过: {project_path}（未检测到足够C#代码）")
        return

    # 临时将代码复制到一个轻量目录构建（加速构建）
    light_root = os.path.join(project_path, "_code_subset")
    if os.path.exists(light_root):
        shutil.rmtree(light_root, ignore_errors=True)
    os.makedirs(light_root, exist_ok=True)

    for d in code_dirs:
        rel = os.path.relpath(d, project_path)
        dest = os.path.join(light_root, rel)
        os.makedirs(dest, exist_ok=True)
        for f in os.listdir(d):
            if f.endswith(".cs"):
                shutil.copy(os.path.join(d, f), dest)

    print(f"🚀 构建轻量数据库: {project_path}，共 {len(code_dirs)} 个代码目录")

    cmd = [
        "codeql", "database", "create", db_path,
        "--language=csharp",
        "--build-mode=none",
        f"--source-root={light_root}",
        "--threads=4",
    ]

    env = os.environ.copy()
    env["DOTNET_REFERENCE_ASSEMBLIES_PATH"] = UNITY_MANAGED_DIR

    try:
        subprocess.run(cmd, check=True, env=env)
        print(f"✅ 成功构建数据库: {db_path}")
    except subprocess.CalledProcessError as e:
        print(f"❌ 构建失败: {project_path}\n错误: {e}")
    finally:
        shutil.rmtree(light_root, ignore_errors=True)


# ======== 3. 批量处理 ========
def batch_build(base_dir):
    projects = []
    for root, dirs, _ in os.walk(base_dir):
        for d in dirs:
            if d.endswith("_pre"):
                projects.append(os.path.join(root, d))

    print(f"🧩 共检测到 {len(projects)} 个项目，开始构建...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        list(executor.map(build_codeql_db, projects))


if __name__ == "__main__":
    batch_build(BASE_DIR)
