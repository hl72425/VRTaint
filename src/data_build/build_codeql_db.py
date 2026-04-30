import os
import subprocess
import shutil

# === 配置区 ===
# 根目录：存放 git 拉取的父提交项目的目录
base_dir = r"E:/1_my_project/dataset/vulnerability_dataset/CWE-465/Null Pointer/"
unity_managed_dir = r"C:/Program Files/Unity/Hub/Editor/2018.1.0f2/Editor/Data/Managed"


def build_codeql_db(project_path):
    """为一个 Unity 项目构建 CodeQL 数据库 (--build-mode=none)"""
    db_path = os.path.join(project_path, "codeql-db")

    # # 如果数据库已存在，跳过
    # if os.path.exists(db_path):
    #     print(f"⚠️ 已存在 CodeQL 数据库，跳过: {db_path}")
    #     return

    # 如果数据库已存在，先删除再继续
    if os.path.exists(db_path):
        print(f"⚠️ 已存在 CodeQL 数据库，删除旧的: {db_path}")
        shutil.rmtree(db_path)

    # 构建命令
    cmd = [
        "codeql", "database", "create", db_path,
        "--language=csharp",
        "--build-mode=none",   # ⚠️ 关键参数
        f"--source-root={project_path}"
    ]

    print(f"🚀 开始构建 CodeQL 数据库: {project_path}")

    # 设置环境变量，告诉 CodeQL 去哪里找 Unity 的 DLL
    env = os.environ.copy()
    env["DOTNET_REFERENCE_ASSEMBLIES_PATH"] = unity_managed_dir

    try:
        subprocess.run(cmd, check=True, env=env)
        print(f"✅ 构建完成: {db_path}")
    except subprocess.CalledProcessError as e:
        print(f"❌ 构建失败: {project_path}, 错误: {e}")


def batch_build(base_dir):
    """递归遍历所有子目录，识别 *_pre 项目并构建 CodeQL"""
    for root, dirs, files in os.walk(base_dir):
        for d in dirs:
            if d.endswith("_pre"):  # 只处理 *_pre 的项目目录
                project_path = os.path.join(root, d)
                build_codeql_db(project_path)


if __name__ == "__main__":
    batch_build(base_dir)
