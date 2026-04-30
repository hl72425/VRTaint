import os
import shutil
import subprocess
import pandas as pd

# 参数配置
excel_path = "E:/1_my_project/dataset/commit_info/vulnerability_commit_info.xlsx"
base_repo_dir = "E:/1_my_project/dataset/repos"
output_dir = "E:/1_my_project/dataset/vulnerability_dataset"


def safe_copytree(src, dst, ignore_patterns=None):
    """安全拷贝目录，允许忽略特定模式"""
    ignore = shutil.ignore_patterns(*ignore_patterns) if ignore_patterns else None
    for root, dirs, files in os.walk(src):
        rel_path = os.path.relpath(root, src)
        dest_dir = os.path.join(dst, rel_path)
        os.makedirs(dest_dir, exist_ok=True)

        # 忽略规则
        if ignore:
            ignored = ignore(root, files + dirs)
            files = [f for f in files if f not in ignored]
            dirs[:] = [d for d in dirs if d not in ignored]

        for file in files:
            src_file = os.path.join(root, file)
            dst_file = os.path.join(dest_dir, file)
            try:
                shutil.copy2(src_file, dst_file)
            except FileNotFoundError:
                print(f"⚠️ 文件不存在，跳过: {src_file}")
            except Exception as e:
                print(f"⚠️ 无法复制文件 {src_file} -> {dst_file}：{e}")


def process_commits(sheet_name, type_filter):
    """
    从 Excel 指定工作表，读取符合 '类型' 列值的 commit，执行 checkout + 拷贝
    """
    df = pd.read_excel(excel_path, sheet_name=sheet_name)

    if "类型" not in df.columns:
        raise ValueError(f"工作表 {sheet_name} 缺少 '类型' 列")

    # 过滤出指定类型
    df_filtered = df[df["类型"] == type_filter]

    if df_filtered.empty:
        print(f"❌ 没有找到符合类型 {type_filter} 的记录 (sheet={sheet_name})")
        return

    for idx, row in df_filtered.iterrows():
        project = row['project']
        commit = row['commit_hash']

        repo_path = os.path.join(base_repo_dir, project).replace("\\", "/")
        print(f"\n🔍 处理项目：{project}, commit: {commit}")
        print(f"📁 仓库路径：{repo_path}")

        # 构建嵌套输出路径
        nested_dir = os.path.join(output_dir, sheet_name, type_filter)
        os.makedirs(nested_dir, exist_ok=True)

        # 输出路径
        dst_path = os.path.join(nested_dir, f"{project}_{commit}_pre")

        # 如果存在则跳过
        if os.path.exists(dst_path):
            print(f"⏭️ 跳过已存在的输出目录：{dst_path}")
            continue

        # 如果存在则覆盖
        # if os.path.exists(dst_path):
        #     shutil.rmtree(dst_path)

        # 添加安全目录
        subprocess.run(["git", "config", "--global", "--add", "safe.directory", repo_path])

        if not os.path.exists(repo_path):
            print(f"❌ 未找到本地仓库：{repo_path}")
            continue

        try:
            # 获取父版本
            subprocess.run(["git", "checkout", f"{commit}^"], cwd=repo_path, check=True)

            print(f"📦 正在复制到：{dst_path}")
            safe_copytree(repo_path, dst_path, ignore_patterns=[".git", "Library", "Temp", "Build"])

            print(f"✅ 保存成功：{dst_path}")

        except subprocess.CalledProcessError:
            print(f"⚠️ Git 操作失败：{project} @ {commit}")


if __name__ == "__main__":
    process_commits(sheet_name="CWE-465", type_filter="空指针")
