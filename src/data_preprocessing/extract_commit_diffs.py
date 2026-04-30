import os
import re
import json
import pandas as pd
from git import Repo
from tqdm import tqdm
import subprocess
from git import Repo

# ========== 用户配置部分 ==========
EXCEL_PATH = r"E:\1_my_project\dataset\commit_info\vulnerability_commit_info.xlsx"
REPO_ROOT = r"E:\1_my_project\dataset\repos"
OUTPUT_PATH = r"E:\1_my_project\dataset\commit_info\commit_info_with_diffs_all.xlsx"
# ==================================


def ensure_safe_repo(repo_path):
    """确保仓库路径被Git标记为安全"""
    abs_repo = os.path.abspath(repo_path).replace("\\", "/")
    try:
        # 注册安全目录（Git >= 2.35 需要）
        subprocess.run(
            ["git", "config", "--global", "--add", "safe.directory", abs_repo],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        print(f"[WARN] safe.directory 配置失败: {abs_repo} ({e})")


# ---------- 提取类名/方法名的辅助函数 ----------
def extract_cs_structure(code_lines):
    """通过正则从 C# 代码片段中提取类名和方法名"""
    classes, methods = set(), set()
    class_pattern = re.compile(r'\bclass\s+([A-Za-z_][A-Za-z0-9_]*)')
    # 匹配 public/private/protected/internal 修饰的函数声明
    method_pattern = re.compile(
        r'\b(public|private|protected|internal)\s+[\w<>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\('
    )
    for line in code_lines:
        c = class_pattern.search(line)
        m = method_pattern.search(line)
        if c:
            classes.add(c.group(1))
        if m:
            methods.add(m.group(2))
    return list(classes), list(methods)


# ---------- 提取单个 commit 的详细信息 ----------
def extract_commit_info(repo_path, commit_hash):
    ensure_safe_repo(repo_path)  # 在每次访问仓库前调用

    repo = Repo(repo_path)
    try:
        commit = repo.commit(commit_hash)
    except Exception as e:
        print(f"[DEBUG] Failed to find commit: {e}")
        return []

    if not commit.parents:
        print("[DEBUG] No parents found. This is likely an initial commit.")
        return []

    parent = commit.parents[0]

    # 关键调试点1：检查 diff 列表
    diffs = parent.diff(commit, create_patch=True)
    print(f"[DEBUG] Found {len(diffs)} diff(s) against first parent.")

    # 针对合并提交的额外检查
    if len(commit.parents) > 1:
        print(f"[DEBUG] This is a merge commit with {len(commit.parents)} parents.")
        # 你可以尝试 diff 其他 parent
        # diffs_other_parent = commit.parents[1].diff(commit, create_patch=True)
        # print(f"[DEBUG] Found {len(diffs_other_parent)} diff(s) against second parent.")

    if not diffs:
        print("[DEBUG] Diff list is empty. No changes detected against the first parent.")
        # 对于合并提交，可以尝试使用 git show
        try:
            # git show <hash> is more reliable for merge commits
            diff_text_raw = repo.git.show(commit_hash, format="", patch=True)
            print("[DEBUG] `git show` output is not empty. The issue is likely with parent.diff().")
        except Exception:
            print("[DEBUG] `git show` also failed or produced empty output.")
        return []

    commit_info = []

    for i, diff in enumerate(diffs):
        file_path = diff.b_path or diff.a_path
        # 关键调试点2：检查每个 diff 的文件和类型
        print(f"[DEBUG] Diff #{i}: Change type='{diff.change_type}', File='{file_path}'")

        # 无法识别 不要运行
        # if diff.change_type not in ['M', 'A', 'D']:
        #     print("[DEBUG] -> Skipping: not M, A, or D.")
        #     continue

        # 仅关注.cs文件, 之后CWE-1218要进行更换
        if not file_path or not file_path.endswith(".cs"):
            print("[DEBUG] -> Skipping: not a .cs file.")
            continue

        print("[DEBUG] -> Processing this .cs file diff.")

        diff_text = diff.diff.decode('utf-8', errors='ignore')
        added_lines, removed_lines = [], []
        added_code, removed_code = [], []

        # 解析 diff 行号信息
        for hunk in re.finditer(r"@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@", diff_text):
            old_start, old_len, new_start, new_len = map(lambda x: int(x or 1), hunk.groups())
            added_lines.append((new_start, new_start + new_len - 1))
            removed_lines.append((old_start, old_start + old_len - 1))

        # 提取新增/删除代码内容
        for line in diff_text.splitlines():
            if line.startswith('+') and not line.startswith('+++'):
                added_code.append(line[1:].strip())
            elif line.startswith('-') and not line.startswith('---'):
                removed_code.append(line[1:].strip())

        # 提取类名和方法名
        classes, methods = extract_cs_structure(added_code + removed_code)

        commit_info.append({
            "file_path": file_path,
            "change_type": diff.change_type,
            "added_lines": json.dumps(added_lines),
            "removed_lines": json.dumps(removed_lines),
            "class_names": json.dumps(classes),
            "method_names": json.dumps(methods),
            "added_code_excerpt": "\n".join(added_code[:5]),
            "removed_code_excerpt": "\n".join(removed_code[:5])
        })

    return commit_info


# ---------- 主流程 ----------
def main():
    # 读取所有 sheet
    excel = pd.ExcelFile(EXCEL_PATH)
    all_results = []

    print(f"发现 {len(excel.sheet_names)} 个工作表，将逐一处理...\n")

    for sheet_name in excel.sheet_names:
        print(f"\n📄 处理工作表：{sheet_name}")
        df = pd.read_excel(EXCEL_PATH, sheet_name=sheet_name)

        # 支持多种列名情况（index、序号等）
        if "index" in df.columns:
            idx_col = "index"
        elif "序号" in df.columns:
            idx_col = "序号"
        else:
            df.insert(0, "index", range(1, len(df) + 1))
            idx_col = "index"

        results = []

        for _, row in tqdm(df.iterrows(), total=len(df), desc=f"Processing {sheet_name}"):
            project = str(row["project"]).strip()
            commit_hash = str(row["commit_hash"]).strip()
            index_val = row[idx_col]

            repo_path = os.path.join(REPO_ROOT, project)
            if not os.path.exists(repo_path):
                print(f"[WARN] 仓库路径不存在: {repo_path}")
                results.append({
                    "index": index_val,
                    "project": project,
                    "commit_hash": commit_hash,
                    "sheet_name": sheet_name,
                    "file_path": None,
                    "change_type": None,
                    "added_lines": None,
                    "removed_lines": None,
                    "class_names": None,
                    "method_names": None,
                    "added_code_excerpt": None,
                    "removed_code_excerpt": None
                })
                continue

            try:
                commit_data = extract_commit_info(repo_path, commit_hash)
                if commit_data:
                    for entry in commit_data:
                        results.append({
                            "index": index_val,
                            "project": project,
                            "commit_hash": commit_hash,
                            "sheet_name": sheet_name,
                            **entry
                        })
                else:
                    results.append({
                        "index": index_val,
                        "project": project,
                        "commit_hash": commit_hash,
                        "sheet_name": sheet_name,
                        "file_path": None,
                        "change_type": None,
                        "added_lines": None,
                        "removed_lines": None,
                        "class_names": None,
                        "method_names": None,
                        "added_code_excerpt": None,
                        "removed_code_excerpt": None
                    })
            except Exception as e:
                print(f"[ERROR] {project} {commit_hash}: {e}")
                results.append({
                    "index": index_val,
                    "project": project,
                    "commit_hash": commit_hash,
                    "sheet_name": sheet_name,
                    "file_path": None,
                    "change_type": None,
                    "added_lines": None,
                    "removed_lines": None,
                    "class_names": None,
                    "method_names": None,
                    "added_code_excerpt": None,
                    "removed_code_excerpt": None
                })

        # 合并结果
        all_results.extend(results)

    # 输出汇总结果
    result_df = pd.DataFrame(all_results)
    result_df.to_excel(OUTPUT_PATH, index=False)
    print(f"\n✅ 所有工作表处理完成，结果已保存到: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()


# import subprocess
# from git import Repo
#
# repo_path = r"E:\1_my_project\dataset\repos\CognitiveVR_cvr-sdk-unity"
# commit = "5c0a25129dadab6d33fe7727dc6a2e41fb28275c"
#
# # cmd = ["git", "-C", repo_path, "show", commit, "--stat", "--name-only", "--oneline"]
# # print(subprocess.check_output(cmd, encoding="utf-8"))
#
# repo = Repo(repo_path)
# commit = repo.commit(commit)
# print(commit.summary)