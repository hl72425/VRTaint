from pydriller import Repository
import os
import json

# 配置部分
REPO_PATH = "./repos/EditorXR"  # 本地 Git 仓库路径
OUTPUT_FILE = "./vulnerability_commits.json"  # 输出文件名
KEYWORDS = ["CWE-1021", "CWE-1007", "CWE-549", "CWE-449", "CWE-448", "CWE-447", "CWE-357", "CWE",
            "Product UI does not Warn User of Unsafe Actions",
            "Insufficient UI Warning of Dangerous Operations",
            "Unimplemented or Unsupported Feature in UI",
            "Obsolete Feature in UI",
            "The UI Performs the Wrong Action",
            "Missing Password Field Masking"
            ]  # 搜索关键词


def extract_vulnerability_commits(repo_path, keywords, output_file):
    """提取包含特定关键词的提交及其代码差异"""
    results = []

    for commit in Repository(repo_path).traverse_commits():
        # 检查提交消息是否包含关键词
        if any(keyword in commit.msg.lower() for keyword in keywords):
            print(f"Processing commit: {commit.hash}")
            for modified_file in commit.modified_files:
                # 提取修改前和修改后的代码
                diff = modified_file.diff  # 整体差异
                old_code = modified_file.source_code_before
                new_code = modified_file.source_code
                file_path = modified_file.new_path or modified_file.old_path

                # 保存结果
                results.append({
                    "commit_hash": commit.hash,
                    "author": commit.author.name,
                    "date": commit.author_date.strftime("%Y-%m-%d %H:%M:%S"),
                    "file_path": file_path,
                    "diff": diff,
                    "old_code": old_code,
                    "new_code": new_code,
                    "message": commit.msg.strip(),
                })

    # 保存结果到 JSON 文件
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"Extraction complete. Results saved to {output_file}")


if __name__ == "__main__":
    # 检查仓库路径是否存在
    if not os.path.exists(REPO_PATH):
        print(f"Error: Repository path '{REPO_PATH}' does not exist.")
    else:
        extract_vulnerability_commits(REPO_PATH, KEYWORDS, OUTPUT_FILE)
