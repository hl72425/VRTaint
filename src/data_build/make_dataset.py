import os
import json
import subprocess
import ast
import re
import csv
from datetime import datetime
import shutil
from pathlib import Path

os.environ["PYTHONIOENCODING"] = "utf-8"

# 输入和输出目录
input_dir = "./json_files"  # 存放 JSON 文件的目录
output_dir = "commit_diffs"  # 存放结果文件的目录
clone_dir = "repos"  # 存放克隆仓库的目录
os.makedirs(output_dir, exist_ok=True)
os.makedirs(clone_dir, exist_ok=True)
json_dir = "./dataset_result"


# 项目根目录，包含所有JSON文件和代码仓库
result_dir = './dataset_result'
repos_dir = './repos'
# 指定的CWE ID
target_cwe_id = 'CWE-355'


# 读取CWE-1216-project.txt文件，返回文件中列出的项目名称
def read_project_names(project_file):
    with open(project_file, "r", encoding="utf-8") as f:
        # 读取所有项目名，去除空格并去除换行符
        project_names = [line.strip() for line in f.readlines()]

    print(project_names)
    return project_names

def clone_repos_from_urltxt() -> dict:
    """
    从文本文件读取 Git 地址并批量克隆。
    包含基础容错：超时控制、失败清理、重复跳过、错误日志截断。
    """
    URL_FILE = r"E:\VR_project\dataset\new_dataset\Dataset_Repo_Git_Url.txt"
    OUTPUT_DIR = r"E:\VR_project\dataset\new_dataset"
    out_path = Path(OUTPUT_DIR)
    out_path.mkdir(parents=True, exist_ok=True)

    if not Path(URL_FILE).is_file():
        raise FileNotFoundError(f"找不到 URL 文件: {URL_FILE}")

    stats = {"success": 0, "failed": 0, "skipped": 0}

    # 读取并过滤空行/注释行
    with open(URL_FILE, "r", encoding="utf-8-sig") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    for url in urls:
        # 自动提取仓库名 (兼容 .git 后缀)
        repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
        target = out_path / repo_name

        # 跳过已完整克隆的仓库
        if target.is_dir() and (target / ".git").is_dir():
            print(f"已存在: {repo_name}")
            stats["skipped"] += 1
            continue

        print(f"克隆中: {url}")
        try:
            subprocess.run(
                ["git", "clone", url, str(target)],
                check=True,
                timeout=300,  # 5分钟超时，防大仓库卡死
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
            print(f"成功: {repo_name}")
            stats["success"] += 1

        except subprocess.TimeoutExpired:
            print(f"超时: {repo_name}")
            stats["failed"] += 1
            shutil.rmtree(target, ignore_errors=True)  # 清理残骸

        except subprocess.CalledProcessError as e:
            err = e.stderr.decode("utf-8", errors="ignore").strip()
            print(f"失败: {repo_name} | {err[:150]}")  # 截断长报错
            stats["failed"] += 1
            shutil.rmtree(target, ignore_errors=True)

        except Exception as e:
            print(f"异常: {repo_name} | {str(e)}")
            stats["failed"] += 1
            shutil.rmtree(target, ignore_errors=True)

    print(f"\n完成 -> 成功: {stats['success']} | 跳过: {stats['skipped']} | 失败: {stats['failed']}")
    return stats


def clone_repo():
    """
    克隆远程仓库到本地目录。
    """
    for filename in os.listdir(json_dir):
        if filename.endswith(".json") and "_fix" in filename:
            basename = filename[:-5]  # 去掉 .json
            repo_part = basename.split("_fix")[0]

            # 以第一个下划线分割用户名和仓库名，其余部分全部作为仓库名
            if "_" not in repo_part:
                print(f"跳过：{filename}，无法分割出 user/repo")
                continue

            first_underscore = repo_part.index("_")
            user = repo_part[:first_underscore]
            repo = repo_part[first_underscore + 1:]

            repo_url = f"https://github.com/{user}/{repo}.git"
            local_path = os.path.join(clone_dir, f"{user}_{repo}")

            if os.path.exists(local_path):
                print(f"已存在：{user}/{repo}，跳过克隆。")
            else:
                print(f"正在克隆：{repo_url}")
                try:
                    subprocess.run(["git", "clone", repo_url, local_path], check=True)
                except subprocess.CalledProcessError:
                    print(f"❌ 克隆失败：{repo_url}")


def extract_code_diff_with_context(json_file, repo_root=repos_dir, cwe_id=target_cwe_id, context_lines=3):
    """
    从 json 文件中提取特定 CWE 的代码修改，并保留修改前后上下文信息。

    参数：
        json_file (str): json 文件路径
        repo_root (str): 本地项目根目录路径
        cwe_id (str): 要提取的CWE ID
        context_lines (int): 每次提取修改时，保留修改前后上下文的行数

    返回：
        before_change (list): 修改前的代码，包括上下文
        after_change (list): 修改后的代码，包括上下文
    """
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 遍历 "final_vulnerability_commits" 找到特定CWE ID的提交
    for commit in data.get('final_vulnerability_commits', []):
        if commit.get('CWE_id') == cwe_id:
            code_diff = commit.get('code_diff', '')
            file_path = commit.get('files', [])[0]  # 获取修改的文件路径
            if code_diff and file_path:
                # 先处理换行符，替换<nl>为真实换行
                code_diff = code_diff.replace('<nl>', '\n')

                # 提取修改前后的代码段
                code_lines = code_diff.split('\n')
                modified_lines = []

                # 提取修改前后行的代码
                for line in code_lines:
                    if line.startswith('---') or line.startswith('+++'):
                        continue
                    elif line.startswith('-'):
                        modified_lines.append(('before', line[1:].strip()))  # 修改前代码
                    elif line.startswith('+'):
                        modified_lines.append(('after', line[1:].strip()))  # 修改后代码

                # 获取文件内容以进行静态分析
                file_content = read_file_from_repo(repo_root, file_path)
                if file_content:
                    # 提取修改前后的上下文
                    before_context, after_context = get_code_context_with_structure(file_content, modified_lines,
                                                                                    context_lines)
                    return before_context, after_context
    return None, None


def read_file_from_repo(repo_root, file_path):
    """
    从本地项目文件夹中读取指定文件的内容。

    参数：
        repo_root (str): 本地项目根目录路径
        file_path (str): 相对路径（相对于项目根目录）

    返回：
        str: 文件内容
    """
    full_path = os.path.join(repo_root, file_path)
    if os.path.exists(full_path):
        with open(full_path, 'r', encoding='utf-8') as file:
            return file.readlines()
    return None


def get_code_context_with_structure(file_content, modified_lines, context_lines):
    """
    获取修改前后的上下文代码，保留函数、类等结构。

    参数：
        file_content (list): 文件的所有代码行
        modified_lines (list): 存储修改行的类型和内容（修改前或修改后）
        context_lines (int): 每次提取修改时，保留修改前后上下文的行数

    返回：
        before_context (list): 修改前的上下文代码
        after_context (list): 修改后的上下文代码
    """
    before_context = []
    after_context = []

    # 获取文件中的函数和类的边界
    function_boundaries = get_function_boundaries(file_content)
    class_boundaries = get_class_boundaries(file_content)

    # 将修改的行号转换为行索引（从1开始）
    modified_line_indexes = [i for i, (change_type, _) in enumerate(modified_lines)]

    for idx in modified_line_indexes:
        # 获取修改行前后的上下文，首先需要找到它所在的函数或类
        start_idx, end_idx = get_code_block_boundaries(idx + 1, function_boundaries, class_boundaries)

        # 扩展上下文范围：根据需要的上下文行数
        start_context = max(0, start_idx - context_lines)
        end_context = min(len(file_content), end_idx + context_lines)

        # 先提取修改前上下文
        if modified_lines[idx][0] == 'before':
            before_context.extend(file_content[start_context:start_idx])  # 添加修改前上下文
            before_context.append(modified_lines[idx][1])  # 添加修改行本身

        # 提取修改后上下文
        elif modified_lines[idx][0] == 'after':
            after_context.extend(file_content[start_context:start_idx])  # 添加修改前上下文
            after_context.append(modified_lines[idx][1])  # 添加修改行本身

    return before_context, after_context


def get_code_block_boundaries(line_index, function_boundaries, class_boundaries):
    """
    获取修改行所在的函数或类的代码块范围。

    参数：
        line_index (int): 修改行的行号（从1开始）
        function_boundaries (list): 函数边界列表（每个元素是 (start_line, end_line)）
        class_boundaries (list): 类边界列表（每个元素是 (start_line, end_line)）

    返回：
        (int, int): 修改行所在的代码块的开始和结束行号
    """
    for start_line, end_line in function_boundaries:
        if start_line <= line_index <= end_line:
            return start_line, end_line

    for start_line, end_line in class_boundaries:
        if start_line <= line_index <= end_line:
            return start_line, end_line

    # 如果找不到，返回该行本身（即只包含修改行）
    return line_index, line_index


def get_function_boundaries(file_content):
    """
    获取文件中的函数定义的边界（行号）。

    参数：
        file_content (list): 文件的所有代码行

    返回：
        list: 函数边界的行号（start, end）
    """
    function_boundaries = []
    tree = ast.parse(''.join(file_content))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            start_line = node.lineno
            end_line = find_function_end(file_content, start_line)
            function_boundaries.append((start_line, end_line))
    return function_boundaries


def find_function_end(file_content, start_line):
    """
    找到函数的结束行。

    参数：
        file_content (list): 文件的所有代码行
        start_line (int): 函数的开始行号

    返回：
        int: 函数的结束行号
    """
    indent_level = len(file_content[start_line - 1]) - len(file_content[start_line - 1].lstrip())
    for i in range(start_line, len(file_content)):
        if len(file_content[i]) - len(file_content[i].lstrip()) <= indent_level:
            return i
    return len(file_content)  # 默认返回文件末尾


def get_class_boundaries(file_content):
    """
    获取文件中的类定义的边界（行号）。

    参数：
        file_content (list): 文件的所有代码行

    Returns:
        list: 类边界的行号（start, end）
    """
    class_boundaries = []
    for i, line in enumerate(file_content):
        if line.strip().startswith('class '):
            start_line = i + 1
            end_line = find_class_end(file_content, start_line)
            class_boundaries.append((start_line, end_line))
    return class_boundaries


def find_class_end(file_content, start_line):
    """
    找到类的结束行。

    参数：
        file_content (list): 文件的所有代码行
        start_line (int): 类的开始行号

    返回：
        int: 类的结束行号
    """
    indent_level = len(file_content[start_line - 1]) - len(file_content[start_line - 1].lstrip())
    for i in range(start_line, len(file_content)):
        if len(file_content[i]) - len(file_content[i].lstrip()) <= indent_level:
            return i
    return len(file_content)  # 默认返回文件末尾


# 保存提取的数据为 JSON 格式
def save_code_diff_to_json(project_name, commit_hash, cwe_id, file_path, before_code, after_code):
    output = {
        "project": project_name,
        "commit_hash": commit_hash,
        "cwe_id": cwe_id,
        "file_path": file_path,
        "before": "\n".join(before_code),
        "after": "\n".join(after_code)
    }

    output_filename = f"{project_name}_{commit_hash[:7]}_cwe_{cwe_id}.json"
    output_path = os.path.join('./output', output_filename)

    with open(output_path, 'w', encoding='utf-8') as json_file:
        json.dump(output, json_file, ensure_ascii=False, indent=4)

    print(f"Saved to {output_path}")


# 查找对应项目目录并提取代码
def get_project_code_diff():
    if not os.path.exists('./output'):
        os.makedirs('./output')

    for json_file in os.listdir(result_dir):
        if json_file.endswith('.json'):
            project_name = json_file.split('_fix.json')[0]  # 提取项目名
            json_file_path = os.path.join(result_dir, json_file)

            print(json_file_path)
            before_code, after_code = extract_code_diff_with_context(json_file_path)
            if before_code and after_code:
                # 找到对应项目，提取代码
                repo_path = os.path.join(repos_dir, project_name)
                if os.path.exists(repo_path):
                    # 获取commit hash
                    with open(json_file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    commit_hash = data['final_vulnerability_commits'][0]['hash']

                    # 假设文件路径为commit中提到的文件
                    file_path = "README.md"  # 可根据实际情况调整

                    # 保存结果为JSON文件
                    save_code_diff_to_json(project_name, commit_hash, target_cwe_id, file_path, before_code, after_code)
                else:
                    print(f"Repository for project '{project_name}' not found.")
            else:
                print(f"No relevant changes found for CWE-ID: {target_cwe_id} in {json_file}")


def extract_commit_info_to_csv():
    """
    从JSON文件中提取所有commit信息并保存到CSV文件
    每个JSON文件可能包含多个commit，每个commit有CWE_id、hash和message等信息
    """
    # 准备CSV文件路径和表头
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = os.path.join(output_dir, f'commit_info_{timestamp}.csv')

    fieldnames = [
        'project',
        'CWE_id',
        'commit_hash',
        'commit_message',
        'commit_date',
        'files_changed',
        'code_diff_summary'
    ]

    with open(csv_file, 'w', encoding='utf-8', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # 遍历所有JSON文件
        for json_file in os.listdir(result_dir):
            if not json_file.endswith('.json'):
                continue

            project_name = os.path.splitext(json_file)[0].replace('_fix', '')
            json_file_path = os.path.join(result_dir, json_file)

            try:
                with open(json_file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                    # 检查是否有final_vulnerability_commits字段
                    if 'final_vulnerability_commits' not in data:
                        print(f"文件 {json_file} 中没有 final_vulnerability_commits 字段")
                        continue

                    # 处理每个commit
                    for commit in data['final_vulnerability_commits']:
                        # 准备行数据
                        row = {
                            'project': project_name,
                            'CWE_id': commit.get('CWE_id', ''),
                            'commit_hash': commit.get('hash', ''),
                            'commit_message': safe_str_join(commit.get('message', ''), ' '),
                            'commit_date': commit.get('commit_date', ''),
                            'files_changed': safe_str_join(commit.get('files', ''), ' '),
                            'code_diff_summary': summarize_code_diff(commit.get('code_diff', ''))
                        }

                        # 写入CSV
                        writer.writerow(row)

            except json.JSONDecodeError as e:
                print(f"JSON解析错误 {json_file}: {str(e)}")
            except Exception as e:
                print(f"处理 {json_file} 时出错: {str(e)}")

    print(f"Commit信息已保存到: {csv_file}")
    print(f"共处理了 {count_json_files(result_dir)} 个JSON文件")


def safe_str_join(items, delimiter):
    """
    安全地将项目连接成字符串，处理None和非可迭代对象
    """
    if items is None:
        return ""
    if not isinstance(items, (list, tuple, set)):
        return str(items)
    return delimiter.join(str(item) for item in items if item is not None)



def summarize_code_diff(code_diff):
    """
    对代码差异进行简要总结
    """
    if not code_diff:
        return ""

    # 替换换行符
    code_diff = code_diff.replace('<nl>', '\n')

    # 计算修改的行数
    lines = code_diff.split('\n')
    added = sum(1 for line in lines if line.startswith('+') and not line.startswith('+++'))
    removed = sum(1 for line in lines if line.startswith('-') and not line.startswith('---'))

    summary = f"added: {added}, removed:{removed}."
    return summary[:200]  # 限制长度


def count_json_files(directory):
    """
    计算目录中的JSON文件数量
    """
    return sum(1 for f in os.listdir(directory) if f.endswith('.json'))


if __name__ == "__main__":
    # extract_commit_info_to_csv()
    # clone_repo()
    # get_project_code_diff()
    clone_repos_from_urltxt()
