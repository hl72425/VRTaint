import os
from typing import List, Optional

root_dir = "E:\\1_my_project\\dataset\\vulnerability_dataset\\CWE-465\\Null Pointer"

def print_directory_tree(
        root_path: str = ".",
        max_depth: int = 2,
        show_files: bool = True,
        show_hidden: bool = False,
        exclude_dirs: Optional[List[str]] = None,
        exclude_files: Optional[List[str]] = None,
        indent_size: int = 4
) -> None:
    """
    打印美观的目录树形结构

    参数:
        root_path (str): 要显示的根目录路径，默认为当前目录
        max_depth (int): 最大显示深度（0=只显示根目录名称）
        show_files (bool): 是否显示文件（默认True）
        show_hidden (bool): 是否显示隐藏文件/目录（默认False）
        exclude_dirs (List[str]): 要排除的目录名列表
        exclude_files (List[str]): 要排除的文件名列表
        indent_size (int): 缩进空格数（默认4）
    """
    # 初始化排除列表
    exclude_dirs = exclude_dirs or []
    exclude_files = exclude_files or []

    # 标准化路径
    root_path = os.path.abspath(root_path)
    base_name = os.path.basename(root_path)

    # 树形符号定义
    TREE_STRUCTURE = {
        'branch': '│',
        'tee': '├',
        'last': '└',
        'dash': '─',
        'space': ' '
    }

    def _print_node(
            current_path: str,
            current_depth: int,
            prefix: str,
            is_last: bool = False
    ) -> None:
        """递归打印目录节点"""
        if current_depth > max_depth:
            return

        # 获取当前节点名称
        node_name = os.path.basename(current_path)

        # 打印当前节点
        print(f"{prefix}{node_name}")

        if current_depth == max_depth:
            return

        try:
            # 获取目录内容并排序
            entries = sorted(os.listdir(current_path))
        except PermissionError:
            return

        # 过滤内容
        filtered_entries = []
        for entry in entries:
            entry_path = os.path.join(current_path, entry)

            # 跳过隐藏文件/目录（除非show_hidden为True）
            if not show_hidden and entry.startswith('.'):
                continue

            # 跳过排除项
            if os.path.isdir(entry_path):
                if entry in exclude_dirs:
                    continue
            elif not show_files or entry in exclude_files:
                continue

            filtered_entries.append(entry)

        entries_count = len(filtered_entries)

        for i, entry in enumerate(filtered_entries):
            entry_path = os.path.join(current_path, entry)
            entry_is_last = i == entries_count - 1

            # 构建新的前缀
            if is_last:
                new_prefix = prefix + TREE_STRUCTURE['space'] * indent_size
            else:
                new_prefix = prefix + TREE_STRUCTURE['branch'] + TREE_STRUCTURE['space'] * (indent_size - 1)

            # 构建连接线
            connector = TREE_STRUCTURE['last'] if entry_is_last else TREE_STRUCTURE['tee']
            connector += TREE_STRUCTURE['dash'] * 2 + ' '

            # 打印连接线
            print(f"{prefix}{connector}", end="")

            # 递归处理子目录或打印文件名
            if os.path.isdir(entry_path):
                _print_node(entry_path, current_depth + 1, new_prefix, entry_is_last)
            else:
                print(entry)

    # 打印根目录
    print(base_name)

    # 开始递归打印
    _print_node(root_path, 0, "", True)


# 使用示例
if __name__ == "__main__":
    # 示例1：打印当前目录的2层结构（包含文件）
    print("\n示例1：当前目录的2层结构（含文件）")
    print_directory_tree(root_path=root_dir, max_depth=2)

    # # 示例2：打印指定目录的1层结构（仅目录）
    # print("\n示例2：指定目录的1层结构（仅目录）")
    # print_directory_tree(
    #     root_path="..",
    #     max_depth=1,
    #     show_files=False
    # )
    #
    # # 示例3：打印3层结构，排除特定目录和文件
    # print("\n示例3：3层结构，排除特定内容")
    # print_directory_tree(
    #     max_depth=3,
    #     exclude_dirs=["__pycache__", ".git"],
    #     exclude_files=["*.tmp", "temp.*"],
    #     indent_size=2
    # )