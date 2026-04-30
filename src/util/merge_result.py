import csv
import os

# === 配置区 ===
# 索引文件路径（你刚生成的那个文件）
index_csv_path = r"E:\VR_project\dataset\results\unity-vr-sensitive-apis_query_v1_20260429_2013.csv"
# 合并后的保存路径
final_output_path = r"E:\VR_project\dataset\results\FINAL_ALL_PROJECTS_MERGED.csv"

def merge_by_index():
    merged_data = []
    header = []
    processed_count = 0

    print(f"🚀 开始读取索引文件: {index_csv_path}")

    with open(index_csv_path, 'r', encoding='utf-8') as index_f:
        # 自动识别列名，避免索引偏移问题
        reader = csv.DictReader(index_f)
        
        for row in reader:
            file_path = row.get('ResultFile')
            if not file_path or not os.path.exists(file_path):
                print(f"⚠️ 跳过无效路径: {file_path}")
                continue

            # --- 提取项目标识 (从路径中提取) ---
            # 逻辑：取 'codeql-db_' 文件夹所在的上一级目录名作为项目名
            normalized_path = file_path.replace('\\', '/')
            parts = normalized_path.split('/')
            project_name = "Unknown"
            for i, part in enumerate(parts):
                if "codeql-db_" in part and i > 0:
                    project_name = parts[i-1]
                    break

            # --- 读取子文件内容 ---
            try:
                with open(file_path, 'r', encoding='utf-8') as sub_f:
                    sub_reader = csv.reader(sub_f)
                    sub_header = next(sub_reader, None)

                    # 如果是第一个处理的文件，确定总表头
                    if not header and sub_header:
                        header = ["Project_ID"] + sub_header
                    
                    # 抓取数据行
                    for sub_row in sub_reader:
                        if sub_row:
                            merged_data.append([project_name] + sub_row)
                    
                    processed_count += 1
                    print(f"✅ 已合并 ({processed_count}): {project_name}")

            except Exception as e:
                print(f"❌ 读取子文件出错 {file_path}: {e}")

    # === 写入最终结果 ===
    if merged_data:
        print(f"💾 正在写入总表到: {final_output_path}")
        with open(final_output_path, 'w', newline='', encoding='utf-8') as out_f:
            writer = csv.writer(out_f)
            writer.writerow(header)
            writer.writerows(merged_data)
        print(f"✨ 合并成功！总计处理 {processed_count} 个项目，共 {len(merged_data)} 条数据。")
    else:
        print("Empty: 没有提取到任何有效数据。")

if __name__ == "__main__":
    merge_by_index()