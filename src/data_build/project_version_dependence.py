import os
import csv
import subprocess
import xml.etree.ElementTree as ET


def run_cmd(cmd):
    """执行命令并返回输出"""
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, timeout=10)
        return result.stdout.strip().splitlines()[0] if result.stdout else "Unknown"
    except Exception:
        return "Unknown"


def detect_host_env():
    """检测主机环境版本"""
    dotnet_ver = run_cmd("dotnet --version")
    msbuild_ver = run_cmd("msbuild -version")
    # 常见 Unity Hub 路径（Windows），你也可以手动配置
    unity_paths = [
        r"C:\Program Files\Unity\Hub\Editor\2020.3.48f1\Editor\Unity.exe",
        r"C:\Program Files\Unity\Hub\Editor\2019.4.40f1\Editor\Unity.exe",
    ]
    unity_ver = "Unknown"
    for path in unity_paths:
        if os.path.exists(path):
            unity_ver = run_cmd(f"\"{path}\" -version")
            break
    return dotnet_ver, msbuild_ver, unity_ver


def parse_csproj(csproj_path):
    """解析 .csproj 文件"""
    build_method = "unknown"
    target_framework = ""
    note = ""
    try:
        tree = ET.parse(csproj_path)
        root = tree.getroot()
        # SDK 风格
        if "Sdk" in root.attrib:
            build_method = "dotnet"
            tf = root.find("PropertyGroup/TargetFramework")
            if tf is not None:
                target_framework = tf.text
        # 老式 .NET Framework
        if build_method == "unknown":
            for prop in root.findall("PropertyGroup"):
                tfv = prop.find("TargetFrameworkVersion")
                if tfv is not None:
                    build_method = "msbuild"
                    target_framework = tfv.text
                    break
    except Exception as e:
        note = f"CsprojParseError:{e}"
    return build_method, target_framework, note


def detect_unity_version(project_path):
    """检测 Unity 项目版本"""
    version_file = os.path.join(project_path, "ProjectSettings", "ProjectVersion.txt")
    if os.path.exists(version_file):
        try:
            with open(version_file, "r", encoding="utf-8") as f:
                for line in f:
                    if "m_EditorVersion:" in line:
                        return line.split(":", 1)[1].strip()
        except Exception:
            return "Unknown"
    return ""


def scan_projects(root_dir, output_csv="results.csv"):
    results = []
    visited = set()

    # 检测主机环境
    dotnet_ver, msbuild_ver, unity_ver = detect_host_env()

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Unity 项目
        if ("Assets" in dirnames and "ProjectSettings" in dirnames):
            if dirpath not in visited:
                unity_version = detect_unity_version(dirpath)
                results.append({
                    "project_path": dirpath,
                    "project_type": "unity",
                    "build_method": "unity",
                    "target_framework": "",
                    "unity_version": unity_version,
                    "note": "",
                    "host_dotnet_version": dotnet_ver,
                    "host_msbuild_version": msbuild_ver,
                    "host_unity_version": unity_ver
                })
                visited.add(dirpath)

        # .csproj 项目
        for f in filenames:
            if f.endswith(".csproj"):
                csproj_path = os.path.join(dirpath, f)
                if csproj_path not in visited:
                    build_method, tf, note = parse_csproj(csproj_path)
                    results.append({
                        "project_path": csproj_path,
                        "project_type": "dotnet_project",
                        "build_method": build_method,
                        "target_framework": tf,
                        "unity_version": "",
                        "note": note,
                        "host_dotnet_version": dotnet_ver,
                        "host_msbuild_version": msbuild_ver,
                        "host_unity_version": unity_ver
                    })
                    visited.add(csproj_path)

    # 导出 CSV
    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["project_path", "project_type", "build_method", "target_framework", "unity_version",
                      "note", "host_dotnet_version", "host_msbuild_version", "host_unity_version"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"扫描完成，共识别 {len(results)} 个项目，结果已导出到 {output_csv}")


if __name__ == "__main__":
    # 修改为你的 Unity VR 项目集合路径
    root_dir = r"E:\1_my_project\dataset\repos"
    scan_projects(root_dir, "project_version.csv")
