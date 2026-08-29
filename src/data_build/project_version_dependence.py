import os
import csv
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

# Anchor: this file lives under <dataset>/src/data_build/, parents[2] is the dataset root
ROOT = Path(__file__).resolve().parents[2]


def run_cmd(cmd):
    """Run a command (as a list or string) and return its first output line."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=10)
        return result.stdout.strip().splitlines()[0] if result.stdout else "Unknown"
    except Exception:
        return "Unknown"


def detect_host_env():
    """Detect the host environment versions"""
    dotnet_ver = run_cmd("dotnet --version")
    msbuild_ver = run_cmd("msbuild -version")
    # Common Unity Hub paths (Windows); can be overridden via the UNITY_EDITOR_PATHS environment variable (semicolon-separated)
    default_paths = (
        r"C:\Program Files\Unity\Hub\Editor\2020.3.48f1\Editor\Unity.exe;"
        r"C:\Program Files\Unity\Hub\Editor\2019.4.40f1\Editor\Unity.exe"
    )
    unity_paths = [p for p in (os.environ.get("UNITY_EDITOR_PATHS") or default_paths).split(";") if p]
    unity_ver = "Unknown"
    for path in unity_paths:
        if os.path.exists(path):
            unity_ver = run_cmd([path, "-version"])
            break
    return dotnet_ver, msbuild_ver, unity_ver


def parse_csproj(csproj_path):
    """Parse a .csproj file"""
    build_method = "unknown"
    target_framework = ""
    note = ""
    try:
        tree = ET.parse(csproj_path)
        root = tree.getroot()
        # SDK-style project
        if "Sdk" in root.attrib:
            build_method = "dotnet"
            tf = root.find("PropertyGroup/TargetFramework")
            if tf is not None:
                target_framework = tf.text
        # Legacy .NET Framework
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
    """Detect the Unity project version"""
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

    # Detect the host environment
    dotnet_ver, msbuild_ver, unity_ver = detect_host_env()

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Unity project
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

        # .csproj project
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

    # Export the CSV
    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["project_path", "project_type", "build_method", "target_framework", "unity_version",
                      "note", "host_dotnet_version", "host_msbuild_version", "host_unity_version"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Scan finished; identified {len(results)} projects in total, results exported to {output_csv}")


if __name__ == "__main__":
    # Change to your Unity VR project collection path (default <dataset>/repos; can be overridden with VRTRAINT_REPOS_ROOT)
    root_dir = os.environ.get("VRTRAINT_REPOS_ROOT") or str(ROOT / "repos")
    scan_projects(root_dir, "project_version.csv")
