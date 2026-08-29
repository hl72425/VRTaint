import os
import csv
from pathlib import Path

# Anchor: this file lives under <dataset>/src/data_build/, parents[2] is the dataset root
ROOT = Path(__file__).resolve().parents[2]

def identify_project_type(project_path):
    try:
        entries = set(os.listdir(project_path))
        lower_entries = [e.lower() for e in entries]

        # Unity main structure
        if "assets" in lower_entries and "projectsettings" in lower_entries:
            return "Unity(C#)"

        # Unreal
        if any(e.endswith(".uproject") for e in entries):
            return "Unreal(C++)"
        if "source" in lower_entries:
            src_path = os.path.join(project_path, "Source")
            if os.path.isdir(src_path) and any(f.endswith((".cpp", ".h")) for f in os.listdir(src_path)):
                return "Unreal(C++)"

        # WebXR / Three.js
        if "index.html" in lower_entries:
            index_file = os.path.join(project_path, "index.html")
            try:
                with open(index_file, "r", encoding="utf-8") as f:
                    content = f.read().lower()
                    if "three.js" in content or "webxr" in content or "aframe" in content:
                        return "WebXR/Three.js"
            except Exception as e:
                print(f"  [!] Error reading {index_file}: {e}")

        # Native VR SDKs (e.g., OpenXR, Oculus)
        if "cmakelists.txt" in lower_entries:
            cmake_file = os.path.join(project_path, "CMakeLists.txt")
            try:
                with open(cmake_file, "r", encoding="utf-8") as f:
                    content = f.read().lower()
                    if "openxr" in content or "ovr_" in content or "xr_runtime" in content:
                        return "NativeVR(C++)"
            except Exception as e:
                print(f"  [!] Error reading {cmake_file}: {e}")

        # Unity plugins / VR tooling
        if any(e.endswith(".sln") for e in entries):
            has_csproj = any(f.endswith(".csproj") for f in entries)
            has_cs = any(f.endswith(".cs") for root, _, files in os.walk(project_path) for f in files)
            has_vr_term = any("vrchat" in e.lower() or "xr" in e.lower() for e in entries)
            if has_csproj and has_cs:
                return "Unity Plugin(C#)" if has_vr_term else "C# Project(VR Related)"

    except Exception as e:
        print(f"[!] Failed to identify project {project_path}: {e}")

    return "Unknown"

def scan_projects(root_dir, output_csv="vr_project_types.csv"):
    results = []

    print(f"🔍 Scanning projects under: {root_dir}\n")

    for entry in os.listdir(root_dir):
        full_path = os.path.join(root_dir, entry)
        if not os.path.isdir(full_path):
            continue

        print(f"➡️  Processing: {entry}")
        project_type = identify_project_type(full_path)
        print(f"    ➤ Detected Type: {project_type}")

        results.append({
            "Project Name": entry,
            "Path": full_path,
            "Type": project_type
        })

    # Save the results as a CSV
    output_path = os.path.join(root_dir, output_csv)
    with open(output_path, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Project Name", "Path", "Type"])
        writer.writeheader()
        writer.writerows(results)

    print(f"\n✅ Done. Results saved to: {output_path}")

if __name__ == "__main__":
  
    directory = os.environ.get("VRTRAINT_REPOS_ROOT") or str(ROOT / "repos")
    output = "vr_project_types.csv"

    scan_projects(directory, output)