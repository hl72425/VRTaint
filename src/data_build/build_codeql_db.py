import os
import subprocess
import csv
import datetime
import time
from pathlib import Path

# Anchor: this file lives under <dataset>/src/data_build/, parents[2] is the dataset root
ROOT = Path(__file__).resolve().parents[2]


# ====== Auto encoding detection (built-in only, no chardet dependency) ======
def detect_encoding(file_path):
    """Try common encodings and return the first one that decodes correctly."""
    encodings = ['utf-8-sig', 'utf-8', 'gbk', 'gb2312', 'gb18030', 'latin-1']
    with open(file_path, 'rb') as f:
        raw = f.read()
    for enc in encodings:
        try:
            raw.decode(enc)
            return enc
        except (UnicodeDecodeError, LookupError):
            continue
    return 'utf-8'


def auto_open(file_path, mode='r', **kwargs):
    """Open a file with the detected encoding."""
    if 'b' in mode:
        return open(file_path, mode, **kwargs)
    enc = detect_encoding(file_path)
    return open(file_path, mode, encoding=enc, **kwargs)


def read_csv_auto(file_path):
    """Read a CSV with auto-detected encoding; return (rows, fieldnames)."""
    enc = detect_encoding(file_path)
    with open(file_path, 'r', encoding=enc, newline='') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        return rows, reader.fieldnames


# ====== Configuration ======
# Index CSV produced by the dataset-download stage (name/path columns)
CSV_INDEX_FILE = str(ROOT / "new5_dataset" / "download_status.csv")
BASE_OUT_DIR = str(ROOT / "new5_codeql_database")
NONE_MODE_DIR = os.path.join(BASE_OUT_DIR, "none-mode")
AUTO_MODE_DIR = os.path.join(BASE_OUT_DIR, "auto-mode")
TIMEOUT_SECONDS = 1800


def get_report_path():
    """Reuse the most recent build report if present, otherwise create a new one."""
    existing = []
    if os.path.exists(BASE_OUT_DIR):
        for f in os.listdir(BASE_OUT_DIR):
            if f.startswith("build_report_") and f.endswith(".csv"):
                existing.append(os.path.join(BASE_OUT_DIR, f))
    if existing:
        return max(existing, key=os.path.getmtime)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(BASE_OUT_DIR, f"build_report_{ts}.csv")


def load_completed(report_csv):
    """Return the set of projects already built successfully (for resume)."""
    done = set()
    if os.path.exists(report_csv):
        with auto_open(report_csv, 'r') as f:
            for row in csv.DictReader(f):
                if row.get('Status', '').strip().lower() == 'ok':
                    done.add(row['Project'].strip())
    return done


def setup_dirs():
    """Create output directories; return (none_mode_dir, auto_mode_dir) absolute paths."""
    for d in [BASE_OUT_DIR, NONE_MODE_DIR, AUTO_MODE_DIR]:
        os.makedirs(d, exist_ok=True)
    return os.path.abspath(NONE_MODE_DIR), os.path.abspath(AUTO_MODE_DIR)


def run_codeql(mode, proj_name, root, out_dir):
    """Run `codeql database create` for one project; return (ok, db_path, message)."""
    # Replace slashes in project names to prevent Windows path truncation crashes
    safe_proj_name = proj_name.replace("/", "_").replace("\\", "_")
    db_name = f"db-{mode}-{safe_proj_name}"
    db_path = os.path.join(out_dir, db_name)
    cmd = ["codeql", "database", "create", db_path, "--language=csharp", "--overwrite"]
    if mode == "none":
        cmd += [f"--source-root={root}", "--build-mode=none"]
    else:
        cmd += [f"--source-root={root}", "--build-mode=autobuild"]

    t0 = time.time()
    print(f"\n    [CMD] {' '.join(cmd)}")
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=TIMEOUT_SECONDS)
        return True, db_path, f"OK ({round(time.time() - t0, 1)}s)"
    except subprocess.TimeoutExpired:
        return False, db_path, f"Timeout({TIMEOUT_SECONDS}s)"
    except subprocess.CalledProcessError as e:
        err = (e.stderr or "").strip().split('\n')[-1][:100]
        return False, db_path, f"CodeQL: {err}"
    except Exception as e:
        return False, db_path, f"Exception: {str(e)[:100]}"


def load_projects(csv_path):
    """Load project name/path pairs from the index CSV."""
    projects = []
    try:
        rows, fieldnames = read_csv_auto(csv_path)
        nc = pc = None
        for c in fieldnames:
            lc = c.lower()
            if not nc and lc in ['project', 'project name', 'projectname', 'name']:
                nc = c
            if not pc and lc in ['project path', 'projectpath', 'path', 'local_path']:
                pc = c
        if not nc or not pc:
            print(f"[ERR] Columns not found: {fieldnames}")
            return []
        for row in rows:
            n = row[nc].strip()
            p = row[pc].strip()
            if n and p:
                projects.append({'name': n, 'path': p})
    except Exception as e:
        print(f"[ERR] Read failed: {e}")
    return projects


def main():
    nd, ad = setup_dirs()
    report = get_report_path()
    completed = load_completed(report)

    print("=" * 60)
    print(f"CodeQL Batch Build | {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"Index: {CSV_INDEX_FILE}")
    print(f"Output: {BASE_OUT_DIR}")
    print(f"Report: {report} (done: {len(completed)})")
    print("=" * 60)

    projects = load_projects(CSV_INDEX_FILE)
    if not projects:
        print("[WARN] No projects found.")
        return

    if not os.path.exists(report):
        with open(report, 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow(["Project", "Mode", "Status", "Path", "Message", "Time"])

    total = len(projects)
    skip = 0
    for i, p in enumerate(projects, 1):
        name = p['name']
        root = p['path']
        bar = f"[{i}/{total}] ({i * 100 // total}%)"

        if name in completed:
            print(f"\n{bar} SKIP {name}")
            skip += 1
            continue

        print(f"\n{bar} {name}\n    Source: {root}")
        if not os.path.exists(root):
            print("    [SKIP] Path not found")
            now = datetime.datetime.now().strftime("%H:%M:%S")
            with open(report, 'a', newline='', encoding='utf-8') as f:
                csv.writer(f).writerow([name, "none", "Fail", "", "Path not found", now])
            continue

        print("    --> none mode", end="", flush=True)
        ok, db, msg = run_codeql("none", name, root, nd)
        print(" [OK]" if ok else f" [FAIL] {msg}")
        now = datetime.datetime.now().strftime("%H:%M:%S")
        with open(report, 'a', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow([name, "none", "OK" if ok else "Fail", db, msg, now])

    print(f"\n{'=' * 60}")
    print(f"Done | Total:{total} Skip:{skip} Report:{report}")
    print("=" * 60)


if __name__ == "__main__":
    main()
