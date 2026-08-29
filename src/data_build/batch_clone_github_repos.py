# -*- coding: utf-8 -*-
"""
Windows-friendly version: batch download GitHub projects, showing live git clone progress

Usage:
1. Modify the CSV_FILE and SAVE_DIR paths below
2. Run it in PowerShell / CMD:
   python download_github_projects_windows_live.py

CSV file format:
name,url
Cytoid/Cytoid,https://github.com/Cytoid/Cytoid
"""

import csv
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


# ===================== Only change things here =====================

# Anchor: this file lives under <dataset>/src/data_build/, parents[2] is the dataset root
ROOT = Path(__file__).resolve().parents[2]

CSV_FILE = str(ROOT / "new5_Unity_projects.csv")

SAVE_DIR = str(ROOT / "new5_dataset")

# True: download only the latest version (much faster); False: download the full history
SHALLOW_CLONE = True

# Maximum retries per project
MAX_RETRY = 3

# If a single git clone produces no new output for this many seconds, consider it stuck and terminate it
# Increase this when the GitHub network is poor, e.g. 300
NO_OUTPUT_TIMEOUT = 400

# Total download timeout per repository, in seconds
TOTAL_TIMEOUT = 60 * 30

# Whether to delete the half-finished directory after a failure
DELETE_BROKEN_DIR = True

# Optional: GitHub proxy. Leave empty if not used.
# For example:
# GITHUB_PROXY = "https://gh-proxy.com/"
GITHUB_PROXY = ""

# =========================================================


def read_csv_auto_encoding(csv_file):
    encodings = [
        "utf-8-sig",
        "utf-8",
        "gb18030",
        "gbk",
        "cp936",
        "utf-16",
        "latin-1",
    ]

    last_error = None

    for enc in encodings:
        try:
            with open(csv_file, "r", encoding=enc, newline="") as f:
                text = f.read()

            text = text.replace("\ufeff", "").replace("\x00", "")

            # Auto-detect the delimiter
            try:
                dialect = csv.Sniffer().sniff(text[:4096], delimiters=",\t;|")
            except Exception:
                dialect = csv.excel

            rows = list(csv.DictReader(text.splitlines(), dialect=dialect))

            if rows and "name" in rows[0] and "url" in rows[0]:
                print(f"[OK] CSV encoding detected successfully: {enc}")
                return rows

        except Exception as e:
            last_error = e

    raise RuntimeError(f"CSV encoding detection failed: {last_error}")


def safe_folder_name(name):
    name = name.strip().replace("\\", "/")
    name = name.strip("/")
    name = name.replace("/", "_")

    # Illegal characters in Windows folder names
    name = re.sub(r'[<>:"|?*]', "_", name)

    # Avoid overly long names
    if len(name) > 180:
        name = name[:180]

    return name


def normalize_github_url(url):
    url = url.strip().strip('"').strip("'")

    # Strip branch/file paths that may have been copied from a web page
    url = re.sub(r"/tree/.*$", "", url)
    url = re.sub(r"/blob/.*$", "", url)
    url = url.rstrip("/")

    if url.startswith("https://github.com/") and not url.endswith(".git"):
        url = url + ".git"

    if GITHUB_PROXY and url.startswith("https://github.com/"):
        url = GITHUB_PROXY.rstrip("/") + "/" + url

    return url


def check_git():
    try:
        result = subprocess.run(
            ["git", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        print("[OK]", result.stdout.strip())
        return True
    except Exception:
        print("[ERROR] git command not found. Please install Git for Windows and make sure git is on PATH.")
        return False


def build_clone_cmd(url, target_dir):
    cmd = ["git", "clone", "--progress"]

    if SHALLOW_CLONE:
        cmd += ["--depth", "1"]

    cmd += [url, str(target_dir)]
    return cmd


def run_git_clone_live(url, target_dir):
    """
    Show git clone output in real time.
    Solves the "looks stuck" problem.
    """
    cmd = build_clone_cmd(url, target_dir)

    print("    [CMD] " + " ".join(cmd))
    print("    [INFO] Connecting to GitHub; if the network is fine, progress like Counting / Receiving objects will appear below")
    print("    " + "-" * 70)

    start_time = time.time()
    last_output_time = time.time()
    output_lines = []

    # Merge stderr into stdout, because git clone progress is usually written to stderr
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        universal_newlines=True,
    )

    try:
        while True:
            line = process.stdout.readline()

            if line:
                last_output_time = time.time()
                line = line.rstrip("\n")
                output_lines.append(line)

                # Print raw git output in real time
                print("    " + line, flush=True)

            # Process finished
            if process.poll() is not None:
                # Read the remaining output
                rest = process.stdout.read()
                if rest:
                    for extra_line in rest.splitlines():
                        output_lines.append(extra_line)
                        print("    " + extra_line, flush=True)
                break

            now = time.time()

            # Total timeout
            if now - start_time > TOTAL_TIMEOUT:
                process.kill()
                msg = f"Exceeded the total timeout of {TOTAL_TIMEOUT} seconds; terminated git clone"
                print(f"    [TIMEOUT] {msg}")
                output_lines.append(msg)
                return False, "\n".join(output_lines)

            # No output for a long time usually means a stuck network or GitHub access issues
            if now - last_output_time > NO_OUTPUT_TIMEOUT:
                process.kill()
                msg = f"No new output for {NO_OUTPUT_TIMEOUT} seconds; network may be stuck, terminated git clone"
                print(f"    [TIMEOUT] {msg}")
                output_lines.append(msg)
                return False, "\n".join(output_lines)

            time.sleep(0.1)

    except KeyboardInterrupt:
        process.kill()
        print("\n    [STOP] Interrupted manually by the user")
        raise

    return_code = process.returncode
    ok = return_code == 0 and (target_dir / ".git").exists()

    print("    " + "-" * 70)

    if ok:
        return True, "\n".join(output_lines)
    else:
        output_lines.append(f"git clone return code = {return_code}")
        return False, "\n".join(output_lines)


def remove_broken_dir(target_dir):
    if target_dir.exists() and not (target_dir / ".git").exists():
        if DELETE_BROKEN_DIR:
            try:
                shutil.rmtree(target_dir)
                print("    [CLEAN] Deleted the incomplete directory")
            except Exception as e:
                print(f"    [WARN] Failed to delete the incomplete directory: {e}")


def main():
    csv_path = Path(CSV_FILE)
    save_root = Path(SAVE_DIR)

    if not csv_path.exists():
        print(f"[ERROR] CSV file does not exist: {csv_path}")
        return

    if not check_git():
        return

    save_root.mkdir(parents=True, exist_ok=True)

    rows = read_csv_auto_encoding(csv_path)
    total = len(rows)

    error_log = save_root / "download_errors.txt"
    status_log = save_root / "download_status.csv"

    print(f"[INFO] Read {total} records in total")
    print(f"[INFO] Save directory: {save_root}")
    print(f"[INFO] No-output timeout: {NO_OUTPUT_TIMEOUT} seconds")
    print(f"[INFO] Per-repo total timeout: {TOTAL_TIMEOUT} seconds")
    print("-" * 80)
  
    success = 0
    skipped = 0
    failed = 0

    # Write the header to the status file
    if not status_log.exists():
        with open(status_log, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["index", "total", "name", "url", "target_dir", "status", "message"])

    try:
        for i, row in enumerate(rows, start=1):
            name = (row.get("name") or "").strip()
            url = (row.get("url") or "").strip()

            if not name or not url:
                print(f"[{i}/{total}] [SKIP] empty name or url")
                skipped += 1
                continue

            url = normalize_github_url(url)
            folder_name = safe_folder_name(name)
            target_dir = save_root / folder_name

            print()
            print("=" * 80)
            print(f"[{i}/{total}] Processing: {name}")
            print(f"    URL : {url}")
            print(f"    DIR : {target_dir}")

            if (target_dir / ".git").exists():
                print("    [SKIP] Already exists, skipping")
                skipped += 1

                with open(status_log, "a", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([i, total, name, url, str(target_dir), "SKIPPED", "already exists"])

                continue

            if target_dir.exists() and not (target_dir / ".git").exists():
                print("    [WARN] Target directory exists but is not a complete Git repository")
                remove_broken_dir(target_dir)

                if target_dir.exists():
                    msg = "Target directory still exists; cannot clone. Please delete it manually and retry"
                    print(f"    [ERROR] {msg}")
                    failed += 1

                    with open(error_log, "a", encoding="utf-8") as f:
                        f.write(f"{name}\t{url}\t{msg}\n")

                    with open(status_log, "a", encoding="utf-8-sig", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([i, total, name, url, str(target_dir), "FAILED", msg])

                    continue

            ok = False
            last_output = ""

            for retry in range(1, MAX_RETRY + 1):
                print(f"    [CLONE] Attempt {retry}/{MAX_RETRY}...")

                ok, output = run_git_clone_live(url, target_dir)
                last_output = output

                if ok:
                    print("    [OK] Download succeeded")
                    success += 1

                    with open(status_log, "a", encoding="utf-8-sig", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([i, total, name, url, str(target_dir), "SUCCESS", f"retry={retry}"])

                    break

                print("    [WARN] This clone attempt failed")
                remove_broken_dir(target_dir)

                if retry < MAX_RETRY:
                    print("    [WAIT] Retrying in 5 seconds...")
                    time.sleep(5)

            if not ok:
                print("    [ERROR] Final download failed")
                failed += 1

                with open(error_log, "a", encoding="utf-8") as f:
                    f.write("=" * 80 + "\n")
                    f.write(f"index: {i}/{total}\n")
                    f.write(f"name : {name}\n")
                    f.write(f"url  : {url}\n")
                    f.write("last git output:\n")
                    f.write(last_output[-5000:] + "\n\n")

                with open(status_log, "a", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([i, total, name, url, str(target_dir), "FAILED", "see download_errors.txt"])

            print(f"    [SUMMARY] Current stats: success {success}, skipped {skipped}, failed {failed}")

    except KeyboardInterrupt:
        print()
        print("[STOP] Interrupted by user. The next run of this script will automatically skip projects already downloaded successfully.")

    print()
    print("=" * 80)
    print("[DONE] Batch download finished")
    print(f"Success: {success}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")
    print(f"Status file: {status_log}")
    print(f"Error log: {error_log}")


if __name__ == "__main__":
    main()
