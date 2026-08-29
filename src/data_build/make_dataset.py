"""Dataset construction helpers for the VRTaint project corpus.

This module provides two self-contained, reusable entry points:

1. ``clone_repos_from_urltxt()`` — batch-clone repositories listed in
   ``<root>/new_dataset/Dataset_Repo_Git_Url.txt`` into ``<root>/new_dataset``.
2. ``main()`` — convert ``<root>/old_dataset`` folder names (``author_repo``)
   back into GitHub URLs and write a CSV.

Run ``python make_dataset.py`` to execute the folder-name -> URL conversion.
"""
import os
import csv
import shutil
import subprocess
from pathlib import Path

# Anchor: this file lives under <dataset>/src/data_build/, parents[2] is the dataset root
ROOT = Path(__file__).resolve().parents[2]


def clone_repos_from_urltxt() -> dict:
    """Read Git URLs from a text file and clone them in batch.

    Includes basic fault tolerance: timeout control, failure cleanup,
    duplicate skipping, and truncated error logs.
    """
    url_file = ROOT / "new_dataset" / "Dataset_Repo_Git_Url.txt"
    out_path = ROOT / "new_dataset"
    out_path.mkdir(parents=True, exist_ok=True)

    if not url_file.is_file():
        raise FileNotFoundError(f"URL file not found: {url_file}")

    stats = {"success": 0, "failed": 0, "skipped": 0}

    # Read and filter out blank/comment lines
    with open(url_file, "r", encoding="utf-8-sig") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    for url in urls:
        # Extract the repo name (compatible with the .git suffix)
        repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
        target = out_path / repo_name

        # Skip repos that are already fully cloned
        if target.is_dir() and (target / ".git").is_dir():
            print(f"Already exists: {repo_name}")
            stats["skipped"] += 1
            continue

        target.mkdir(parents=True, exist_ok=True)
        url = url if url.endswith(".git") else f"{url}.git"
        print(f"Cloning: {url}")
        try:
            subprocess.run(
                ["git", "clone", url, str(target)],
                check=True,
                timeout=300,  # prevent large repos from hanging
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            print(f"Success: {repo_name}")
            stats["success"] += 1
        except subprocess.TimeoutExpired:
            print(f"Timeout: {repo_name}")
            stats["failed"] += 1
            shutil.rmtree(target, ignore_errors=True)
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode("utf-8", errors="ignore").strip()
            print(f"Failed: {repo_name} | {err[:150]}")  # truncate long error output
            stats["failed"] += 1
            shutil.rmtree(target, ignore_errors=True)
        except Exception as e:
            print(f"Exception: {repo_name} | {str(e)}")
            stats["failed"] += 1
            shutil.rmtree(target, ignore_errors=True)

    print(f"\nDone -> success: {stats['success']} | skipped: {stats['skipped']} | failed: {stats['failed']}")
    return stats


def folder_name_to_github_url(folder: str) -> tuple[str, str]:
    """Convert an ``author_repo`` folder name into (github_url, note).

    Handles zero, one, or multiple underscores:
    - 0 underscores: cannot determine author/repo -> empty URL with a note.
    - 1 underscore:  normal ``author_repo`` -> full URL.
    - 2+ underscores: split at the first underscore, with a reminder note.
    """
    underscore_count = folder.count("_")
    if underscore_count == 0:
        return "", "No underscore separator; cannot determine author and repo name"
    author, repo = folder.split("_", 1)
    note = ""
    if underscore_count >= 2:
        note = (f"Contains multiple underscores ({underscore_count} total); "
                "repo name may include extra underscores, please confirm manually")
    return f"https://github.com/{author}/{repo}", note


def main() -> None:
    """Convert old_dataset folder names back to GitHub URLs and write a CSV."""
    root_dir = ROOT / "old_dataset"
    output_csv = "github_repos.csv"

    if not root_dir.is_dir():
        print(f"Error: directory does not exist - {root_dir}")
        return

    folders = [name for name in os.listdir(root_dir)
               if (root_dir / name).is_dir()]
    results = []
    for folder in folders:
        url, note = folder_name_to_github_url(folder)
        results.append({"FolderName": folder, "GitHubURL": url, "Note": note})

    with open(output_csv, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["FolderName", "GitHubURL", "Note"])
        writer.writeheader()
        writer.writerows(results)

    print(f"Generated {output_csv}, processed {len(results)} folders.")


if __name__ == "__main__":
    main()
