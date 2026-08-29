"""
Unity Inspector Binding Analyzer
Fixes:
1) Encoding tolerance for .cs.meta / .unity / .prefab files to avoid UnicodeDecodeError.
2) Support interrupt-and-resume:
      - Projects that already have inspector_bindings.csv are skipped by default;
      - Within a project, per-file parse results are cached in .inspector_binding_cache.
3) Add project-level and file-level progress and incremental summary writes.
"""

import os
import re
import csv
import json
import hashlib
import argparse
import tempfile
import sys
from multiprocessing import Pool, cpu_count

try:
    import yaml
except ImportError:
    yaml = None

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(it, **kwargs):
        return it

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


BASE_DIR = r".\new3_dataset"
OUTPUT_CSV_NAME = "inspector_bindings.csv"
SUMMARY_CSV_NAME = "analysis_summary.csv"
CACHE_DIR_NAME = ".inspector_binding_cache"
CACHE_SCHEMA_VERSION = "v2-runtime-target-assembly-type"

FIELDNAMES = [
    'source_file', 'source_file_id', 'source_gameobject',
    'source_component_type', 'source_script_guid', 'event_field',
    'target_file_id', 'target_gameobject', 'target_component_type',
    'target_assembly_type',
    'target_method', 'param_index', 'call_type', 'listener_mode',
    'call_state', 'provenance'
]

SUMMARY_FIELDNAMES = [
    'project', 'assets_root', 'yaml_files_count',
    'bindings_count', 'output_file', 'status', 'error'
]


# ============================================================
# Generic safe reading
# ============================================================
def read_text_lossy(path):
    """
    Most Unity YAML is UTF-8, but real repositories may contain GBK/Latin-1/BOM files.
    The goal here is to extract ASCII/YAML structures such as fileID/guid/m_Name, not lossless full text.
    """
    with open(path, "rb") as f:
        raw = f.read()

    for enc in ("utf-8-sig", "utf-8", "gb18030", "cp936", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue

    return raw.decode("utf-8", errors="replace")


def atomic_write_csv(path, fieldnames, rows):
    """
    Write a temporary file first, then replace the final file, to avoid leaving a truncated CSV behind on interruption.
    """
    out_dir = os.path.dirname(os.path.abspath(path))
    os.makedirs(out_dir, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".csv", dir=out_dir)
    os.close(fd)
    try:
        with open(tmp_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def count_csv_rows(path):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return None
            return sum(1 for _ in reader)
    except Exception:
        return None


def update_summary_csv(summary_csv, info):
    """
    Update the summary immediately after each project is processed.
    This way, even if it crashes midway, the next run can still see completed/failed/skipped projects.
    """
    rows = []
    if os.path.isfile(summary_csv):
        try:
            with open(summary_csv, "r", encoding="utf-8-sig", newline="") as f:
                rows = list(csv.DictReader(f))
        except Exception:
            rows = []

    replaced = False
    for i, row in enumerate(rows):
        if row.get("project") == info.get("project"):
            rows[i] = info
            replaced = True
            break

    if not replaced:
        rows.append(info)

    atomic_write_csv(summary_csv, SUMMARY_FIELDNAMES, rows)


# ============================================================
# 1. GUID -> class name mapping (scan .cs.meta)
# ============================================================
def build_guid_map(project_root):
    """
    Key fix:
    No longer read .cs.meta directly with encoding='utf-8'.
    Since the guid field only contains ASCII characters, binary read + bytes regex is the most robust.
    """
    guid_map = {}
    meta_count = 0
    unreadable_count = 0

    guid_re = re.compile(rb"guid:\s+([a-fA-F0-9]{32})")

    for root, dirs, files in os.walk(project_root):
        for f in files:
            if not f.endswith(".cs.meta"):
                continue

            meta_count += 1
            path = os.path.join(root, f)

            try:
                with open(path, "rb") as fh:
                    content = fh.read()
            except Exception:
                unreadable_count += 1
                continue

            m = guid_re.search(content)
            if m:
                guid = m.group(1).decode("ascii").lower()
                fallback_type = os.path.basename(path).replace(".cs.meta", "")
                script_path = path[:-5]  # strip the trailing '.meta'
                type_name = fallback_type
                if os.path.isfile(script_path):
                    try:
                        script_text = read_text_lossy(script_path)
                        class_match = re.search(
                            r"\b(?:public|internal|private|protected|abstract|sealed|partial|static|\s)*"
                            r"class\s+([A-Za-z_][A-Za-z0-9_]*)\b",
                            script_text,
                        )
                        if class_match:
                            type_name = class_match.group(1)
                    except Exception:
                        pass
                guid_map[guid] = type_name

    print(f"  [INFO] GUID map: {len(guid_map)} entries / {meta_count} .cs.meta files")
    if unreadable_count:
        print(f"  [WARN] unreadable .cs.meta files: {unreadable_count}")

    return guid_map


# ============================================================
# 2. Single-file parser
# ============================================================
def parse_unity_file(file_path, verbose=False):
    try:
        content = read_text_lossy(file_path)
    except Exception:
        return []

    # Split object headers
    header_re = re.compile(r"^---\s*!u!(\d+)\s*&(-?\d+)\b", re.MULTILINE)
    matches = list(header_re.finditer(content))
    if not matches:
        return []

    objects = []
    for i, m in enumerate(matches):
        class_id = int(m.group(1))
        file_id = m.group(2)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        body = content[start:end].strip()
        objects.append({
            'class_id': class_id,
            'fileID': file_id,
            'body': body
        })

    # ---------- Helper regexes ----------
    def extract_name(body):
        m = re.search(r'^\s*m_Name:\s*(.+?)\s*$', body, re.MULTILINE)
        return m.group(1).strip() if m else 'Unknown'

    def extract_guid(body):
        m = re.search(r"m_Script:\s*\{[^}]*guid:\s*([a-fA-F0-9]{32})", body)
        return m.group(1).lower() if m else None

    def extract_gameobject_ref(body):
        m = re.search(r"m_GameObject:\s*\{fileID:\s*(-?\d+)\}", body)
        return m.group(1) if m else None

    # ---------- First scan: build all indexes ----------
    go_names = {}               # fileID -> GameObject name
    id_to_go_ref = {}           # any object's fileID -> the fileID its m_GameObject points to
    component_guid = {}         # fileID -> script GUID

    for obj in objects:
        fid = obj['fileID']
        body = obj['body']

        if obj['class_id'] != 1:
            go_ref = extract_gameobject_ref(body)
            if go_ref:
                id_to_go_ref[fid] = go_ref

        if obj['class_id'] == 1:
            go_names[fid] = extract_name(body)

        if obj['class_id'] == 114:  # MonoBehaviour
            guid = extract_guid(body)
            if guid:
                component_guid[fid] = guid

    # ---------- Helper: get GameObject name by fileID ----------
    def get_go_name(fid):
        fid = str(fid)

        if fid in go_names:
            return go_names[fid]

        if fid in id_to_go_ref:
            ref = id_to_go_ref[fid]
            if ref in go_names:
                return go_names[ref]

        obj = next((o for o in objects if o['fileID'] == fid), None)
        if obj:
            if obj['class_id'] == 1:
                return extract_name(obj['body'])
            go_ref = extract_gameobject_ref(obj['body'])
            if go_ref and go_ref in go_names:
                return go_names[go_ref]

        return 'Unknown'

    # ---------- Second scan: extract Inspector bindings ----------
    bindings = []

    for obj in objects:
        if obj['class_id'] != 114:
            continue

        body = obj['body']
        source_guid = component_guid.get(obj['fileID'], 'Unknown')
        source_go_name = get_go_name(obj['fileID'])

        if yaml is None:
            # Without PyYAML, the nested structure of UnityEvent cannot be parsed reliably.
            # Run: pip install pyyaml
            continue

        try:
            data = yaml.safe_load(body)
            if not isinstance(data, dict) or 'MonoBehaviour' not in data:
                continue
            mb_data = data['MonoBehaviour']
            if not isinstance(mb_data, dict):
                continue
        except Exception:
            continue

        for field, value in mb_data.items():
            if not isinstance(field, str):
                continue
            if field.startswith('m_') or not isinstance(value, dict):
                continue
            if 'm_PersistentCalls' not in value:
                continue

            persistent_calls = value.get('m_PersistentCalls') or {}
            calls = persistent_calls.get('m_Calls', [])
            if not isinstance(calls, list):
                continue

            for call in calls:
                if not isinstance(call, dict):
                    continue

                target = call.get('m_Target', {}) or {}
                target_fid = str(target.get('fileID', ''))
                method_name = call.get('m_MethodName', '')

                # fileID: 0 means a null reference, not a valid binding
                if not method_name or not target_fid or target_fid == "0":
                    continue

                # Unity PersistentListenerMode.EventDefined (0) forwards the
                # runtime Invoke argument. Other modes consume serialized values.
                args = call.get('m_Arguments', {}) or {}
                raw_mode = call.get('m_Mode', None)
                try:
                    listener_mode = int(raw_mode) if raw_mode is not None else None
                except (TypeError, ValueError):
                    listener_mode = None
                is_dynamic = listener_mode == 0 if listener_mode is not None else True
                if listener_mode is None and args:
                    checks = [
                        'm_ObjectArgument',
                        'm_IntArgument',
                        'm_FloatArgument',
                        'm_StringArgument',
                        'm_BoolArgument'
                    ]

                    def is_empty_arg(v):
                        return (
                            v is None
                            or v == 0
                            or v == 0.0
                            or v == ''
                            or v == {'fileID': 0}
                            or v == {'fileID': 0, 'guid': '', 'type': 0}
                        )

                    is_dynamic = all(is_empty_arg(args.get(k)) for k in checks)

                if not is_dynamic:
                    continue

                raw_call_state = call.get('m_CallState', 2)
                try:
                    call_state = int(raw_call_state)
                except (TypeError, ValueError):
                    call_state = 2
                # UnityEventCallState.Off does not execute in player/runtime.
                if call_state == 0:
                    continue

                # PersistentCall records the runtime receiver type explicitly.
                # Built-in Unity objects (for example GameObject) have no
                # MonoBehaviour script GUID, so GUID-only recovery incorrectly
                # classified executable bindings as Unknown.
                target_assembly_type = str(
                    call.get('m_TargetAssemblyTypeName', '') or ''
                ).split(',', 1)[0].strip()
                target_guid = component_guid.get(target_fid, 'Unknown')
                target_type = target_guid
                if target_type == 'Unknown' and target_assembly_type:
                    target_type = target_assembly_type.rsplit('.', 1)[-1]
                target_go_name = get_go_name(target_fid)

                if verbose:
                    print(f"  Binding: {source_go_name}.{field} -> {target_go_name}.{method_name}")

                bindings.append({
                    'source_file': file_path,
                    'source_file_id': obj['fileID'],
                    'source_gameobject': source_go_name,
                    'source_component_type': '',
                    'source_script_guid': source_guid,
                    'event_field': field,
                    'target_file_id': target_fid,
                    'target_gameobject': target_go_name,
                    'target_component_type': target_type,
                    'target_assembly_type': target_assembly_type,
                    'target_method': method_name,
                    'param_index': 0,
                    'call_type': 'dynamic',
                    'listener_mode': 0 if listener_mode is None else listener_mode,
                    'call_state': call_state,
                    'provenance': 'unity-yaml-persistent-call'
                })

    return bindings


# ============================================================
# 2.5 File-level cache: support interrupt-and-resume within a project
# ============================================================
def cache_key_for_file(file_path, assets_root):
    try:
        rel = os.path.relpath(file_path, assets_root)
    except Exception:
        rel = file_path
    norm = os.path.normcase(rel).replace("\\", "/")
    cache_identity = CACHE_SCHEMA_VERSION + "|" + norm
    return hashlib.sha1(cache_identity.encode("utf-8", errors="replace")).hexdigest() + ".json"


def parse_unity_file_cached(args):
    file_path, assets_root, cache_dir, use_cache, verbose = args

    try:
        st = os.stat(file_path)
        size = st.st_size
        mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))
    except Exception as e:
        return {
            "file_path": file_path,
            "bindings": [],
            "from_cache": False,
            "status": "FAILED",
            "error": f"stat failed: {e}"
        }

    cache_path = os.path.join(cache_dir, cache_key_for_file(file_path, assets_root))

    if use_cache and os.path.isfile(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if cached.get("size") == size and cached.get("mtime_ns") == mtime_ns:
                return {
                    "file_path": file_path,
                    "bindings": cached.get("bindings", []),
                    "from_cache": True,
                    "status": cached.get("status", "SUCCESS"),
                    "error": cached.get("error", "")
                }
        except Exception:
            # recompute if the cache is corrupted
            pass

    try:
        bindings = parse_unity_file(file_path, verbose=verbose)
        result = {
            "file_path": file_path,
            "bindings": bindings,
            "from_cache": False,
            "status": "SUCCESS",
            "error": ""
        }
    except Exception as e:
        result = {
            "file_path": file_path,
            "bindings": [],
            "from_cache": False,
            "status": "FAILED",
            "error": repr(e)
        }

    if use_cache:
        os.makedirs(cache_dir, exist_ok=True)
        payload = {
            "file_path": file_path,
            "size": size,
            "mtime_ns": mtime_ns,
            "bindings": result["bindings"],
            "status": result["status"],
            "error": result["error"]
        }

        tmp_path = cache_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
            os.replace(tmp_path, cache_path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    return result


# ============================================================
# 3. Find the Assets directory
# ============================================================
def find_assets_dir(project_root):
    """Find the Assets folder under the project root; supports nested scenes."""
    direct = os.path.join(project_root, "Assets")
    if os.path.isdir(direct):
        return direct

    for root, dirs, _ in os.walk(project_root):
        depth = root[len(project_root):].count(os.sep)
        if depth > 4:
            continue
        if "Assets" in dirs:
            return os.path.join(root, "Assets")

    return None


def collect_yaml_files(assets_root):
    yaml_files = []
    for root, dirs, files in os.walk(assets_root):
        for f in files:
            if f.endswith('.unity') or f.endswith('.prefab'):
                yaml_files.append(os.path.join(root, f))
    return yaml_files


# ============================================================
# 4. Process a single project
# ============================================================
def process_project(project_name, project_root, workers=4, verbose=False, resume=True,
                    use_cache=True, output_csv_override=None):
    print(f"\n[PROJECT] {project_name}")

    output_csv = output_csv_override or os.path.join(project_root, OUTPUT_CSV_NAME)

    # Project-level resume: skip if a valid CSV already exists
    if resume:
        existing_rows = count_csv_rows(output_csv)
        if existing_rows is not None:
            print(f"  [SKIP] {OUTPUT_CSV_NAME} already exists; skipped by default. bindings={existing_rows}")
            return {
                'project': project_name,
                'assets_root': '',
                'bindings_count': existing_rows,
                'yaml_files_count': '',
                'output_file': output_csv,
                'status': 'SKIPPED_ALREADY_DONE',
                'error': ''
            }

    assets_root = find_assets_dir(project_root)
    if not assets_root:
        print(f"  ⚠️ Assets directory not found")
        return {
            'project': project_name,
            'assets_root': 'NOT FOUND',
            'bindings_count': 0,
            'yaml_files_count': 0,
            'output_file': '',
            'status': 'FAILED',
            'error': 'Assets folder not found'
        }

    print(f"  Assets: {assets_root}")

    guid_map = build_guid_map(assets_root)

    yaml_files = collect_yaml_files(assets_root)
    print(f"  Scene/prefab files: {len(yaml_files)}")

    if yaml is None:
        print("  [WARN] PyYAML is not installed; nested UnityEvent fields cannot be parsed. Run: pip install pyyaml")

    cache_dir = os.path.join(project_root, CACHE_DIR_NAME)
    os.makedirs(cache_dir, exist_ok=True)

    worker_count = max(1, min(int(workers), cpu_count(), len(yaml_files) if yaml_files else 1))
    tasks = [(fp, assets_root, cache_dir, use_cache, verbose) for fp in yaml_files]

    results = []
    if tasks:
        with Pool(processes=worker_count) as pool:
            iterator = pool.imap_unordered(parse_unity_file_cached, tasks, chunksize=8)
            results = list(tqdm(
                iterator,
                total=len(tasks),
                desc=f"  Parsing {project_name}",
                unit="file"
            ))

    failed_files = [r for r in results if r.get("status") == "FAILED"]
    cache_hits = sum(1 for r in results if r.get("from_cache"))

    all_bindings = []
    for r in results:
        all_bindings.extend(r.get("bindings", []))

    # Fill in class names
    for b in all_bindings:
        b['source_component_type'] = guid_map.get(b['source_script_guid'], b['source_script_guid'])
        b['target_component_type'] = guid_map.get(b['target_component_type'], b['target_component_type'])

    atomic_write_csv(output_csv, FIELDNAMES, all_bindings)

    print(f"  ✅ Extracted {len(all_bindings)} dynamic bindings -> {output_csv}")
    print(f"  [PROGRESS] files={len(yaml_files)}, cache_hits={cache_hits}, failed_files={len(failed_files)}")

    status = 'SUCCESS' if not failed_files else 'PARTIAL_SUCCESS'
    error = ''
    if failed_files:
        error = f"{len(failed_files)} yaml/prefab files failed; see console/cache for details"
        # Print only the first 5 to avoid spamming the console
        for item in failed_files[:5]:
            print(f"    [FAILED FILE] {item.get('file_path')}: {item.get('error')}")
        if len(failed_files) > 5:
            print(f"    ... and {len(failed_files) - 5} more")

    return {
        'project': project_name,
        'assets_root': assets_root,
        'bindings_count': len(all_bindings),
        'yaml_files_count': len(yaml_files),
        'output_file': output_csv,
        'status': status,
        'error': error
    }


# ============================================================
# 5. Main function: batch processing
# ============================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-dir", default=BASE_DIR, help="Root directory containing multiple Unity projects")
    parser.add_argument("--project-root", help="Process only one Unity project; recommended for system pipelines")
    parser.add_argument("--output-csv", help="Output CSV path for single-project mode")
    parser.add_argument("--workers", type=int, default=min(cpu_count(), 4), help="Number of parallel processes, at most 4 by default")
    parser.add_argument("--force", action="store_true", help="Force a rerun, ignoring the existing inspector_bindings.csv")
    parser.add_argument("--no-cache", action="store_true", help="Disable the file-level cache")
    parser.add_argument("--verbose", action="store_true", help="Print more detailed binding information")
    args = parser.parse_args()

    if args.project_root:
        project_root = os.path.abspath(args.project_root)
        info = process_project(
            os.path.basename(project_root.rstrip(os.sep)), project_root,
            workers=args.workers, verbose=args.verbose, resume=not args.force,
            use_cache=not args.no_cache,
            output_csv_override=os.path.abspath(args.output_csv) if args.output_csv else None,
        )
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0 if info.get("status") in {"SUCCESS", "PARTIAL_SUCCESS", "SKIPPED_ALREADY_DONE"} else 1

    base_dir = args.base_dir

    if not os.path.isdir(base_dir):
        print(f"❌ Directory does not exist: {base_dir}")
        return

    projects = [
        d for d in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, d))
    ]

    if not projects:
        print("⚠️ No project directories found")
        return

    projects = sorted(projects)
    summary_csv = os.path.join(base_dir, SUMMARY_CSV_NAME)

    print(f"Found {len(projects)} projects")
    print(f"Resume: {'enabled' if not args.force else 'disabled, forced rerun'}")
    print(f"File cache: {'disabled' if args.no_cache else 'enabled'}")
    print(f"Parallel processes: {args.workers}")
    print(f"Summary report: {summary_csv}")

    summary = []
    project_bar = tqdm(projects, total=len(projects), desc="Projects", unit="project")

    for idx, proj in enumerate(project_bar, start=1):
        project_bar.set_postfix_str(f"{idx}/{len(projects)} {proj[:30]}")
        proj_path = os.path.join(base_dir, proj)

        try:
            info = process_project(
                proj,
                proj_path,
                workers=args.workers,
                verbose=args.verbose,
                resume=not args.force,
                use_cache=not args.no_cache
            )
        except KeyboardInterrupt:
            print("\n[INTERRUPTED] Interrupted by user. The summary for completed projects has been written; simply rerun next time to resume.")
            break
        except Exception as e:
            info = {
                'project': proj,
                'assets_root': '',
                'yaml_files_count': 0,
                'bindings_count': 0,
                'output_file': '',
                'status': 'FAILED',
                'error': repr(e)
            }
            print(f"  ❌ Failed to process project: {proj}: {e}")

        summary.append(info)
        update_summary_csv(summary_csv, info)

        done = len(summary)
        success_like = sum(1 for s in summary if s['status'] in ('SUCCESS', 'SKIPPED_ALREADY_DONE', 'PARTIAL_SUCCESS'))
        failed = sum(1 for s in summary if s['status'] == 'FAILED')
        print(f"  [TOTAL] done={done}/{len(projects)}, ok/skip/partial={success_like}, failed={failed}")

    # Finally re-read summary_csv for complete statistics, including previously written records
    final_rows = []
    if os.path.isfile(summary_csv):
        with open(summary_csv, "r", encoding="utf-8-sig", newline="") as f:
            final_rows = list(csv.DictReader(f))

    success = [s for s in final_rows if s.get('status') == 'SUCCESS']
    skipped = [s for s in final_rows if s.get('status') == 'SKIPPED_ALREADY_DONE']
    partial = [s for s in final_rows if s.get('status') == 'PARTIAL_SUCCESS']
    failed = [s for s in final_rows if s.get('status') == 'FAILED']

    print("\n" + "=" * 60)
    print(f"📊 Batch analysis end/interruption statistics: {len(final_rows)} project records in summary")
    print(f"  ✅ Succeeded: {len(success)}")
    print(f"  ⏭️ Skipped already-done: {len(skipped)}")
    print(f"  ⚠️ Partial success: {len(partial)}")
    print(f"  ❌ Failed: {len(failed)}")
    print(f"Summary report: {summary_csv}")

    if failed:
        print("Failed projects:")
        for f_item in failed:
            print(f"  - {f_item.get('project')}: {f_item.get('error')}")


# ============================================================
# 6. Single-project debug entry point
# ============================================================
def single_analyze_main():
    project_root = r".\vulnerability_dataset\TryNotDie"
    info = process_project(
        project_name=os.path.basename(project_root.rstrip("\\/")),
        project_root=project_root,
        workers=min(cpu_count(), 4),
        verbose=False,
        resume=False,
        use_cache=True
    )
    print(info)


if __name__ == "__main__":
    main()
    # single_analyze_main()
