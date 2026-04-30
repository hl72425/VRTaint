import os
import re
import json
import logging
from typing import Dict, List, Optional
from ruamel.yaml import YAML
import csv

yaml = YAML(typ="safe")
logging.basicConfig(level=logging.INFO, format="[INFO] %(message)s")
base = r"E:\VR_project\dataset\vulnerability_dataset\CWE-465\Null Pointer"


# ============================================================
# Utility functions
# ============================================================

def find_files_by_name(root: str, name: str) -> List[str]:
    """
    Recursively search for files named `name` under root.
    """
    matches = []
    for dirpath, _, filenames in os.walk(root):
        if name in filenames:
            matches.append(os.path.join(dirpath, name))

    return matches


def robust_read_text(path: str) -> Optional[str]:
    """
    Robust reader for Unity YAML-like files.
    Try multiple encodings and fall back safely.
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception as e:
        logging.warning(f"Failed to read file: {path} ({e})")
        return None

    # Try UTF-8
    for enc in ("utf-8", "utf-16", "utf-16-le", "utf-16-be", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue

    # Last resort: ignore invalid bytes
    try:
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        logging.warning(f"Completely failed to decode: {path}")
        return None


def safe_load_yaml(path: str) -> Optional[dict]:
    content = robust_read_text(path)
    if not content:
        return None

    try:
        content = re.sub(r'!u![0-9]+\s*&[0-9]+', '', content)
        return yaml.load(content)
    except Exception as e:
        logging.warning(f"YAML decode failed for {path}: {e}")
        return None


def read_guid_from_meta(meta_path: str) -> Optional[str]:
    """
    Parse GUID from *.meta file.
    """
    if not os.path.exists(meta_path):
        return None

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("guid:"):
                    return line.split("guid:")[1].strip()
        return None
    except Exception:
        return None


# ============================================================
# Main classes
# ============================================================

class GUIDRegistry:
    """
    Maintain mapping:
        GUID -> asset_path
        asset_path -> GUID
    """

    def __init__(self):
        self.guid_to_path: Dict[str, str] = {}
        self.path_to_guid: Dict[str, str] = {}

    def add(self, asset_path: str, guid: Optional[str]):
        if guid is None:
            return
        self.guid_to_path[guid] = asset_path
        self.path_to_guid[asset_path] = guid

    def build_from_project(self, root):
        """
        Scan whole project for *.meta and build GUID mappings.
        """
        logging.info("Building GUID registry...")

        for dirpath, _, filenames in os.walk(root):
            for file in filenames:
                if file.endswith(".meta"):
                    meta_path = os.path.join(dirpath, file)
                    guid = read_guid_from_meta(meta_path)
                    if guid:
                        asset_path = meta_path[:-5]  # remove ".meta"
                        self.add(asset_path, guid)

        logging.info(f"GUID registry built: {len(self.guid_to_path)} GUIDs loaded.")

    def export_csv(self, out_path: str):
        """
        Export GUID <-> path mapping to CSV.
        """
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["GUID", "AssetPath"])
            for guid, path in sorted(self.guid_to_path.items()):
                writer.writerow([guid, path])

        logging.info(f"GUID mapping exported to CSV: {out_path}")
  

class UnityBuildSettingsParser:
    """
    Parse EditorBuildSettings.asset to obtain the scene list.
    """

    def __init__(self):
        self.scene_paths: List[str] = []

    def parse(self, path: str):
        logging.info(f"Parsing EditorBuildSettings.asset: {path}")
        data = safe_load_yaml(path)
        if not data:
            return

        scenes = data.get("EditorBuildSettings", {}).get("m_Scenes", [])
        for s in scenes:
            path_val = s.get("path")
            if path_val:
                self.scene_paths.append(path_val)

        logging.info(f"Scenes detected: {len(self.scene_paths)}")


class UnitySceneParser:
    """
    Parse .unity scene YAML to extract:
        GameObjects
        Components (MonoBehaviour etc.)
    """

    GAMEOBJECT_CLASSID = 1
    MONOBEHAVIOUR_CLASSID = 114
    TRANSFORM_CLASSID = 4

    OBJECT_HEADER_RE = re.compile(
        r"^---\s*!u!(\d+)\s*&\s*(\d+)(?:\s+stripped)?\s*$",
        re.MULTILINE
    )

    def __init__(self, guid_registry: GUIDRegistry):
        self.registry = guid_registry
        self.prefab_parser = UnityPrefabParser(guid_registry)

    def parse_scene(self, path: str) -> dict:
        logging.info(f"Parsing scene: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            logging.warning(f"Scene read failed: {e}")
            return {}

        blocks = self._split_objects(content)

        gameobjects: Dict[str, dict] = {}
        scripts: List[dict] = []
        transforms: Dict[str, dict] = {}

        for obj in blocks:
            class_id = obj["class_id"]

            if class_id == self.GAMEOBJECT_CLASSID:
                go = self._parse_gameobject(obj)
                if go:
                    gameobjects[go["fileID"]] = go
                    # print(go)

            elif class_id == self.MONOBEHAVIOUR_CLASSID:
                mb = self._parse_monobehaviour(obj)
                if mb:
                    scripts.append(mb)
            
            elif class_id == self.TRANSFORM_CLASSID:
                trans = self._parse_transform(obj)
                if trans:
                    transforms[trans["fileID"]] = trans

        # Bind MonoBehaviours to GameObjects
        for script in scripts:
            go_id = script.get("gameObject")
            if go_id in gameobjects:
                gameobjects[go_id]["components"].append(script)
        
        self._build_hierarchy(gameobjects, transforms)

        return {
            "gameobjects": list(gameobjects.values()),
            "scripts": scripts,
            "transforms": list(transforms.values()),
            "hierarchy": self._export_hierarchy(gameobjects)
        }

    # ---------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------

    def _split_objects(self, text: str) -> List[dict]:
        """
        Split Unity YAML into structured object blocks.
        """
        matches = list(self.OBJECT_HEADER_RE.finditer(text))
        objects = []

        for i, m in enumerate(matches):
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)

            objects.append({
                "class_id": int(m.group(1)),
                "fileID": m.group(2),
                "body": text[start:end]
            })

        return objects

    def _parse_gameobject(self, obj: dict) -> Optional[dict]:
        body = obj["body"]

        prefab_guid = self._extract(
            r"m_PrefabParentObject:\s*\{[^}]*guid:\s*([0-9a-fA-F]+)",
            body
        )

        # ========== Prefab Instance ==========
        if prefab_guid:
            prefab_path = self.registry.guid_to_path.get(prefab_guid)
            prefab_data = self.prefab_parser.parse_prefab(prefab_path) if prefab_path else {}

            # 合并 prefab 中所有 GameObject（简化：取第一个 root）
            prefab_gos = prefab_data.get("gameobjects", [])
            root = prefab_gos[0] if prefab_gos else {}

            return {
                "fileID": obj["fileID"],
                "type": "PrefabInstance",
                "prefab_guid": prefab_guid,
                "prefab_path": prefab_path,
                "name": root.get("name"),
                "active": root.get("active", True),
                "components": root.get("components", []),
                "parent_id": None,
                "children_ids": []
            }

        # ========== 普通 Scene GameObject ==========
        name = self._extract(r"m_Name:\s*(.+)", body)
        active = self._extract(r"m_IsActive:\s*(\d)", body)

        return {
            "fileID": obj["fileID"],
            "type": "SceneGameObject",
            "name": name.strip() if name else None,
            "active": active == "1",
            "components": [],
            "parent_id": None,
            "children_ids": []
        }

    def _parse_monobehaviour(self, obj: dict) -> Optional[dict]:
        body = obj["body"]

        gameObject = self._extract(r"m_GameObject:\s*\{fileID:\s*(\d+)", body)
        script_guid = self._extract(r"guid:\s*([0-9a-fA-F]+)", body)

        return {
            "fileID": obj["fileID"],
            "gameObject": gameObject,
            "script_guid": script_guid,
            "script_path": self.registry.guid_to_path.get(script_guid),
        }
    
    def _parse_transform(self, obj: dict) -> Optional[dict]:
        """
        解析 Transform 组件，提取层级关系关键信息。
        
        Unity 中 Transform 组件 (Class ID 4) 包含：
        - m_GameObject: 指向所属 GameObject 的 fileID
        - m_Father: 指向父物体 Transform 的 fileID
        - m_Children: 列出子物体 Transform 的 fileID 列表
        """
        body = obj["body"]
        
        # 提取所属 GameObject 的 fileID
        game_object_id = self._extract(
            r"m_GameObject:\s*\{fileID:\s*(\d+)",
            body
        )
        
        # 提取父物体 Transform 的 fileID
        father_trans_id = self._extract(
            r"m_Father:\s*\{fileID:\s*(\d+)",
            body
        )
        
        # 提取子物体 Transform 的 fileID 列表
        children_trans_ids = self._extract_children(body)
        
        return {
            "fileID": obj["fileID"],
            "game_object_id": game_object_id,
            "father_trans_id": father_trans_id,
            "children_trans_ids": children_trans_ids
        }

    def _extract_children(self, text: str) -> List[str]:
        """
        提取 m_Children 字段中的 Transform fileID 列表。
        
        YAML 格式示例：
        m_Children:
        - {fileID: 123456}
        - {fileID: 789012}
        """
        children_ids = []
        
        # 匹配 m_Children 块
        children_match = re.search(
            r"m_Children:\s*\n((?:\s*-\s*\{fileID:\s*\d+\s*\}\s*\n?)*)",
            text
        )
        
        if children_match:
            children_block = children_match.group(1)
            # 提取所有 fileID
            fileid_matches = re.findall(r"fileID:\s*(\d+)", children_block)
            children_ids = fileid_matches
        
        return children_ids

    def _build_hierarchy(
        self, 
        gameobjects: Dict[str, dict], 
        transforms: Dict[str, dict]
    ) -> None:
        """
        根据 Transform 组件构建 GameObject 的父子层级关系。
        
        处理流程：
        1. 建立 Transform ID -> GameObject ID 的映射
        2. 遍历所有 Transform，通过 m_Father 找到父节点
        3. 将 Transform 层级关系转换为 GameObject 层级关系
        4. 填充 GameObject 的 parent_id 和 children_ids 字段
        """
        # Step 1: 建立 Transform ID 到 GameObject ID 的映射
        trans_to_go: Dict[str, str] = {}
        for trans_id, trans_data in transforms.items():
            go_id = trans_data.get("game_object_id")
            if go_id:
                trans_to_go[trans_id] = go_id
        
        # Step 2: 遍历 Transform，构建 GameObject 父子关系
        for trans_id, trans_data in transforms.items():
            child_go_id = trans_to_go.get(trans_id)
            if not child_go_id or child_go_id not in gameobjects:
                continue
            
            # 获取父 Transform ID
            father_trans_id = trans_data.get("father_trans_id")
            
            if father_trans_id and father_trans_id in trans_to_go:
                parent_go_id = trans_to_go[father_trans_id]
                
                if parent_go_id in gameobjects:
                    # 设置子物体的父节点
                    gameobjects[child_go_id]["parent_id"] = parent_go_id
                    # 设置父物体的子节点列表
                    gameobjects[parent_go_id]["children_ids"].append(child_go_id)
            else:
                # 没有父节点，是根物体
                gameobjects[child_go_id]["parent_id"] = None

    def _export_hierarchy(self, gameobjects: Dict[str, dict]) -> List[dict]:
        """
        导出层级结构，便于可视化和分析。
        
        返回格式：
        [
            {
                "fileID": "123",
                "name": "Parent",
                "parent_id": null,
                "children_ids": ["456", "789"],
                "depth": 0
            },
            ...
        ]
        """
        hierarchy = []
        
        # 计算每个节点的深度
        depths = self._calculate_depths(gameobjects)
        
        for go_id, go_data in gameobjects.items():
            hierarchy.append({
                "fileID": go_id,
                "name": go_data.get("name"),
                "parent_id": go_data.get("parent_id"),
                "children_ids": go_data.get("children_ids", []),
                "depth": depths.get(go_id, 0)
            })
        
        return hierarchy

    def _calculate_depths(self, gameobjects: Dict[str, dict]) -> Dict[str, int]:
        """
        计算每个 GameObject 在层级树中的深度。
        根节点深度为 0，每向下一层深度 +1。
        """
        depths: Dict[str, int] = {}
        
        def get_depth(go_id: str, visited: set) -> int:
            if go_id in depths:
                return depths[go_id]
            
            if go_id in visited:
                return 0  # 防止循环引用
            
            visited.add(go_id)
            
            go_data = gameobjects.get(go_id)
            if not go_data:
                return 0
            
            parent_id = go_data.get("parent_id")
            
            if not parent_id or parent_id not in gameobjects:
                depths[go_id] = 0
            else:
                depths[go_id] = get_depth(parent_id, visited) + 1
            
            return depths[go_id]
        
        for go_id in gameobjects:
            get_depth(go_id, set())
        
        return depths

    def _extract(self, pattern: str, text: str) -> Optional[str]:
        m = re.search(pattern, text)
        return m.group(1) if m else None
    
    def print_hierarchy_tree(
        self, 
        gameobjects: Dict[str, dict], 
        root_ids: Optional[List[str]] = None,
        indent: int = 0
    ) -> None:
        """
        以树形结构打印场景层级。
        
        Args:
            gameobjects: GameObject 字典
            root_ids: 根节点 ID 列表，如果为 None 则自动查找
            indent: 当前缩进级别
        """
        if root_ids is None:
            # 自动查找根节点（没有 parent_id 的节点）
            root_ids = [
                go_id for go_id, go_data in gameobjects.items()
                if go_data.get("parent_id") is None
            ]
        
        for go_id in sorted(root_ids):
            if go_id not in gameobjects:
                continue
            
            go_data = gameobjects[go_id]
            prefix = "  " * indent
            active_status = "✓" if go_data.get("active", True) else "✗"
            
            print(f"{prefix}- [{active_status}] {go_data.get('name', 'Unnamed')} (ID: {go_id})")
            
            children_ids = go_data.get("children_ids", [])
            if children_ids:
                self.print_hierarchy_tree(gameobjects, children_ids, indent + 1)


class UnityPrefabParser:
    """
    Parse .prefab file to extract:
        - GameObjects
        - MonoBehaviours
    """

    GAMEOBJECT_CLASSID = 1
    MONOBEHAVIOUR_CLASSID = 114

    OBJECT_HEADER_RE = UnitySceneParser.OBJECT_HEADER_RE

    def __init__(self, guid_registry: GUIDRegistry):
        self.registry = guid_registry

    def parse_prefab(self, prefab_path: str) -> dict:
        if not os.path.exists(prefab_path):
            logging.warning(f"Prefab not found: {prefab_path}")
            return {}

        with open(prefab_path, "r", encoding="utf-8") as f:
            content = f.read()

        blocks = self._split_objects(content)

        gameobjects = {}
        scripts = []

        for obj in blocks:
            if obj["class_id"] == self.GAMEOBJECT_CLASSID:
                gameobjects[obj["fileID"]] = {
                    "fileID": obj["fileID"],
                    "name": self._extract(r"m_Name:\s*(.+)", obj["body"]),
                    "active": self._extract(r"m_IsActive:\s*(\d)", obj["body"]) != "0",
                    "components": []
                }

            elif obj["class_id"] == self.MONOBEHAVIOUR_CLASSID:
                go_id = self._extract(
                    r"m_GameObject:\s*\{fileID:\s*(\d+)", obj["body"]
                )
                guid = self._extract(r"guid:\s*([0-9a-fA-F]+)", obj["body"])

                scripts.append({
                    "gameObject": go_id,
                    "script_guid": guid,
                    "script_path": self.registry.guid_to_path.get(guid)
                })

        for s in scripts:
            go = gameobjects.get(s["gameObject"])
            if go:
                go["components"].append(s)

        return {
            "gameobjects": list(gameobjects.values())
        }

    def _split_objects(self, text):
        matches = list(self.OBJECT_HEADER_RE.finditer(text))
        objs = []

        for i, m in enumerate(matches):
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            objs.append({
                "class_id": int(m.group(1)),
                "fileID": m.group(2),
                "body": text[start:end]
            })
        return objs

    def _extract(self, pattern, text):
        m = re.search(pattern, text)
        return m.group(1).strip() if m else None


# ============================================================
# High-Level API
# ============================================================

class UnityProjectAnalyzer:
    """
    Full pipeline:
        1. Find EditorBuildSettings.asset
        2. Parse scene list
        3. Parse each scene for GameObjects + components
        4. Build GUID registry
    """

    def __init__(self, root: str):
        self.root = root
        self.guid_registry = GUIDRegistry()
        self.build_parser = UnityBuildSettingsParser()
        self.scene_parser = UnitySceneParser(self.guid_registry)

    def run(self):
        self.guid_registry.build_from_project(self.root)

        # Step 1: find EditorBuildSettings.asset
        ebs_files = find_files_by_name(self.root, "EditorBuildSettings.asset")
        if not ebs_files:
            raise FileNotFoundError("EditorBuildSettings.asset not found.")

        ebs_count = len(ebs_files)
        if ebs_count > 1:
            logging.info(f"WARNING: There are {ebs_count} EditorBuildSettings.asset!")

        ebs_path = ebs_files[0]  # 仅取找到的第一个场景配置文件
        self.build_parser.parse(ebs_path)

        results = {}

        # Step 2: parse scenes
        for scene_path in self.build_parser.scene_paths:
            full_path = resolve_scene_path(
                project_root=self.root,
                scene_path=scene_path
            )

            if not os.path.exists(full_path):
                logging.warning(f"Scene not found: {full_path}")
                continue

            data = self.scene_parser.parse_scene(full_path)
            results[scene_path] = data

        return results


def resolve_scene_path(project_root: str, scene_path: str) -> Optional[str]:
    """
    Resolve Unity scene path with multi-stage fallback.
    """

    scene_name = os.path.basename(scene_path)

    # ---------- Stage 3: Global project fallback ----------
    matches = find_files_by_name(project_root, scene_name)
    if len(matches) == 1:
        logging.info(f"[SceneResolve] Global fallback hit: {matches[0]}")
        return matches[0]
    elif len(matches) > 1:
        logging.warning(
            f"[SceneResolve] Multiple global matches for {scene_name}: {matches}"
        )
        return matches[0]

    logging.warning(f"[SceneResolve] Scene not found: {scene_path}")
    return None


# ============================================================
# CLI Usage
# ============================================================

def analyze_all_projects(root: str):
    for name in os.listdir(root):
        if not name.endswith("_pre"):
            continue
    
        project_path = os.path.join(root, name)
        if not os.path.isdir(project_path):
            continue
    
        logging.info(f"\n==== Analyzing project: {name} ====")

        try:
            # project_path = r"D:\研2\VR paper\unity_project\unity_sample"  # for debug
            analyzer = UnityProjectAnalyzer(project_path)
            result = analyzer.run()

            output_json = os.path.join(project_path, "unity_analysis_2.json")
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            analyzer.guid_registry.export_csv(
                os.path.join(project_path, "guid_mapping.csv")
            )

        except Exception as e:
            # logging.error(f"Failed on {name}: {e}")
            print("Failed! ")


if __name__ == "__main__":
    analyze_all_projects(base)
    logging.info(f"Analysis complete! ")
