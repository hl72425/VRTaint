import json
import os
import sys

# === 路径配置 ===
base_path = r"E:\1_my_project\dataset\vulnerability_dataset\CWE-465\Null Pointer"
json_rel_path = r"VRCFury_VRCFury_06e96d26fa14a1bf1936e625b5959184d00323bd_pre\codeql-db_v1_20251014_0006\v1_20251014_0006_labeled.json"
out_rel_dir = r"VRCFury_VRCFury_06e96d26fa14a1bf1936e625b5959184d00323bd_pre\codeql-db_v1_20251014_0006"

# 拼接为绝对路径
json_path = os.path.join(base_path, json_rel_path)
out_dir = os.path.join(base_path, out_rel_dir)
out_path = os.path.join(out_dir, "GeneratedAPIs.qll")

# === 读取 JSON ===
if not os.path.exists(json_path):
    print(f"❌ JSON 文件不存在: {json_path}")
    sys.exit(1)

with open(json_path, "r", encoding="utf-8") as f:
    entries = json.load(f)


# === 构造 predicate 名称安全化函数（避免特殊字符）===
def safe_name(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch == '_' else '_' for ch in s)


# === 按类+方法分组以减少重复 ===
sources, sinks, props = [], [], []

for e in entries:
    typ = e.get("type", "").strip().lower()
    cls = e.get("class", "")
    method = e.get("method", "")
    if not cls or not method:
        continue
    entry = (cls, method)
    if typ == "source":
        sources.append(entry)
    elif typ == "sink":
        sinks.append(entry)
    elif typ in ("taint-propagator", "propagator"):
        props.append(entry)
    else:
        pass  # 忽略 none

# === 输出 .qll 文件 ===
os.makedirs(out_dir, exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    f.write("module GeneratedAPIs {\n")
    f.write("  import csharp\n\n")

    # --- Source predicate ---
    f.write("  predicate isLLMDetectedSourceMethod(Method m) {\n")
    if sources:
        conds = [f'    m.getDeclaringType().getName() = "{cls}" and m.getName() = "{method}"'
                 for cls, method in sorted(set(sources))]
        f.write("    " + "\n    or ".join(conds) + "\n")
    else:
        f.write("    none()\n")
    f.write("  }\n\n")

    # --- Sink predicate ---
    f.write("  predicate isLLMDetectedSinkMethod(Method m) {\n")
    if sinks:
        conds = [f'    m.getDeclaringType().getName() = "{cls}" and m.getName() = "{method}"'
                 for cls, method in sorted(set(sinks))]
        f.write("    " + "\n    or ".join(conds) + "\n")
    else:
        f.write("    none()\n")
    f.write("  }\n\n")

    # --- Propagator predicate ---
    f.write("  predicate isLLMDetectedPropagator(Method m) {\n")
    if props:
        conds = [f'    m.getDeclaringType().getName() = "{cls}" and m.getName() = "{method}"'
                 for cls, method in sorted(set(props))]
        f.write("    " + "\n    or ".join(conds) + "\n")
    else:
        f.write("    none()\n")
    f.write("  }\n\n")

    f.write("}\n")

print(f"✅ Generated {out_path}")
print(f"   Sources: {len(sources)}, Sinks: {len(sinks)}, Propagators: {len(props)}")
