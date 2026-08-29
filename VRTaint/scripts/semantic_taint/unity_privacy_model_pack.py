#!/usr/bin/env python3
"""Generate project facts for unresolved Unity APIs and serialized privacy flows.

The extractor is project-independent: it recognizes API/serialization families,
then CodeQL performs source-to-sink analysis over the recovered facts.
"""
import argparse, json, os, re
from pathlib import Path

SENSITIVE = re.compile(r"head|hand|controller|gaze|eye|pose|tracked|rig|camera|face|voice|audio|microphone", re.I)
SPATIAL = re.compile(r"head|hand|controller|gaze|eye|pose|tracked|(?:vr|xr)rig|\brig\b|\bxr\b", re.I)
TRANSFORM = re.compile(r"\.(?:position|rotation|localPosition|localRotation)\b")
CLASS = re.compile(r"\bclass\s+(\w+)")
VENDOR = {"Photon", "Oculus", "TextMesh Pro", "Packages", "3rd-Party", "Plugins", "Demos", "Demo"}
IGNORED_DIRS = {
    ".git", ".svn", "Library", "Temp", "Logs", "obj", "bin",
    "Packages", "PackageCache", "Build", "Builds", "UserSettings", ".vs",
    "MonoBleedingEdge", ".inspector_binding_cache",
}

def project_owned(p):
    return not any(part in VENDOR or part.startswith("Demo") for part in p.parts)

def rel(root, p): return p.relative_to(root).as_posix()

def walk_files(root, suffixes):
    """Yield project files while pruning generated/vendor-scale trees early."""
    suffixes = tuple(s.lower() for s in suffixes)
    for current, dirs, files in os.walk(root):
        dirs[:] = [
            d for d in dirs
            if d not in IGNORED_DIRS and d not in VENDOR and not d.startswith("Demo")
        ]
        base = Path(current)
        for name in files:
            if name.lower().endswith(suffixes):
                yield base / name

def scripts(root):
    for p in walk_files(root, (".cs",)):
        if project_owned(p.relative_to(root)):
            yield p

def class_line(p):
    for i, line in enumerate(p.read_text(encoding="utf-8-sig", errors="replace").splitlines(), 1):
        m = CLASS.search(line)
        if m: return i, m.group(1)
    return 1, p.stem

def guid_map(root):
    out = {}
    for m in walk_files(root, (".cs.meta",)):
        text = m.read_text(encoding="utf-8-sig", errors="replace")
        x = re.search(r"^guid:\s*([0-9a-f]+)", text, re.M|re.I)
        if x: out[x.group(1).lower()] = m.with_suffix("")
    return out

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--project-root",type=Path,required=True)
    ap.add_argument("--output-pack",type=Path,required=True); ap.add_argument("--pack-name",required=True)
    a=ap.parse_args(); root=a.project_root.resolve(); out=a.output_pack.resolve(); out.mkdir(parents=True,exist_ok=True)
    source=[]; anchors=[]
    for p in scripts(root):
        lines=p.read_text(encoding="utf-8-sig",errors="replace").splitlines(); cl,cn=class_line(p)
        semantic=SPATIAL.search(p.stem+" "+cn)
        anchors.append((p,cl,cn))
        for i,line in enumerate(lines,1):
            if TRANSFORM.search(line) and (semantic or SPATIAL.search(line)):
                source.append([rel(root,p),i,"xr-spatial-tracking","lexical Unity Transform access in privacy-semantic context"])
    gm=guid_map(root); exposures=[]
    for asset in walk_files(root, (".prefab", ".unity")):
        if not asset.is_file(): continue
        if not project_owned(asset.relative_to(root)): continue
        text=asset.read_text(encoding="utf-8-sig",errors="replace")
        guids=set(re.findall(r"m_Script:\s*\{[^\n]*guid:\s*([0-9a-f]+)",text,re.I))
        attached=[gm[g.lower()] for g in guids if g.lower() in gm and project_owned(gm[g.lower()].relative_to(root))]
        semantic_attached=[]
        for g in guids:
            p=gm.get(g.lower())
            if not p or p not in attached: continue
            for block in re.split(r"(?=^--- !u!\d+ &)", text, flags=re.M):
                if re.search(rf"m_Script:\s*\{{[^\n]*guid:\s*{re.escape(g)}\b",block,re.I) and SPATIAL.search(block):
                    semantic_attached.append(p); break
        # Photon observed transform: require an observed-component list and enabled position/rotation sync.
        if re.search(r"ObservedComponents|m_ObservedComponents",text,re.I) and re.search(r"SynchronizePosition|m_SynchronizePosition|m_SynchronizeRotation|SynchronizeRotation",text,re.I):
            cand=list(dict.fromkeys(semantic_attached + [x for x in attached if SPATIAL.search(x.stem)]))
            if cand:
                p=cand[0]; line,cn=class_line(p)
                exposures.append([rel(root,p),line,"xr-spatial-tracking","photon-transform",rel(root,asset),1,"serialized observed transform with spatial component binding","high"])
        # Photon Voice Recorder: require microphone source and enabled transmission/recording in one asset.
        if re.search(r"\bsourceType:\s*0\b",text) and re.search(r"\btransmitEnabled:\s*1\b",text) and re.search(r"\b(?:autoStart|recordingEnabled|recordOnlyWhenJoined):\s*1\b",text,re.I):
            cand=[x for x in attached if re.search(r"voice|audio|recorder|network",x.stem,re.I)] or attached
            if cand:
                p=cand[0]; line,cn=class_line(p)
                exposures.append([rel(root,p),line,"microphone-audio","photon-voice",rel(root,asset),1,"enabled microphone recorder with automatic network transmission","high"])
    # deterministic dedupe
    source=sorted({tuple(x) for x in source}); exposures=sorted({tuple(x) for x in exposures})
    y={"extensions":[
      {"addsTo":{"pack":"my-org/csharp-custom-queries","extensible":"unityPrivacySourceLocationModel"},"data":[list(x) for x in source] or [["__NONE__",0,"none","none"]]},
      {"addsTo":{"pack":"my-org/csharp-custom-queries","extensible":"unitySerializedPrivacyExposureModel"},"data":[list(x) for x in exposures] or [["__NONE__",0,"none","none","__NONE__",0,"none","none"]]}
    ]}
    (out/"qlpack.yml").write_text(
      f"name: {a.pack_name}\nversion: 0.0.1\nlibrary: true\nextensionTargets:\n  my-org/csharp-custom-queries: ^0.3.0\ndataExtensions:\n  - models.yml\n",
      encoding="utf-8")
    # JSON is valid YAML and avoids emitter dependencies.
    (out/"models.yml").write_text(json.dumps(y,indent=2),encoding="utf-8")
    summary={"source_fact_count":len(source),"serialized_exposure_count":len(exposures),"sources":source,"exposures":exposures}
    (out/"summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    print(json.dumps(summary))
if __name__=="__main__": main()
