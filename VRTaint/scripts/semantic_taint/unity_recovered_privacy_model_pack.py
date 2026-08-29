#!/usr/bin/env python3
"""Convert general semantic source/call/field recovery into CodeQL data-extension facts."""
import argparse, importlib.util, json, sys
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--project-root',type=Path,required=True)
    p.add_argument('--semantic-analyzer',type=Path,required=True);p.add_argument('--output-pack',type=Path,required=True)
    p.add_argument('--pack-name',required=True);a=p.parse_args();root=a.project_root.resolve();out=a.output_pack.resolve();out.mkdir(parents=True,exist_ok=True)
    spec=importlib.util.spec_from_file_location('privacy_semantic',a.semantic_analyzer);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
    methods,texts=m.parse_methods(root);sources,sinks=m.discover_events(methods,texts)
    findings=m.connected_findings(root,root.name,methods,sources,sinks)
    rows=[]
    for f in findings:
        # Only externalize the two implicit, typed project buses that ordinary
        # C# data flow cannot reconstruct. Direct/local flows remain CodeQL's job.
        if (f.source.path.lower().endswith('.cs') and f.sink.path.lower().endswith('.cs') and
            f.bridge in {'typed-voice-processing-pipeline', 'typed-teleoperation-pipeline'} and
            f.sink.kind in {'grpc-client', 'rosbridge', 'photon-fusion', 'photon-rpc', 'socket',
                            'websocket', 'http-multipart', 'http-upload', 'unity-http',
                            'system-net-http', 'system-net-webclient', 'rest-client', 'mqtt'} and
            not (f.bridge == 'typed-teleoperation-pipeline' and
                 any(word in (f.sink.path + ' ' + f.sink.excerpt).lower()
                     for word in ('voice', 'audio', 'speech')))):
            rows.append([f.source.path,f.source.line,f.source.kind,f.sink.path,f.sink.line,f.sink.kind,f.bridge,f.confidence])
    rows=sorted({tuple(x) for x in rows})
    data={"extensions":[{"addsTo":{"pack":"my-org/csharp-custom-queries","extensible":"unityRecoveredPrivacyExposureModel"},"data":[list(x) for x in rows] or [["__NONE__",0,"none","__NONE__",0,"none","none","none"]]}]}
    (out/'qlpack.yml').write_text(f"name: {a.pack_name}\nversion: 0.0.1\nlibrary: true\nextensionTargets:\n  my-org/csharp-custom-queries: ^0.3.0\ndataExtensions:\n  - models.yml\n",encoding='utf-8')
    (out/'models.yml').write_text(json.dumps(data,indent=2),encoding='utf-8');(out/'summary.json').write_text(json.dumps({"count":len(rows),"rows":rows},indent=2),encoding='utf-8')
    print(json.dumps({"count":len(rows)}))
if __name__=='__main__':main()
