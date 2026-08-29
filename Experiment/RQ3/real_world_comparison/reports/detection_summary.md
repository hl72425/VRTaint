# Native CodeQL and Semgrep Detection Summary

Oracle: 12 confirmed security findings plus 6 confirmed privacy findings. A project-level hit requires an alert at a source-backed vulnerable location; unrelated alerts are excluded.

| Tool | Project-level target hits | Rate | Runtime |
|---|---:|---:|---:|
| Native CodeQL official C#/JS suites | 3/18 | 16.67% | about 32m22s sequential wall including 172.4s JS companion; 92m20.9s summed job time |
| Semgrep official C#/TypeScript/Python registry rules | 3/18 | 16.67% | 20m10.7s summed sequential job time |

## Target-matched findings

| ID | Project | Native CodeQL | Semgrep |
|---|---|---|---|
| S01 | Arcthesia_ArcCreate | cs/zipslip @ Assets/Scripts/Storage/FileImportManager.IO.cs:82 | No |
| S03 | TheYellowArchitect_doubledamnation | No | insecure-binaryformatter-deserialization @ Assets/Co-Op Prototype/Scripts/GameManager/Extensions.cs:137,148 |
| S05 | icosa-foundation_open-brush | No | unsafe-path-combine @ Assets/Scripts/API/ApiMethods.cs:1044 |
| S06 | Cuerzor_MinecraftVsZombies2Unity | cs/zipslip @ Assets/Scripts/Managers/SaveManager_Users.cs:239 | No |
| S08 | Boysle_TinkerXR | js/command-line-injection @ MgrServer/server.ts:83 | insecure-binaryformatter-deserialization @ Assets/Scripts/Artun/ModelCreator.cs:250,269 |

## Interpretation

- Semgrep emitted 24 raw alerts; five alerts were at target locations across S03, S05, and S08. The remaining alerts were unrelated to the 18-finding oracle.
- Semgrep target hits are sink/location hits. They do not reconstruct the complete network/HTTP source-to-sink chain or the S05 Lua second stage.
- Native CodeQL C# alone detects S01 and S06. Including the official JavaScript query for TinkerXR adds S08.
- Neither baseline detects any of the six confirmed privacy flows.

