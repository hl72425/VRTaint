# Native CodeQL and Semgrep Detection Summary - C# Scope

JavaScript and TypeScript vulnerabilities are excluded. TinkerXR remains in the oracle only for its C# unsafe BinaryFormatter deserialization finding.

| Tool | Security findings | Privacy findings | Overall | Runtime |
|---|---:|---:|---:|---:|
| Native CodeQL official C# suite | 2/12 | 0/6 | 2/18 (11.11%) | about 29m30s wall |
| Semgrep C#/Python registry rules | 3/12 | 0/6 | 3/18 (16.67%) | about 20m11s sequential |

## Native CodeQL target hits

- S01 Arcthesia_ArcCreate: `cs/zipslip` at `Assets/Scripts/Storage/FileImportManager.IO.cs:82`.
- S06 MinecraftVsZombies2Unity: `cs/zipslip` at `Assets/Scripts/Managers/SaveManager_Users.cs:239`.

## Semgrep target-location hits

- S03 doubledamnation: `insecure-binaryformatter-deserialization` at `Extensions.cs:137,148`.
- S05 open-brush: `unsafe-path-combine` at `ApiMethods.cs:1044`.
- S08 TinkerXR C# only: `insecure-binaryformatter-deserialization` at `ModelCreator.cs:250,269`.

Semgrep target hits are vulnerable sink/location hits rather than complete Unity-aware source-to-sink reconstruction. Neither baseline detects the six confirmed privacy flows.
