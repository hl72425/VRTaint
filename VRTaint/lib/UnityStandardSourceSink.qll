/**
 * @name UnityStandardSourceSink
 * @description Standardized source, sink, and barrier predicates for Unity VR taint analysis.
 *              Extracted from test4.ql baseline. Import this library into project-specific
 *              queries to ensure consistent source/sink/barrier definitions across all analyses.
 *
 * Usage:
 *   import lib.UnityStandardSourceSink
 *   module MyConfig implements ProjectConfigSig {
 *     predicate isSource = UnityStandardSourceSink::isStandardSource/1;
 *     predicate isSink   = UnityStandardSourceSink::isStandardSink/1;
 *     predicate isBarrier = UnityStandardSourceSink::isStandardBarrier/1;
 *     predicate isAdditionalFlowStep(...) { ... }
 *   }
 */

import csharp

module UnityStandardSourceSink {

  // =========================================================================
  // SOURCE/SINK KINDS - coarse taint taxonomy for compatibility filtering
  // =========================================================================
  predicate isStandardSourceKind(DataFlow::Node source, string kind) {
    // Network endpoint data controlled before a request is sent.
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine.Networking.UnityWebRequest", ["Post", "Put", "SendWebRequest"]) and
      source = DataFlow::exprNode(mc.getArgument(0)) and
      kind = "url"
    )
    or
    // UI user text input.
    exists(PropertyAccess pa |
      pa.getTarget().hasFullyQualifiedName("UnityEngine.UI.InputField", "text") and
      source = DataFlow::exprNode(pa) and
      kind = "user-text"
    )
    or
    exists(PropertyAccess pa |
      pa.getTarget().hasFullyQualifiedName("TMPro.TMP_InputField", "text") and
      source = DataFlow::exprNode(pa) and
      kind = "user-text"
    )
    or
    // Process and environment input.
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("System.Environment", "GetCommandLineArgs") and
      source = DataFlow::exprNode(mc) and
      kind = "cmd-arg"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("System.Environment", "GetEnvironmentVariable") and
      source = DataFlow::exprNode(mc) and
      kind = "env"
    )
    or
    // Network response body.
    exists(PropertyAccess pa |
      pa.getTarget().hasFullyQualifiedName(
        "UnityEngine.Networking.DownloadHandler", "text") and
      source = DataFlow::exprNode(pa) and
      kind = "network-body"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine.Networking.NetworkReader", "ReadString") and
      source = DataFlow::exprNode(mc) and
      kind = "network-body"
    )
    or
    // Local file and persisted local/user configuration.
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("System.IO", "File", "ReadAllText") and
      source = DataFlow::exprNode(mc) and
      kind = "file-content"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("UnityEngine", "PlayerPrefs", "GetString") and
      source = DataFlow::exprNode(mc) and
      kind = "persisted-text"
    )
  }

  predicate isStandardSinkKind(DataFlow::Node sink, string kind) {
    // Dynamic method dispatch: tainted method/callback names are control-flow sensitive.
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine", "GameObject", ["SendMessage", "BroadcastMessage", "SendMessageUpwards"]) and
      sink = DataFlow::exprNode(mc.getArgument(0)) and
      kind = "reflection-name"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine", "MonoBehaviour", ["StartCoroutine", "Invoke", "InvokeRepeating"]) and
      sink = DataFlow::exprNode(mc.getArgument(0)) and
      kind = "reflection-name"
    )
    or
    // Reflection and type resolution.
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "System.Reflection", "MethodInfo", "Invoke") and
      sink = DataFlow::exprNode(mc.getAnArgument()) and
      kind = "reflection-argument"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "System.Reflection", "MethodBase", "Invoke") and
      sink = DataFlow::exprNode(mc.getAnArgument()) and
      kind = "reflection-argument"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "System", "Type", "GetType") and
      sink = DataFlow::exprNode(mc.getArgument(0)) and
      kind = "type-name"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "System", "Activator", "CreateInstance") and
      sink = DataFlow::exprNode(mc.getAnArgument()) and
      kind = "type-name"
    )
    or
    // Network request URL/endpoint.
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine.Networking", "UnityWebRequest", ["Get", "Post", "Put", "Delete"]) and
      sink = DataFlow::exprNode(mc.getArgument(0)) and
      kind = "url"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine.Networking", "UnityWebRequest", "SendWebRequest") and
      sink = DataFlow::exprNode(mc.getQualifier()) and
      kind = "url"
    )
    or
    // Persistence / deserialization / asset loading.
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine", "PlayerPrefs", ["SetString", "SetFloat", "SetInt"]) and
      sink = DataFlow::exprNode(mc.getAnArgument()) and
      kind = "persistence"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "Newtonsoft.Json", "JsonConvert", "DeserializeObject") and
      sink = DataFlow::exprNode(mc.getAnArgument()) and
      kind = "deserialization"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine", "Resources", "Load") and
      sink = DataFlow::exprNode(mc.getAnArgument()) and
      kind = "resource-path"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine", "AssetBundle", ["LoadAsset", "LoadAssetAsync"]) and
      sink = DataFlow::exprNode(mc.getAnArgument()) and
      kind = "resource-path"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine.AddressableAssets", "Addressables", "LoadAssetAsync") and
      sink = DataFlow::exprNode(mc.getAnArgument()) and
      kind = "resource-path"
    )
    or
    // File I/O: distinguish path control from content control.
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "System.IO", "File", ["WriteAllText", "WriteAllBytes", "AppendAllText", "Delete", "ReadAllText"]) and
      sink = DataFlow::exprNode(mc.getArgument(0)) and
      kind = "file-path"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "System.IO", "File", ["WriteAllText", "AppendAllText"]) and
      sink = DataFlow::exprNode(mc.getArgument(1)) and
      kind = "file-content"
    )
    or
    // Object instantiation and motion/teleport sinks.
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "UnityEngine", "Object", "Instantiate") and
      sink = DataFlow::exprNode(mc.getAnArgument()) and
      kind = "object-reference"
    )
    or
    exists(PropertyAccess pa |
      pa.getTarget().hasFullyQualifiedName(
        "UnityEngine", "Rigidbody", "velocity") and
      sink = DataFlow::exprNode(pa.getQualifier()) and
      kind = "movement"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName(
        "", "TeleportationProvider", "RequestTeleport") and
      sink = DataFlow::exprNode(mc.getAnArgument()) and
      kind = "movement"
    )
  }

  private predicate isExternalTextKind(string sourceKind) {
    sourceKind in ["user-text", "network-body", "cmd-arg", "env", "file-content", "persisted-text"]
  }

  private predicate isDynamicDispatchSinkKind(string sinkKind) {
    sinkKind in ["reflection-name", "reflection-argument", "type-name"]
  }

  private predicate isTextMaterialSinkKind(string sinkKind) {
    sinkKind in ["persistence", "deserialization", "resource-path", "file-path", "file-content"]
  }

  private predicate isUnityRuntimeObjectSinkKind(string sinkKind) {
    sinkKind in ["object-reference", "movement"]
  }

  predicate isCompatibleTaintKind(string sourceKind, string sinkKind) {
    // Endpoint strings should stay endpoint-specific unless they are later read
    // back as ordinary text by another source predicate.
    sourceKind = "url" and sinkKind = "url"
    or
    // URL construction from attacker-controlled text.
    sourceKind in ["network-body", "cmd-arg", "env", "persisted-text"] and sinkKind = "url"
    or
    // Code/data boundary sinks: reflection, resource lookup, files, persistence,
    // and deserialization are controlled by textual material.
    isExternalTextKind(sourceKind) and
    (isDynamicDispatchSinkKind(sinkKind) or isTextMaterialSinkKind(sinkKind))
    or
    // Unity runtime-object sinks are intentionally narrower: they require text
    // that commonly passes through parsing or scene/configuration material.
    sourceKind in ["user-text", "network-body", "cmd-arg", "env", "persisted-text"] and
    isUnityRuntimeObjectSinkKind(sinkKind)
  }

  predicate isCompatibleStandardFlow(DataFlow::Node source, DataFlow::Node sink, string flowKind) {
    exists(string sourceKind, string sinkKind |
      isStandardSourceKind(source, sourceKind) and
      isStandardSinkKind(sink, sinkKind) and
      isCompatibleTaintKind(sourceKind, sinkKind) and
      flowKind = sourceKind + " -> " + sinkKind
    )
  }

  // =========================================================================
  // SOURCES ? external data entry points
  // =========================================================================
  predicate isStandardSource(DataFlow::Node source) {
    exists(string kind | isStandardSourceKind(source, kind))
  }

  // =========================================================================
  // SINKS ? dangerous or controllable endpoints
  // =========================================================================
  predicate isStandardSink(DataFlow::Node sink) {
    exists(string kind | isStandardSinkKind(sink, kind))
  }

  predicate isSemanticSanitizer(DataFlow::Node node) {
    // Global barriers must be security-preserving for every sink kind. Functions
    // such as Path.GetFileName, Regex.Escape, UrlEncode, or Mathf.Clamp are kept
    // out of this generic barrier because their safety is sink-specific.
    node.asExpr() instanceof Literal
  }

  // =========================================================================
  // BARRIERS ? sanitization points
  // =========================================================================
  predicate isStandardBarrier(DataFlow::Node node) {
    // B1 - Semantic sanitizers with sink-aware security meaning.
    isSemanticSanitizer(node)
  }
}
