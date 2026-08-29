/**
 * @name UnityExternalInput
 * @description Project-neutral external-input model for Unity and common Unity-side SDKs.
 *              The predicates intentionally model API families and callback contracts,
 *              never repository names or fixed source locations.
 */

import csharp
import UnityLifecycleBase

module UnityExternalInput {

  /** True for project runtime code. Editor-only paths remain visible to dedicated editor rules. */
  predicate isRuntimeNode(DataFlow::Node node) {
    exists(Callable c |
      c = node.getEnclosingCallable() and
      not c.getFile().getRelativePath().regexpMatch(
        ".*(/Editor/|/Tests?/|/Samples?/|/Examples?/|/AOTGenerated/|/Generated/).*"
      ) and
      not c.getFile().getRelativePath().regexpMatch("^Editor/.*")
    )
  }

  private predicate hasNetworkTypeEvidence(ValueOrRefType t) {
    t.getName().toLowerCase().regexpMatch(
      ".*(packet|networkreader|netreader|rpcargs|message|payload|frame|http.*request|web.*request).*"
    )
    or
    t.getNamespace().getName().toLowerCase().regexpMatch(
      ".*(network|grpc|rpc|http|socket|websocket|multiplayer|mirror|photon|forge).*"
    )
  }

  /** Values decoded from a network packet/RPC argument object. */
  private predicate networkDecoderSource(DataFlow::Node source, string sourceKind) {
    exists(MethodCall mc, Method m |
      m = mc.getTarget() and
      (
        m.getName() in [
          "ReadString", "ReadBytes", "ReadByteArray", "ReadBuffer", "ReadPayload",
          "ReadMessage", "ReadRemainingBytes", "GetData", "GetPayload", "GetNext"
        ]
        or exists(string suffix | m.getName() = "GetNext<" + suffix)
      ) and
      hasNetworkTypeEvidence(m.getDeclaringType()) and
      source = DataFlow::exprNode(mc) and
      sourceKind = "NetworkInput"
    )
  }

  /** Request-derived properties and stream/reader methods used by embedded HTTP servers. */
  private predicate httpRequestSource(DataFlow::Node source, string sourceKind) {
    exists(PropertyAccess pa, Property p |
      p = pa.getTarget() and
      (
        hasNetworkTypeEvidence(p.getDeclaringType()) or
        p.getDeclaringType().getNamespace().getName().toLowerCase().regexpMatch(".*(http|web).*request.*")
      ) and
      p.getName() in [
        "Body", "InputStream", "QueryString", "RawUrl", "Url", "Path", "RouteValues",
        "Form", "Files", "Headers", "Content", "Data"
      ] and
      source = DataFlow::exprNode(pa) and sourceKind = "HttpRequest"
    )
    or
    exists(MethodCall mc, Method m |
      m = mc.getTarget() and
      m.getName() in ["ReadToEnd", "ReadAsStringAsync", "ReadFromJsonAsync"] and
      (
        hasNetworkTypeEvidence(mc.getQualifier().getType()) or
        exists(Callable c |
          c = mc.getEnclosingCallable() and
          c.getAParameter().getType().getName().toLowerCase().regexpMatch(".*http.*context.*")
        )
      ) and
      source = DataFlow::exprNode(mc) and sourceKind = "HttpRequest"
    )
  }

  /** Parameters of methods exposed through application-defined HTTP endpoint attributes. */
  private predicate attributedHttpEndpointParameterSource(DataFlow::Node source, string sourceKind) {
    exists(Method m, Parameter p, Attribute a |
      p = m.getAParameter() and a = m.getAnAttribute() and
      a.getType().getName().toLowerCase().regexpMatch(".*(apiendpoint|httproute|route|httpget|httppost).*") and
      source = DataFlow::parameterNode(p) and sourceKind = "HttpEndpoint"
    )
  }

  private predicate isFileChooserType(ValueOrRefType t) {
    t.getName().toLowerCase().regexpMatch(".*(filebrowser|filedialog|nativefilepicker|standalonefilebrowser).*" )
    or
    t.getNamespace().getName().toLowerCase().regexpMatch(".*(filebrowser|filedialog|filepicker).*" )
  }

  /** File paths or bytes chosen by a user through a Unity/native file picker. */
  private predicate fileChooserSource(DataFlow::Node source, string sourceKind) {
    exists(MethodCall mc, Method m |
      m = mc.getTarget() and isFileChooserType(m.getDeclaringType()) and
      m.getName().regexpMatch(".*(OpenFile|LoadDialog|PickFile|SelectFile|ReadBytesFromFile).*") and
      source = DataFlow::exprNode(mc) and sourceKind = "UserSelectedFile"
    )
    or
    exists(PropertyAccess pa, Property p |
      p = pa.getTarget() and isFileChooserType(p.getDeclaringType()) and
      p.getName() in ["Result", "Results", "SelectedPath", "SelectedPaths", "FileName", "FileNames"] and
      source = DataFlow::exprNode(pa) and sourceKind = "UserSelectedFile"
    )
    or
    // Callback contract: Show/Open/Load file dialog passes selected paths to its delegate.
    exists(MethodCall registration, Callable callback, MethodAccess ma, Parameter p |
      registration.getTarget().getName().regexpMatch(".*(ShowLoadDialog|OpenFilePanel|PickFile|SelectFile).*") and
      isFileChooserType(registration.getTarget().getDeclaringType()) and
      ma = registration.getAnArgument().getAChildExpr*() and
      callback = ma.getTarget() and p = callback.getParameter(0) and
      source = DataFlow::parameterNode(p) and sourceKind = "UserSelectedFile"
    )
  }

  /** Unity deep-link material. */
  private predicate deepLinkSource(DataFlow::Node source, string sourceKind) {
    exists(PropertyAccess pa |
      pa.getTarget().hasFullyQualifiedName("UnityEngine", "Application", "absoluteURL") and
      source = DataFlow::exprNode(pa) and sourceKind = "DeepLink"
    )
    or
    exists(Parameter p, Method m |
      p = m.getParameter(0) and
      m.getName().toLowerCase().regexpMatch(".*deeplink.*") and
      source = DataFlow::parameterNode(p) and sourceKind = "DeepLink"
    )
  }

  /** Downloaded response body, including byte arrays. */
  private predicate unityWebResponseSource(DataFlow::Node source, string sourceKind) {
    exists(PropertyAccess pa |
      pa.getTarget().getDeclaringType().getName().matches("DownloadHandler%") and
      pa.getTarget().getName() in ["text", "data"] and
      source = DataFlow::exprNode(pa) and sourceKind = "NetworkResponse"
    )
  }

  /**
   * Structured objects materialised from downloaded/imported JSON content.
   *
   * Unity content pipelines frequently persist a response and parse it later in
   * the same Download/Import coroutine.  The file side effect is outside the
   * ordinary C# data-flow graph, so the returned object must be reintroduced as
   * an external source.  Requiring both a structured parser and concrete
   * download/import evidence in the enclosing callable avoids classifying
   * ordinary bundled configuration files as attacker-controlled.
   */
  private predicate structuredExternalContentEvidence(Callable owner, MethodCall conversion) {
      owner = conversion.getEnclosingCallable() and
      (
        conversion.getTarget().getName() in [
          "Parse", "DeserializeObject", "Deserialize", "FromJson"
        ]
        or
        // Closed generic calls are displayed as ToObject<T> in C# databases.
        conversion.getTarget().getName().matches("ToObject<%")
      ) and
      (
        owner.getName().toLowerCase().regexpMatch(
          ".*(download|import|remote|community|workshop|package|update).*"
        )
        or
        exists(MethodCall transfer |
          transfer.getEnclosingCallable() = owner and
          (
            transfer.getTarget().getName().regexpMatch(
              ".*(SaveUrlToFile|DownloadFile|DownloadString|DownloadData|GetAsync|SendWebRequest).*"
            )
            or
            transfer.getTarget().getDeclaringType().getName() in [
              "UnityWebRequest", "HttpClient", "WebClient"
            ]
          )
        )
      ) and
      // Keep the model tied to actual structured/file content rather than any
      // domain method coincidentally named Parse or Deserialize.
      (
        conversion.getTarget().getDeclaringType().getName().regexpMatch(
          ".*(Json|JToken|JObject|JArray|Serializer).*"
        )
        or
        conversion.getTarget().getDeclaringType().getNamespace().getName().toLowerCase().regexpMatch(
          ".*(json|newtonsoft).*"
        )
        or
        conversion.getTarget().getName().matches("ToObject<%") and
        conversion.getQualifier().getType().getName().regexpMatch("J(Token|Object|Array)")
      )
  }

  private predicate structuredExternalContentSource(DataFlow::Node source, string sourceKind) {
    exists(MethodCall conversion, Callable owner |
      structuredExternalContentEvidence(owner, conversion) and
      source = DataFlow::exprNode(conversion) and
      sourceKind = "StructuredExternalContent"
    )
    or
    // A path-shaped member read from a structured external-content record.
    // Collection insertion/iteration is not represented by ordinary C# value
    // flow: Parse(...).ToObject<List<T>>() -> AddRange -> foreach element loses
    // the element identity. Reintroduce only a member expression that is
    // syntactically consumed by a path-construction API, and only in a callable
    // already proven to parse and transfer external structured content. This is
    // a generic container-summary edge rather than a model for a named DTO.
    exists(PropertyAccess access, MethodCall pathBuild, Callable owner, MethodCall conversion |
      owner = access.getEnclosingCallable() and
      structuredExternalContentEvidence(owner, conversion) and
      pathBuild.getEnclosingCallable() = owner and
      pathBuild.getTarget().getName() in ["Combine", "Join", "GetFullPath"] and
      pathBuild.getTarget().getDeclaringType().getName() = "Path" and
      access = pathBuild.getAnArgument().getAChildExpr*() and
      access.getTarget().getName().toLowerCase().regexpMatch(
        "(name|id|path|filepath|filename|relativepath|key|slug|file)"
      ) and
      source = DataFlow::exprNode(access) and
      sourceKind = "StructuredExternalPathMetadata"
    )
  }

  /** A parameter of a generated/SDK streaming receiver callback. */
  private predicate networkReceiverParameterSource(DataFlow::Node source, string sourceKind) {
    exists(Method m, Parameter p, ValueOrRefType baseType |
      p = m.getAParameter() and
      baseType = m.getDeclaringType().getABaseType*() and
      (
        baseType.getName().toLowerCase().regexpMatch(".*(receiver|listener|messagehandler|rpc).*" ) or
        baseType.getNamespace().getName().toLowerCase().regexpMatch(".*(grpc|rpc|network|streaming|multiplayer).*" )
      ) and
      m.getName().regexpMatch("^(On|Handle|Receive|Process).+") and
      source = DataFlow::parameterNode(p) and sourceKind = "NetworkCallback"
    )
  }

  /** Unified source taxonomy used by security queries and five-tuple enrichment. */
  predicate sourceKind(DataFlow::Node source, string sourceKind) {
    networkDecoderSource(source, sourceKind)
    or httpRequestSource(source, sourceKind)
    or attributedHttpEndpointParameterSource(source, sourceKind)
    or fileChooserSource(source, sourceKind)
    or deepLinkSource(source, sourceKind)
    or unityWebResponseSource(source, sourceKind)
    or structuredExternalContentSource(source, sourceKind)
    or networkReceiverParameterSource(source, sourceKind)
  }

  predicate isExternalSource(DataFlow::Node source) {
    exists(string sourceKind | sourceKind(source, sourceKind))
  }

  /** Exact Unity lifecycle phase. Callable/event identity belongs in Context. */
  predicate phase(DataFlow::Node node, string phase) {
    exists(Method lifecycle, string name |
      isUnityLifecycleMethod(lifecycle, name) and
      (node.getEnclosingCallable() = lifecycle or hasCalleeTransitive(lifecycle, node.getEnclosingCallable())) and
      phase = name
    )
    or
    not exists(Method lifecycle, string name |
      isUnityLifecycleMethod(lifecycle, name) and
      (node.getEnclosingCallable() = lifecycle or hasCalleeTransitive(lifecycle, node.getEnclosingCallable()))
    ) and phase = "Unbound"
  }

  predicate objectId(DataFlow::Node node, string objectId) {
    objectId = node.getEnclosingCallable().getDeclaringType().getName() + "#*"
  }

  predicate fieldPath(DataFlow::Node node, string fieldPath) {
    exists(Parameter p |
      node = DataFlow::parameterNode(p) and
      fieldPath = "parameter." + p.getName()
    )
    or
    exists(MethodCall mc |
      node = DataFlow::exprNode(mc) and
      fieldPath = "return." + mc.getTarget().getName()
    )
    or
    exists(PropertyAccess pa |
      node = DataFlow::exprNode(pa) and
      fieldPath = "property." + pa.getTarget().getName()
    )
  }

  predicate context(DataFlow::Node node, string context) {
    exists(Callable c, string p |
      c = node.getEnclosingCallable() and phase(node, p) and
      context = "{\"schema\":\"unity-context/v1\",\"project\":\"UNKNOWN\",\"scene\":\"UNKNOWN\"," +
        "\"game_object\":\"UNKNOWN\",\"component\":\"" + c.getDeclaringType().getName() +
        "#*\",\"script\":\"" + c.getFile().getRelativePath() + "\",\"entry\":\"" + p +
        "\",\"callable\":\"" + c.getName() + "\",\"event\":\"EXTERNAL\"," +
        "\"thread\":\"UNKNOWN\",\"coroutine\":\"UNKNOWN\",\"async\":\"UNKNOWN\"}"
    )
  }
}
