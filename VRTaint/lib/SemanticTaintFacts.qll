/**
 * @name SemanticTaintFacts
 * @description Project-neutral external fact contract for semantic taint seeds.
 */

import csharp
import UnityStandardSourceSink
import UnityExternalInput
import UnityLifecycleBase

external predicate semanticSeedFact(
  string factId,
  string scriptPath,
  string typeName,
  string methodName,
  int parameterIndex,
  string objectId,
  string accessPath,
  string phase,
  string context,
  string sourceKind,
  string influenceKind,
  string confidence
);

external predicate semanticMethodEdgeFact(
  string edgeId,
  string callerScriptPath,
  string callerType,
  string callerMethod,
  int callerParameterIndex,
  string calleeScriptPath,
  string calleeType,
  string calleeMethod,
  int calleeParameterIndex,
  string edgeKind,
  string confidence
);

external predicate semanticExprSeedFact(
  string factId,
  string scriptPath,
  int line,
  string objectId,
  string accessPath,
  string phase,
  string context,
  string sourceKind,
  string influenceKind,
  string confidence
);

module SemanticTaintFacts {
  predicate sameScript(Method method, string scriptPath) {
    scriptPath = method.getFile().getRelativePath()
  }

  /** A lifecycle/event entry from which `node` may execute. This relation may be multi-valued. */
  predicate possibleExecutionPhase(DataFlow::Node node, string phase) {
    exists(Callable current, Method lifecycle, string lifecycleName |
      current = node.getEnclosingCallable() and
      isUnityLifecycleMethod(lifecycle, lifecycleName) and
      (current = lifecycle or hasCalleeTransitive(lifecycle, current)) and
      phase = lifecycleName
    )
  }

  /**
   * Single-valued normalized phase for the five-tuple contract. Direct callbacks
   * are exact; helpers with one reachable entry inherit it; helpers reachable
   * from multiple entries are reported as Ambiguous rather than duplicated.
   */
  predicate executionPhase(DataFlow::Node node, string phase) {
    exists(Method lifecycle, string lifecycleName |
      lifecycle = node.getEnclosingCallable() and
      isUnityLifecycleMethod(lifecycle, lifecycleName) and
      phase = lifecycleName
    )
    or
    (
      not node.getEnclosingCallable() instanceof Method
      or not isUnityLifecycleMethod(node.getEnclosingCallable().(Method), _)
    ) and
    (
      exists(string onlyPhase |
        possibleExecutionPhase(node, onlyPhase) and
        not exists(string otherPhase |
          possibleExecutionPhase(node, otherPhase) and otherPhase != onlyPhase
        ) and
        phase = onlyPhase
      )
      or
      exists(string firstPhase, string secondPhase |
        possibleExecutionPhase(node, firstPhase) and
        possibleExecutionPhase(node, secondPhase) and
        firstPhase != secondPhase and phase = "Ambiguous"
      )
      or
      not possibleExecutionPhase(node, _) and phase = "Unbound"
    )
  }

  private predicate codeSeed(
    DataFlow::Node source,
    string factId,
    string objectId,
    string accessPath,
    string phase,
    string context,
    string sourceKind,
    string influenceKind,
    string confidence
  ) {
    (
      UnityStandardSourceSink::isStandardSourceKind(source, sourceKind)
      or UnityExternalInput::sourceKind(source, sourceKind)
    ) and
    exists(Callable c |
      c = source.getEnclosingCallable() and
      factId = "CODEQL:" + c.getFile().getRelativePath() + ":" +
        source.getLocation().getStartLine().toString() + ":" + sourceKind and
      objectId = c.getDeclaringType().getName() + "#*" and
      accessPath = "source." + sourceKind and
      executionPhase(source, phase) and
      context = "{\"schema\":\"unity-context/v1\",\"project\":\"UNKNOWN\",\"scene\":\"UNKNOWN\"," +
        "\"game_object\":\"UNKNOWN\",\"component\":\"" + c.getDeclaringType().getName() +
        "#*\",\"script\":\"" + c.getFile().getRelativePath() + "\",\"entry\":\"" + phase +
        "\",\"callable\":\"" + c.getName() + "\",\"event\":\"NONE\",\"thread\":\"MainThread\"," +
        "\"coroutine\":\"UNKNOWN\",\"async\":\"UNKNOWN\"}" and
      influenceKind = "data" and confidence = "high"
    )
    or
    exists(string scriptPath, int line, AssignableDefinition def |
      semanticExprSeedFact(factId, scriptPath, line, objectId, accessPath, phase,
                           context, sourceKind, influenceKind, confidence) and
      def.getLocation().getFile().getRelativePath() = scriptPath and
      def.getLocation().getStartLine() = line and
      source = DataFlow::assignableDefinitionNode(def)
    )
    or
    exists(MethodCall call, Expr outValue, Callable c |
      call.getTarget().getName() = "TryGetFeatureValue" and
      outValue = call.getArgument(1) and
      source = DataFlow::exprNode(outValue) and
      c = source.getEnclosingCallable() and
      executionPhase(source, phase) and
      sourceKind = "XRInput" and influenceKind = "data" and confidence = "high" and
      factId = "CODEQL:" + c.getFile().getRelativePath() + ":" +
        source.getLocation().getStartLine().toString() + ":XRInput" and
      objectId = c.getDeclaringType().getName() + "#*" and
      accessPath = "out.value" and
      context = "{\"schema\":\"unity-context/v1\",\"project\":\"UNKNOWN\",\"scene\":\"UNKNOWN\"," +
        "\"game_object\":\"UNKNOWN\",\"component\":\"" + c.getDeclaringType().getName() +
        "#*\",\"script\":\"" + c.getFile().getRelativePath() + "\",\"entry\":\"" + phase +
        "\",\"callable\":\"" + c.getName() + "\",\"event\":\"XRInput\",\"thread\":\"MainThread\"," +
        "\"coroutine\":\"NONE\",\"async\":\"NONE\"}"
    )
  }

  predicate seed(
    DataFlow::Node source,
    string factId,
    string objectId,
    string accessPath,
    string phase,
    string context,
    string sourceKind,
    string influenceKind,
    string confidence
  ) {
    exists(string scriptPath, string typeName, string methodName, int parameterIndex, Method method |
      semanticSeedFact(
        factId, scriptPath, typeName, methodName, parameterIndex, objectId,
        accessPath, phase, context, sourceKind, influenceKind, confidence
      ) and
      sameScript(method, scriptPath) and
      method.getDeclaringType().getName() = typeName and
      method.getName() = methodName and
      parameterIndex >= 0 and
      parameterIndex < method.getNumberOfParameters() and
      source = DataFlow::parameterNode(method.getParameter(parameterIndex))
    )
    or
    codeSeed(source, factId, objectId, accessPath, phase, context,
             sourceKind, influenceKind, confidence)
  }

  predicate isSeed(DataFlow::Node source) {
    exists(string factId, string objectId, string accessPath, string phase,
           string context, string sourceKind, string influenceKind, string confidence |
      seed(source, factId, objectId, accessPath, phase, context,
           sourceKind, influenceKind, confidence)
    )
  }

  predicate isSecurityDataSeed(DataFlow::Node source) {
    exists(string factId, string objectId, string accessPath, string phase,
           string context, string sourceKind, string influenceKind, string confidence |
      seed(source, factId, objectId, accessPath, phase, context,
           sourceKind, influenceKind, confidence) and
      influenceKind = "data" and
      sourceKind != "UnitySerializedConstant"
    )
  }

  predicate isCompatibleSecurityFlow(DataFlow::Node source, DataFlow::Node sink) {
    exists(string sourceKind, string sinkKind |
      UnityStandardSourceSink::isStandardSourceKind(source, sourceKind) and
      UnityStandardSourceSink::isStandardSinkKind(sink, sinkKind) and
      UnityStandardSourceSink::isCompatibleTaintKind(sourceKind, sinkKind)
    )
  }

  predicate isProjectRuntimeNode(DataFlow::Node node) {
    exists(Callable c |
      c = node.getEnclosingCallable() and
      not c.getFile().getRelativePath().matches("%/Editor/%") and
      not c.getFile().getRelativePath().matches("Editor/%") and
      not c.getFile().getRelativePath().matches("%/Tests/%") and
      not c.getFile().getRelativePath().matches("%/Test/%") and
      not c.getFile().getRelativePath().matches("%/Examples/%") and
      not c.getFile().getRelativePath().matches("%/Examples & Extras/%") and
      not c.getFile().getRelativePath().matches("%/SampleFramework/%") and
      not c.getFile().getRelativePath().matches("%/Samples/%")
    )
  }

  predicate methodEdge(DataFlow::Node pred, DataFlow::Node succ) {
    exists(string edgeId, string callerScriptPath, string callerType, string callerMethod,
           int callerParameterIndex, string calleeScriptPath, string calleeType,
           string calleeMethod, int calleeParameterIndex, string edgeKind,
           string confidence, Method caller, Method callee |
      semanticMethodEdgeFact(edgeId, callerScriptPath, callerType, callerMethod,
        callerParameterIndex, calleeScriptPath, calleeType, calleeMethod,
        calleeParameterIndex, edgeKind, confidence) and
      sameScript(caller, callerScriptPath) and caller.getDeclaringType().getName() = callerType and
      caller.getName() = callerMethod and callerParameterIndex >= 0 and
      callerParameterIndex < caller.getNumberOfParameters() and
      sameScript(callee, calleeScriptPath) and callee.getDeclaringType().getName() = calleeType and
      callee.getName() = calleeMethod and calleeParameterIndex >= 0 and
      calleeParameterIndex < callee.getNumberOfParameters() and
      pred = DataFlow::parameterNode(caller.getParameter(callerParameterIndex)) and
      succ = DataFlow::parameterNode(callee.getParameter(calleeParameterIndex))
    )
  }
}
