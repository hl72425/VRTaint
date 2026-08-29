/**
 * @name UnitySerializedConfig
 * @description Extension points for Unity scene/prefab serialized metadata.
 *
 * A production deployment should populate these predicates from a Unity YAML
 * extractor or CodeQL data extension. The query library keeps the hook explicit
 * so scene/prefab configuration sensitivity is modeled from facts, not guessed
 * from field names alone.
 */

import csharp
import UnitySensitivityCore
import UnityProjectModel

/**
 * Describes a persistent UnityEvent binding recovered from `.unity` or `.prefab`
 * metadata.
 *
 * Columns:
 * - attachedScriptPath / attachedTypeName: concrete MonoBehaviour script
 *   attached to the serialized component. This is intentionally distinct from
 *   the type that declares the event field: Unity serializes inherited fields
 *   on a derived component without recording the C# declaring type in YAML.
 * - eventFieldName: serialized UnityEvent field/property name.
 * - targetTypeName: C# type that receives the persistent callback.
 * - targetMethodName: callback method name.
 * - parameterIndex: event argument index mapped to the callback parameter.
 */
extensible predicate unitySerializedUnityEventBindingModel(
  string attachedScriptPath,
  string attachedTypeName,
  string ownerComponentId,
  string eventFieldName,
  string targetScriptPath,
  string targetTypeName,
  string targetComponentId,
  string targetMethodName,
  int eventArgumentIndex,
  int callbackParameterIndex,
  string listenerMode,
  string callState,
  string assetPath,
  string confidence
);

/** Source-confirmed `.Invoke(...)` location for a configured event field. */
extensible predicate unitySerializedUnityEventInvocationModel(
  string invocationScriptPath,
  string eventFieldName,
  int invocationLine,
  string provenance
);

private predicate isConfiguredUnityEventDispatch(
  MethodCall invokeCall, FieldAccess eventAccess, string eventFieldName
) {
  invokeCall.getQualifier() = eventAccess and
  eventFieldName = eventAccess.getTarget().getName() and
  (
    invokeCall.getTarget().hasName("Invoke") and
    (
      invokeCall.getTarget().getDeclaringType().getABaseType*().hasFullyQualifiedName(
        "UnityEngine.Events", "UnityEventBase"
      ) or
      invokeCall.getTarget().getDeclaringType().getName().matches("UnityEvent%")
    )
    or
    // none-mode may extract the call syntax but omit its Unity API target.
    // The project-specific source fact distinguishes Invoke from listener setup.
    not exists(invokeCall.getTarget()) and
    unitySerializedUnityEventInvocationModel(
      invokeCall.getFile().getRelativePath(), eventFieldName,
      invokeCall.getLocation().getStartLine(), "source-lexical"
    )
  )
}

predicate isSerializedUnityEventStateStep(
  DataFlow::Node pred, DataFlow::Node succ,
  string boundOwnerComponentId, string boundTargetComponentId
) {
  exists(
    Class attachedClass, FieldAccess eventAccess, MethodCall invokeCall,
    Method targetMethod, int eventArgumentIndex, int callbackParameterIndex,
    string attachedScriptPath, string attachedTypeName, string ownerComponentId,
    string eventFieldName, string targetScriptPath, string targetTypeName,
    string targetComponentId, string targetMethodName, string assetPath
  |
    isConfiguredUnityEventDispatch(invokeCall, eventAccess, eventFieldName) and
    // The model identifies the concrete script attached to the GameObject.
    // Resolve the actual field declaration through CodeQL's C# type hierarchy:
    // the event may be declared directly on that script or on any base class.
    attachedClass.getName() = attachedTypeName and
    attachedClass.getFile().getRelativePath() = attachedScriptPath and
    eventAccess.getTarget().getDeclaringType() = attachedClass.getABaseType*() and
    eventFieldName = eventAccess.getTarget().getName() and
    targetTypeName = targetMethod.getDeclaringType().getName() and
    targetMethodName = targetMethod.getName() and
    unitySerializedUnityEventBindingModel(
      attachedScriptPath, attachedTypeName, ownerComponentId, eventFieldName,
      targetScriptPath, targetTypeName, targetComponentId, targetMethodName,
      eventArgumentIndex, callbackParameterIndex, "dynamic", ["1", "2"], assetPath,
      ["high", "medium"]
    ) and
    (
      targetMethod.getFile().getRelativePath() = targetScriptPath
      or
      targetScriptPath = "@engine/UnityEngine" and
      targetMethod.getDeclaringType().getNamespace().getName() = "UnityEngine"
    ) and
    ProjectModel::hasEventComponentReference(ownerComponentId, targetComponentId) and
    boundOwnerComponentId = ownerComponentId and
    boundTargetComponentId = targetComponentId and
    eventArgumentIndex >= 0 and callbackParameterIndex >= 0 and
    eventArgumentIndex < invokeCall.getNumberOfArguments() and
    callbackParameterIndex < targetMethod.getNumberOfParameters() and
    SensitivityCore::isViableExpr(invokeCall.getArgument(eventArgumentIndex)) and
    pred = DataFlow::exprNode(invokeCall.getArgument(eventArgumentIndex)) and
    succ = DataFlow::parameterNode(targetMethod.getParameter(callbackParameterIndex))
  )
}

predicate isSerializedUnityEventFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
  isSerializedUnityEventStateStep(pred, succ, _, _)
}

