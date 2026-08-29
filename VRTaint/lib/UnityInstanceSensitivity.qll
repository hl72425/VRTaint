/**
 * @name UnityInstanceSensitivity
 * @description Component-instance state lifting for VRTaint.
 *
 * Concrete component IDs come from UnityProjectModel data extensions. When a
 * project/type has no such facts, the analysis uses an explicit type-level
 * fallback state. The fallback is visible in results and never presented as a
 * proven GameObject identity.
 */

import csharp
import UnityLifecycleBase
import UnityProjectModel
import UnitySensitivityCore

module InstanceSensitivity {
  predicate nodeComponentIdentity(
    DataFlow::Node node, string scriptPath, ValueOrRefType type
  ) {
    exists(Callable callable |
      callable = node.getEnclosingCallable() and
      (
        type = callable.getDeclaringType() and
        scriptPath = callable.getFile().getRelativePath() and
        (
          type.getABaseType*().hasFullyQualifiedName("UnityEngine", "MonoBehaviour")
          or ProjectModel::exactComponentIdForType(scriptPath, type.getName(), _)
        )
        or
        exists(Method entry, string entryName |
          isUnityLifecycleMethod(entry, entryName) and
          // Execution context is propagated only across calls that preserve the
          // current component receiver. A call into a field-held helper has a
          // distinct storage identity and is handled by VRTaintInstanceFlow.
          (callable = entry or SensitivityCore::hasContextCallee(entry, callable)) and
          type = entry.getDeclaringType() and
          scriptPath = entry.getFile().getRelativePath()
        )
      )
    )
  }

  predicate nodeComponentType(DataFlow::Node node, ValueOrRefType type) {
    nodeComponentIdentity(node, _, type)
  }

  predicate typeHasExactInstances(string scriptPath, string typeName) {
    ProjectModel::exactComponentIdForType(scriptPath, typeName, _)
  }

  predicate typeHasExactInstances(string typeName) {
    ProjectModel::exactComponentIdForType(_, typeName, _)
  }

  predicate nodeCompatibleWithComponent(DataFlow::Node node, string componentId) {
    exists(ValueOrRefType type, string scriptPath |
      nodeComponentIdentity(node, scriptPath, type) and
      ProjectModel::exactComponentIdForType(scriptPath, type.getName(), componentId)
    )
  }

  /**
   * Closed-world coverage for the node's component type. Exact component rows
   * alone are intentionally insufficient: Unity may create further instances
   * through Instantiate, Addressables, AssetBundles, or other runtime loading.
   */
  predicate nodeHasCompleteExactCoverage(DataFlow::Node node) {
    exists(ValueOrRefType type, string scriptPath |
      nodeComponentIdentity(node, scriptPath, type) and
      ProjectModel::hasCompleteExactCoverage(scriptPath, type.getName()) and
      ProjectModel::exactComponentIdForType(scriptPath, type.getName(), _)
    )
  }

  bindingset[role]
  predicate exactStateForNode(
    DataFlow::Node node, string role, string stateId, string objectId
  ) {
    ProjectModel::nodeHasExactBinding(node, role, stateId, objectId)
    or
    role in ["source", "sink", "flow"] and
    exists(Method entry, Callable current |
      current = node.getEnclosingCallable() and
      ProjectModel::entryMethodHasExactBinding(entry, stateId, objectId) and
      (current = entry or SensitivityCore::hasContextCallee(entry, current))
    )
  }

  /**
   * May-binding derived from a concrete serialized component reference. Unlike
   * an exact Inspector entry binding, this does not suppress GLOBAL fallback.
   */
  predicate referenceStateForNode(
    DataFlow::Node node, string stateId, string objectId
  ) {
    exists(string scriptPath, ValueOrRefType type |
      nodeComponentIdentity(node, scriptPath, type) and
      ProjectModel::exactComponentIdForType(scriptPath, type.getName(), stateId) and
      ProjectModel::participatesInComponentReference(stateId) and
      ProjectModel::exactObjectIdForComponent(stateId, objectId)
    )
  }

  /**
   * Binds a node to a component state. Exact bindings suppress broader type and
   * GLOBAL fallback only when an independent closed-world coverage fact proves
   * that the recovered instance set is complete.
   */
  bindingset[role]
  predicate nodeMayExecuteOn(DataFlow::Node node, string role, string stateId) {
    exists(string objectId | exactStateForNode(node, role, stateId, objectId))
    or
    exists(string objectId |
      referenceStateForNode(node, stateId, objectId) and
      (
        not nodeHasCompleteExactCoverage(node)
        or not exists(string exactState, string exactObject |
          exactStateForNode(node, role, exactState, exactObject)
        )
        or exactStateForNode(node, role, stateId, _)
      )
    )
    or
    (
      not exists(string boundState, string objectId |
        exactStateForNode(node, role, boundState, objectId)
      )
      or not nodeHasCompleteExactCoverage(node)
    ) and
    exists(ValueOrRefType type, string scriptPath |
      nodeComponentIdentity(node, scriptPath, type) and
      ProjectModel::exactNodeBoundComponentId(stateId) and
      ProjectModel::exactComponentIdForType(scriptPath, type.getName(), stateId)
    )
    or
    stateId = "GLOBAL" and not nodeHasCompleteExactCoverage(node)
  }

  bindingset[stateId]
  predicate objectIdForState(string stateId, string objectId) {
    ProjectModel::exactObjectIdForComponent(stateId, objectId)
    or stateId = "GLOBAL" and objectId = "GLOBAL"
  }
}
