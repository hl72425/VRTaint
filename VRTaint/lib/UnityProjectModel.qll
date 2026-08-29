/**
 * @name UnityProjectModel
 * @description Project-neutral extension contract for Unity scene/prefab instances,
 *              lifecycle entries, node bindings, object references, and execution order.
 *
 * Project facts are supplied by a generated CodeQL model pack. Empty predicates
 * are valid: callers then use an explicit type-level fallback rather than
 * inventing scene identities.
 */

import csharp

/** A concrete MonoBehaviour/component instance recovered from Unity assets. */
extensible predicate unityComponentInstanceModel(
  string projectId,
  string assetPath,
  string gameObjectId,
  string gameObjectName,
  string componentId,
  string scriptPath,
  string typeName,
  string activeState,
  string confidence
);

/** A verified engine/event entry belonging to a project component type. */
extensible predicate unityLifecycleEntryModel(
  string scriptPath,
  string typeName,
  string methodName,
  string entryKind,
  string confidence
);

/**
 * Optional source/sink/entry binding for a concrete syntax node. This is used
 * when scene configuration proves that only selected component instances can
 * execute the node (for example, a persistent UnityEvent target).
 */
extensible predicate unityNodeInstanceModel(
  string scriptPath,
  int line,
  string role,
  string componentId,
  string objectId,
  string confidence
);

/** A serialized UnityEvent entry method bound to a concrete target component. */
extensible predicate unityEntryInstanceModel(
  string scriptPath,
  string typeName,
  string methodName,
  string componentId,
  string objectId,
  string assetPath,
  string confidence
);

/** A serialized or otherwise proven component-to-component reference. */
extensible predicate unityComponentReferenceModel(
  string ownerComponentId,
  string fieldPath,
  string targetComponentId,
  string confidence
);

/** Script execution order from DefaultExecutionOrder or MonoManager. */
extensible predicate unityExecutionOrderModel(
  string typeName,
  int orderValue,
  string provenance
);

/**
 * Closed-world evidence for a component type's serialized instance set.
 * Merely observing one or more component rows is not coverage evidence.
 * `complete` is accepted only with a provenance that explicitly rules out
 * additional runtime-created instances for the analyzed deployment/fixture.
 */
extensible predicate unityInstanceCoverageModel(
  string scriptPath,
  string typeName,
  string coverage,
  string provenance
);

module ProjectModel {
  predicate hasComponentFacts() {
    unityComponentInstanceModel(_, _, _, _, _, _, _, _, ["high", "medium"])
  }

  predicate hasEntryFacts() { unityLifecycleEntryModel(_, _, _, _, ["high", "medium"]) }

  predicate hasCompleteExactCoverage(string scriptPath, string typeName) {
    unityInstanceCoverageModel(
      scriptPath, typeName, "complete",
      ["verified-no-dynamic-instantiation", "closed-world-build", "test-fixture"]
    )
  }

  predicate hasCompleteExactCoverageForComponent(string componentId) {
    exists(string scriptPath, string typeName |
      exactComponentIdForType(scriptPath, typeName, componentId) and
      hasCompleteExactCoverage(scriptPath, typeName)
    )
  }

  predicate exactComponentIdForType(
    string scriptPath, string typeName, string componentId
  ) {
    unityComponentInstanceModel(
      _, _, _, _, componentId, scriptPath, typeName, _, ["high", "medium"]
    )
  }

  /** Compatibility projection for callers that intentionally ignore script identity. */
  predicate exactComponentIdForType(string typeName, string componentId) {
    exactComponentIdForType(_, typeName, componentId)
  }

  predicate exactObjectIdForComponent(string componentId, string objectId) {
    exists(string assetPath, string gameObjectId |
      unityComponentInstanceModel(
        _, assetPath, gameObjectId, _, componentId, _, _, _, ["high", "medium"]
      ) and
      objectId = "asset:" + assetPath + "|gameObject:" + gameObjectId + "|component:" + componentId
    )
  }

  predicate methodMatchesEntryFact(Method method, string entryKind) {
    exists(string scriptPath, string typeName, string methodName |
      unityLifecycleEntryModel(
        scriptPath, typeName, methodName, entryKind, ["high", "medium"]
      ) and
      method.getFile().getRelativePath() = scriptPath and
      method.getDeclaringType().getName() = typeName and
      method.getName() = methodName
    )
  }

  predicate nodeHasExactBinding(
    DataFlow::Node node, string role, string componentId, string objectId
  ) {
    unityNodeInstanceModel(
      node.getLocation().getFile().getRelativePath(), node.getLocation().getStartLine(), role,
      componentId, objectId, ["high", "medium"]
    )
  }

  predicate entryMethodHasExactBinding(
    Method method, string componentId, string objectId
  ) {
    unityEntryInstanceModel(
      method.getFile().getRelativePath(), method.getDeclaringType().getName(), method.getName(),
      componentId, objectId, _, ["high", "medium"]
    )
  }

  predicate exactNodeBoundComponentId(string componentId) {
    unityNodeInstanceModel(_, _, _, componentId, _, ["high", "medium"])
    or unityEntryInstanceModel(_, _, _, componentId, _, _, ["high", "medium"])
  }

  predicate hasExactNodeBindings() { exactNodeBoundComponentId(_) }

  predicate hasComponentReference(
    string ownerComponentId, string targetComponentId
  ) {
    unityComponentReferenceModel(ownerComponentId, _, targetComponentId, ["high", "medium"])
  }

  predicate hasEventComponentReference(
    string ownerComponentId, string targetComponentId
  ) {
    exists(string eventField |
      unityComponentReferenceModel(
        ownerComponentId, "event:" + eventField, targetComponentId, ["high", "medium"]
      )
    )
  }

  /** A direct serialized field reference suitable for receiver-sensitive call lifting. */
  predicate hasDirectComponentFieldReference(
    string ownerComponentId, string fieldName, string targetComponentId
  ) {
    unityComponentReferenceModel(
      ownerComponentId, fieldName, targetComponentId, ["high", "medium"]
    )
  }

  predicate componentHasType(
    string componentId, string scriptPath, string typeName
  ) {
    exactComponentIdForType(scriptPath, typeName, componentId)
  }

  predicate participatesInComponentReference(string componentId) {
    hasComponentReference(componentId, _)
    or hasComponentReference(_, componentId)
  }
}
