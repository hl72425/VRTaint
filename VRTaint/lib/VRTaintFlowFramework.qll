/**
 * @name VRTaintFlowFramework
 * @description Parameterized analysis framework for Unity MonoBehaviour lifecycle taint tracking.
 *              Query files implement ProjectConfigSig to supply project-specific sources/sinks/barriers,
 *              then instantiate VRTaintFlow to obtain a complete DataFlow::ConfigSig.
 */

import csharp
import UnityLifecycleBase
import UnityStationSkipping
import UnityCodeEventFlow
import UnityAsynchronousFlow
import UnitySensitivityCore
import UnityOwnedObjectFlow
import UnityInstanceSensitivity
import UnityProjectModel

// ============================================================================
// Compatibility helpers for the restored ORIGINAL lifecycle model.
//
// UnityLifecycleBase.qll / UnityStationSkipping.qll have been restored to the
// initial (pre-hardening) version, which does not define the may-reach / kill
// helpers that the flow routes below consume. These helpers re-express that
// contract on top of the original primitives so the rest of the framework
// (sanitization, instance flow, ownership, async, code-event routes) keeps
// compiling and working unchanged.
// ============================================================================

/** Same component implementation (exact type or base-derived). */
predicate isSameComponentImplementation(Method first, Method second) {
  first.getDeclaringType() = second.getDeclaringType()
  or first.getDeclaringType().getABaseType*() = second.getDeclaringType()
  or second.getDeclaringType().getABaseType*() = first.getDeclaringType()
}

/**
 * Deterministic intermediate phase used only for must-kill reasoning:
 * a callback that must occur between two named callback observations.
 */
bindingset[beforeName, middleName, afterName]
predicate mustBetweenLifecycle(
  string beforeName, string middleName, string afterName
) {
  lifecycleMustBetween(beforeName, middleName, afterName)
}

/** Single lifecycle station step under the restored (adjacent) station model. */
private predicate lifecycleStationStep(Method before, Method after) {
  exists(string beforeName, string afterName |
    isSameComponentImplementation(before, after) and
    isUnityLifecycleMethod(before, beforeName) and
    isUnityLifecycleMethod(after, afterName) and
    lifecycleOrder(beforeName, afterName) and
    not exists(Method middle, string middleName |
      middle.fromSource() and
      middle != before and middle != after and
      isSameComponentImplementation(before, middle) and
      isUnityLifecycleMethod(middle, middleName) and
      lifecycleOrder(beforeName, middleName) and
      lifecycleOrder(middleName, afterName)
    )
  )
}

/** Direct may-edges that cross a frame/tick boundary or a re-enable cycle. */
private predicate lifecycleCrossFrameStep(Method before, Method after) {
  exists(string beforeName, string afterName |
    isSameComponentImplementation(before, after) and
    isUnityLifecycleMethod(before, beforeName) and
    isUnityLifecycleMethod(after, afterName) and
    (
      beforeName = "LateUpdate" and afterName = "Update"
      or beforeName = "Update" and afterName = "FixedUpdate"
      or beforeName = "OnDisable" and afterName = "OnEnable"
      or conditionalLifecycleEventMayFollow(beforeName, afterName)
    )
  )
}

/** One direct may-step, including ordinary stations and frame/re-enable edges. */
private predicate lifecycleMayStep(Method before, Method after) {
  lifecycleStationStep(before, after) or lifecycleCrossFrameStep(before, after)
}

/** Closure over the union, so station and cross-frame steps compose. */
predicate isLifecycleMayReach(Method before, Method after) {
  lifecycleMayStep+(before, after)
}

/** Named variant of may-reachability. */
predicate isLifecycleMayReach(
  Method before, Method after, string beforeName, string afterName
) {
  isUnityLifecycleMethod(before, beforeName) and
  isUnityLifecycleMethod(after, afterName) and
  isLifecycleMayReach(before, after)
}

/**
 * Project-specific configuration signature.
 * Each query file implements this module to define its own sources, sinks, barriers,
 * and any extra flow steps not covered by the framework.
 */
signature module ProjectConfigSig {
  predicate isSource(DataFlow::Node source);
  predicate isSink(DataFlow::Node sink);
  predicate isBarrier(DataFlow::Node node);
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ);
}

/**
 * Parameterized taint-tracking configuration for Unity MonoBehaviour lifecycle analysis.
 *
 * Usage from a query file:
 *   module MyConfig implements ProjectConfigSig { ... }
 *   module Flow = VRTaintFlow<MyConfig>;
 *   module Tracking = TaintTracking::Global<Flow>;
 *   import Tracking::PathGraph
 *   from Tracking::PathNode source, Tracking::PathNode sink
 *   where Tracking::flowPath(source, sink)
 *   select ...
 */
module VRTaintFlow<ProjectConfigSig Cfg> implements DataFlow::ConfigSig {

  predicate isSource = Cfg::isSource/1;
  predicate isSink = Cfg::isSink/1;
  predicate isBarrier = Cfg::isBarrier/1;

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // ---------------- ROUTE 1: CROSS-LIFECYCLE STATE PERSISTENCE FIELD FLOW ----------------
    exists(Method m1, Method m2, string n1, string n2, Field f, 
           FieldWrite writeExpr, FieldRead readExpr, Expr rhs |
        
        isLifecycleMayReach(m1, m2, n1, n2) and

        // Route 1 models persistent state declared by the component itself.
        // Fields of plain helper objects reached through calls belong to Route 3,
        // where the owning component field and helper-state kill are correlated.
        f.getDeclaringType().getABaseType*().hasFullyQualifiedName("UnityEngine", "MonoBehaviour") and
        
        writeExpr.getTarget() = f and 
        (
          (
            (writeExpr.getEnclosingCallable() = m1 or
             SensitivityCore::hasContextCallee(m1, writeExpr.getEnclosingCallable())) and
            (
              exists(AssignExpr assign | assign.getLeftOperand() = writeExpr and rhs = assign.getRightOperand())
              or
              rhs = writeExpr.getParent().(Expr)
            )
          )
          or
          exists(MethodCall mc, Parameter outParam, int index, VariableWrite actualWrite, Expr subRhs |
            (mc.getEnclosingCallable() = m1 or
             SensitivityCore::hasContextCallee(m1, mc.getEnclosingCallable())) and
            mc.getArgument(index) = writeExpr and
            outParam = mc.getTarget().getParameter(index) and
            (outParam.isOut() or outParam.isRef()) and
            actualWrite.getTarget() = outParam and
            actualWrite.getEnclosingCallable() = mc.getTarget() and
            (
              exists(AssignExpr subAssign | subAssign.getLeftOperand() = actualWrite and subRhs = subAssign.getRightOperand())
              or
              subRhs = actualWrite.getParent().(Expr)
            ) and
            rhs = subRhs
          )
        ) and
        SensitivityCore::isViableExpr(rhs) and
        
        pred = DataFlow::exprNode(rhs) and 

        readExpr.getTarget() = f and 
        SensitivityCore::isReceiverCompatibleFieldFlow(writeExpr, readExpr) and
        SensitivityCore::isViableExpr(readExpr) and
        (readExpr.getEnclosingCallable() = m2 or
         SensitivityCore::hasContextCallee(m2, readExpr.getEnclosingCallable())) and
        succ = DataFlow::exprNode(readExpr) and
        
        not isSanitizedAtExitGate(m1, f, writeExpr) and
        not isSanitizedAtEntryGate(m2, f, readExpr) and
        not hasCleanOverwriteBeforeRead(m2, f, readExpr) and
        // Definite direct kill in a deterministic intermediate phase. This is
        // deliberately correlated with the already-bound Route 1 candidate;
        // materializing a project-wide method triple caused severe tuple growth.
        not exists(
          Method middle, string middleName,
          FieldWrite middleOverwrite, AssignExpr middleAssign
        |
          isSameComponentImplementation(m1, middle) and
          isSameComponentImplementation(middle, m2) and
          isUnityLifecycleMethod(middle, middleName) and
          mustBetweenLifecycle(n1, middleName, n2) and
          middleOverwrite.getEnclosingCallable() = middle and
          SensitivityCore::isReceiverCompatible(writeExpr, middleOverwrite) and
          isCleanDefinition(f, middleOverwrite, middleAssign) and
          middleOverwrite.getAControlFlowNode().postDominates(middle.getEntryPoint()) and
          isStableAfter(f, middleOverwrite)
        )
    )

    // ---------------- ROUTE 2: INDEX-SENSITIVE ARRAY/COLLECTION SLOT FLOW ----------------
    or SensitivityCore::isIndexSensitiveElementFlow(pred, succ)

    // ---------------- ROUTE 3: OWNERSHIP-SENSITIVE HELPER OBJECT FIELD FLOW ----------------
    or isOwnedObjectFlowStep(pred, succ)
    
    // ---------------- ROUTE 4: DECOUPLED UNITYEVENT SUBSCRIPTION STEP ----------------
    or isUnityEventFlowStep(pred, succ)

    // ---------------- ROUTE 5: ASYNCHRONOUS STRING CALLBACK ROUTING STEP ----------------
    or isAsynchronousFlowStep(pred, succ)

    // ---------------- ROUTE 6: EXPLICIT METADATA/REFLECTION RESOLUTION ----------------
    or exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("System", "Type", "GetType") and
      SensitivityCore::isViableExpr(mc.getArgument(0)) and
      pred = DataFlow::exprNode(mc.getArgument(0)) and
      succ = DataFlow::exprNode(mc)
    )
    
    // ---------------- ROUTE 7: STRUCT CONSTRUCTOR PROPAGATION ----------------
    or exists(ObjectCreation oc, DataFlow::Node argumentNode |
      argumentNode = DataFlow::exprNode(oc.getAnArgument()) and
      SensitivityCore::isViableExpr(oc.getAnArgument()) and
      (
        pred = argumentNode
        or
        pred.asExpr() = oc.getAnArgument().getAChildExpr*()
      ) and
      succ = DataFlow::exprNode(oc)
    )

    // ---------------- ROUTE 8: PRIMITIVE PARSE/CONVERSION BYPASS ----------------
    or exists(MethodCall mc, Method m, string typeName |
      m = mc.getTarget() and
      m.isStatic() and
      m.getDeclaringType().getNamespace().hasName("System") and
      typeName = m.getDeclaringType().getName() and
      typeName in [
        "Single", "Double", "Int32", "Int64", "Int16", 
        "UInt32", "UInt64", "Byte", "Boolean", "Char", "Decimal"
      ] and
      (
        m.getName() in ["Parse", "TryParse"]
        or
        (m.getDeclaringType().getName() = "Convert" and m.getName().matches("To%"))
      )
      |
      pred = DataFlow::exprNode(mc.getArgument(0)) and
      SensitivityCore::isViableExpr(mc.getArgument(0)) and
      (
        succ = DataFlow::exprNode(mc)
        or
        exists(Parameter outParam, int outIndex |
          m.getParameter(outIndex) = outParam and
          outParam.isOut() and
          outIndex < mc.getNumberOfArguments() and
          (
            succ = DataFlow::parameterNode(outParam)
            or succ = DataFlow::exprNode(mc.getArgument(outIndex))
            or
            // Roslyn/CodeQL represents an inline declaration (`out int x`) as
            // a LocalVariableDeclExpr. It is not always returned by
            // MethodCall.getArgument(outIndex), so connect the converted value
            // to reads of that exact declared local.
            exists(LocalVariableDeclExpr decl, LocalVariableRead read |
              decl.getParent*() = mc and
              decl.getVariable() = read.getTarget() and
              succ = DataFlow::exprNode(read)
            )
          )
        )
      )
    )

    // Primitive value formatting preserves information (for example a tainted
    // `int` parsed from UI input and then passed as `value.ToString()`).
    or exists(MethodCall mc, Method m, Expr qualifier, string typeName |
      m = mc.getTarget() and
      not m.isStatic() and
      m.getName() = "ToString" and
      mc.getNumberOfArguments() = 0 and
      qualifier = mc.getQualifier() and
      m.getDeclaringType().getNamespace().hasName("System") and
      typeName = m.getDeclaringType().getName() and
      typeName in [
        "Single", "Double", "Int32", "Int64", "Int16",
        "UInt32", "UInt64", "Byte", "SByte", "Boolean", "Char", "Decimal"
      ] and
      pred = DataFlow::exprNode(qualifier) and
      succ = DataFlow::exprNode(mc)
    )

    // ---------------- ROUTE 9: PROJECT-SPECIFIC FLOW OVERRIDES (DELEGATED) ----------------
    or Cfg::isAdditionalFlowStep(pred, succ)
  }

  // =========================== SANITIZATION PREDICATES ===========================

  /**
   * Syntactic strong-update boundary used by the stateless core. Static fields
   * and fields of the current `this` receiver have a stable storage identity.
   * Writes through an arbitrary object expression remain may-updates and never
   * justify a definite lifecycle kill. VRTaintInstanceFlow further refines the
   * current receiver with configuration-derived component IDs.
   */
  private predicate isStrongUpdate(FieldWrite overwrite) {
    overwrite.getTarget().isStatic()
    or
    not overwrite.getTarget().isStatic() and
    SensitivityCore::isImplicitThisReceiver(
      overwrite.getQualifier(), overwrite.getEnclosingCallable().getDeclaringType()
    )
  }

  /**
   * A definite clean definition of the target field.
   *
   * Query barriers remain valid sanitizer evidence.  Intrinsically clean
   * replacement values (literal/default/const) are modeled separately because
   * a strong field update is a state kill, not merely a node-level barrier.
   */
  private predicate isCleanDefinition(
    Field f, FieldWrite overwrite, AssignExpr overwriteAssign
  ) {
    overwrite.getTarget() = f and
    overwriteAssign.getLeftOperand() = overwrite and
    isStrongUpdate(overwrite) and
    (
      Cfg::isBarrier(DataFlow::exprNode(overwriteAssign.getRightOperand()))
      or SensitivityCore::isDefinitelyCleanDefinitionExpr(overwriteAssign.getRightOperand())
    ) and
    SensitivityCore::isViableExpr(overwriteAssign.getRightOperand())
  }

  /** No later write may undo a candidate must-kill before normal return. */
  private predicate isStableAfter(Field f, FieldWrite overwrite) {
    not exists(FieldWrite laterWrite |
      laterWrite.getTarget() = f and
      laterWrite.getEnclosingCallable() = overwrite.getEnclosingCallable() and
      SensitivityCore::isReceiverCompatible(overwrite, laterWrite) and
      overwrite.getAControlFlowNode().getASuccessor+() = laterWrite.getAControlFlowNode()
    )
  }

  /** Direct all-normal-return clean kill summary. */
  private predicate hasDirectCleanOnReturn(Callable callable, Field f) {
    exists(FieldWrite overwrite, AssignExpr overwriteAssign |
      overwrite.getEnclosingCallable() = callable and
      isCleanDefinition(f, overwrite, overwriteAssign) and
      overwrite.getAControlFlowNode().postDominates(callable.getEntryPoint()) and
      isStableAfter(f, overwrite)
    )
  }

  /**
   * Least-fixed-point interprocedural must-kill summary.
   *
   * The base case is a clean field definition that post-dominates the callable
   * entry and is not subsequently redefined. The recursive case lifts such a
   * summary through a context-preserving call only when the call itself
   * post-dominates the caller entry and no later caller write can invalidate the
   * kill. Since every derivation must bottom out in the direct base case, a call
   * cycle without a proven clean write cannot manufacture a must-kill fact.
   */
  private predicate isCleanOnReturn(Callable callable, Field f) {
    hasDirectCleanOnReturn(callable, f)
    or
    exists(Call call, Callable callee |
      call.getEnclosingCallable() = callable and
      SensitivityCore::isContextPreservingCall(call, callee) and
      call.getAControlFlowNode().postDominates(callable.getEntryPoint()) and
      isCleanOnReturn(callee, f) and
      not exists(FieldWrite laterWrite |
        laterWrite.getTarget() = f and
        laterWrite.getEnclosingCallable() = callable and
        call.getAControlFlowNode().getASuccessor+() = laterWrite.getAControlFlowNode()
      )
    )
  }

  /**
   * A clean strong update in an entry helper can protect a read performed by a
   * descendant helper before that entry chain returns.  The overwrite must
   * dominate the exact dispatch that reaches the read-side callable, and no
   * compatible write may intervene.  This is deliberately call-chain scoped;
   * an unrelated clean helper in the same component is not sufficient.
   */
  private predicate hasCleanOverwriteBeforeDescendantRead(
    Method entry, Field f, FieldRead readExpr
  ) {
    exists(
      Callable cleanHost, FieldWrite overwrite, AssignExpr overwriteAssign,
      Call readDispatch, Callable readRoot
    |
      (cleanHost = entry or SensitivityCore::hasContextCallee(entry, cleanHost)) and
      overwrite.getEnclosingCallable() = cleanHost and
      isCleanDefinition(f, overwrite, overwriteAssign) and
      SensitivityCore::isReceiverCompatible(overwrite, readExpr) and

      readDispatch.getEnclosingCallable() = cleanHost and
      SensitivityCore::isContextPreservingCall(readDispatch, readRoot) and
      (
        readExpr.getEnclosingCallable() = readRoot
        or SensitivityCore::hasContextCallee(readRoot, readExpr.getEnclosingCallable())
      ) and

      overwrite.getAControlFlowNode().dominates(readDispatch.getAControlFlowNode()) and
      not exists(FieldWrite laterWrite |
        laterWrite.getTarget() = f and
        laterWrite.getEnclosingCallable() = cleanHost and
        SensitivityCore::isReceiverCompatible(laterWrite, readExpr) and
        overwrite.getAControlFlowNode().getASuccessor+() = laterWrite.getAControlFlowNode() and
        (
          laterWrite.getLocation().getStartLine() < readDispatch.getLocation().getStartLine()
          or
          laterWrite.getLocation().getStartLine() = readDispatch.getLocation().getStartLine() and
          laterWrite.getLocation().getStartColumn() <= readDispatch.getLocation().getStartColumn()
        )
      )
    )
  }

  /** Exit kill requires true post-dominance of the tainted write. */
  private predicate isSanitizedAtExitGate(Method m1, Field f, FieldWrite writeExpr) {
    exists(FieldWrite overwrite, AssignExpr overwriteAssign |
      overwrite.getEnclosingCallable() = m1 and
      isCleanDefinition(f, overwrite, overwriteAssign) and
      SensitivityCore::isReceiverCompatible(writeExpr, overwrite) and
      overwrite.getAControlFlowNode().postDominates(writeExpr.getAControlFlowNode()) and
      isStableAfter(f, overwrite)
    )
    or
    exists(Call call, Callable callee |
      call.getEnclosingCallable() = m1 and
      SensitivityCore::isContextPreservingCall(call, callee) and
      call.getAControlFlowNode().postDominates(writeExpr.getAControlFlowNode()) and
      isCleanOnReturn(callee, f) and
      not exists(FieldWrite laterWrite |
        laterWrite.getTarget() = f and
        laterWrite.getEnclosingCallable() = m1 and
        call.getAControlFlowNode().getASuccessor+() = laterWrite.getAControlFlowNode()
      )
    )
  }

  /** Entry kill requires dominance of the read and a clean last definition. */
  private predicate isSanitizedAtEntryGate(Method m2, Field f, FieldRead readExpr) {
    exists(FieldWrite overwrite, AssignExpr overwriteAssign |
      overwrite.getEnclosingCallable() = m2 and
      isCleanDefinition(f, overwrite, overwriteAssign) and
      SensitivityCore::isReceiverCompatible(overwrite, readExpr) and
      overwrite.getAControlFlowNode().dominates(readExpr.getAControlFlowNode()) and
      not exists(FieldWrite laterWrite |
        laterWrite.getTarget() = f and
        laterWrite.getEnclosingCallable() = m2 and
        SensitivityCore::isReceiverCompatible(laterWrite, readExpr) and
        overwrite.getAControlFlowNode().getASuccessor+() = laterWrite.getAControlFlowNode() and
        (
          laterWrite.getLocation().getStartLine() < readExpr.getLocation().getStartLine()
          or
          laterWrite.getLocation().getStartLine() = readExpr.getLocation().getStartLine() and
          laterWrite.getLocation().getStartColumn() <= readExpr.getLocation().getStartColumn()
        )
      )
    )
    or
    exists(Call call, Callable callee |
      call.getEnclosingCallable() = m2 and
      SensitivityCore::isContextPreservingCall(call, callee) and
      call.getAControlFlowNode().dominates(readExpr.getAControlFlowNode()) and
      isCleanOnReturn(callee, f) and
      not exists(FieldWrite laterWrite |
        laterWrite.getTarget() = f and
        laterWrite.getEnclosingCallable() = m2 and
        call.getAControlFlowNode().getASuccessor+() = laterWrite.getAControlFlowNode() and
        (
          laterWrite.getLocation().getStartLine() < readExpr.getLocation().getStartLine()
          or
          laterWrite.getLocation().getStartLine() = readExpr.getLocation().getStartLine() and
          laterWrite.getLocation().getStartColumn() <= readExpr.getLocation().getStartColumn()
        )
      )
    )
    or hasCleanOverwriteBeforeDescendantRead(m2, f, readExpr)
  }

  /**
   * Direct same-entry overwrite guard: if the read-side lifecycle station writes
   * a barrier/literal value into the same field before reading it, stale taint from
   * an earlier station or scene should not survive into the read.
   */
  private predicate hasCleanOverwriteBeforeRead(Method m2, Field f, FieldRead readExpr) {
    isSanitizedAtEntryGate(m2, f, readExpr)
  }

}

/**
 * Component-instance-sensitive lifting of the same VRTaint core. Normal CodeQL
 * flow preserves the state automatically; VRTaint additional edges are admitted
 * only when both endpoints can execute on the same concrete component state.
 */
module VRTaintInstanceFlow<ProjectConfigSig Cfg> implements DataFlow::StateConfigSig {
  private module Core = VRTaintFlow<Cfg>;

  /** A concrete component instance owns one abstract storage per helper field. */
  private predicate componentOwnsHelperField(string componentId, Field ownerField) {
    exists(Class attachedClass, string scriptPath, string typeName |
      ProjectModel::componentHasType(componentId, scriptPath, typeName) and
      attachedClass.getName() = typeName and
      attachedClass.getFile().getRelativePath() = scriptPath and
      ownerField.getDeclaringType() = attachedClass.getABaseType*() and
      isOwnedHelperObjectField(ownerField)
    )
  }

  bindingset[componentId, ownerField]
  private string ownedHelperStorageState(string componentId, Field ownerField) {
    result = "STORAGE|owner=" + componentId + "|field=" +
      ownerField.getDeclaringType().getName() + "." + ownerField.getName()
  }

  /**
   * Storage identity is derived from the receiver field and its concrete owner,
   * not from whichever lifecycle callback happened to execute the helper code.
   */
  private predicate nodeMayUseOwnedHelperStorage(
    DataFlow::Node node, string stateId, string ownerComponentId
  ) {
    exists(
      Field ownerField, MethodCall call, Method target, Callable current
    |
      current = node.getEnclosingCallable() and
      isOwnedHelperCall(call, ownerField) and
      target = call.getTarget() and
      (current = target or SensitivityCore::hasContextCallee(target, current)) and
      componentOwnsHelperField(ownerComponentId, ownerField) and
      stateId = ownedHelperStorageState(ownerComponentId, ownerField)
    )
  }

  private predicate nodeHasOwnedHelperStorage(DataFlow::Node node) {
    nodeMayUseOwnedHelperStorage(node, _, _)
  }

  private predicate ownedHelperStorageCoverageComplete(DataFlow::Node node) {
    nodeHasOwnedHelperStorage(node) and
    not exists(string stateId, string ownerComponentId |
      nodeMayUseOwnedHelperStorage(node, stateId, ownerComponentId) and
      not ProjectModel::hasCompleteExactCoverageForComponent(ownerComponentId)
    )
  }

  bindingset[role]
  private predicate nodeMayExecuteInState(
    DataFlow::Node node, string role, string stateId
  ) {
    not nodeHasOwnedHelperStorage(node) and
    InstanceSensitivity::nodeMayExecuteOn(node, role, stateId)
    or
    role in ["source", "sink", "flow"] and
    exists(string ownerComponentId |
      nodeMayUseOwnedHelperStorage(node, stateId, ownerComponentId) and
      (
        not ownedHelperStorageCoverageComplete(node)
        or not exists(string exactComponentId, string objectId |
          InstanceSensitivity::exactStateForNode(node, role, exactComponentId, objectId)
        )
        or InstanceSensitivity::exactStateForNode(node, role, ownerComponentId, _)
      )
    )
    or
    role in ["source", "sink", "flow"] and stateId = "GLOBAL" and
    nodeHasOwnedHelperStorage(node) and
    not ownedHelperStorageCoverageComplete(node)
  }

  class FlowState extends string {
    FlowState() {
      exists(DataFlow::Node node, string role, string objectId |
        (
          Cfg::isSource(node) and role = "source"
          or Cfg::isSink(node) and role = "sink"
        ) and
        InstanceSensitivity::exactStateForNode(node, role, this, objectId)
      )
      or
      exists(DataFlow::Node node, string objectId |
        (Cfg::isSource(node) or Cfg::isSink(node)) and
        InstanceSensitivity::referenceStateForNode(node, this, objectId)
      )
      or
      exists(string ownerComponentId, Field ownerField |
        componentOwnsHelperField(ownerComponentId, ownerField) and
        this = ownedHelperStorageState(ownerComponentId, ownerField)
      )
      or
      // Serialized owner/target component states may be intermediate states even
      // when neither endpoint is itself a query source or sink.
      ProjectModel::participatesInComponentReference(this)
      or
      this = "GLOBAL"
    }

    string getComponentId() { result = this }

    string getObjectId() {
      InstanceSensitivity::objectIdForState(this, result)
    }

    string toString() { result = this }
  }

  predicate isSource(DataFlow::Node source, FlowState state) {
    Cfg::isSource(source) and
    nodeMayExecuteInState(source, "source", state.getComponentId())
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    Cfg::isSink(sink) and
    nodeMayExecuteInState(sink, "sink", state.getComponentId())
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    exists(state) and Cfg::isBarrier(node)
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node pred, FlowState state1, DataFlow::Node succ, FlowState state2
  ) {
    Core::isAdditionalFlowStep(pred, succ) and
    state1 = state2 and
    nodeMayExecuteInState(pred, "flow", state1.getComponentId()) and
    nodeMayExecuteInState(succ, "flow", state2.getComponentId())
    or
    ownedHelperCallStateStep(
      pred, succ, state1.getComponentId(), state2.getComponentId()
    )
    or
    serializedReferenceCallStep(
      pred, succ, state1.getComponentId(), state2.getComponentId()
    )
    or
    serializedTargetPersistenceStep(
      pred, succ, state1.getComponentId(), state2.getComponentId()
    )
    or
    ownedHelperReturnStateStep(
      pred, succ, state1.getComponentId(), state2.getComponentId()
    )
    or
    serializedReferenceReturnStateStep(
      pred, succ, state1.getComponentId(), state2.getComponentId()
    )
    or
    serializedUnityEventStateStep(
      pred, succ, state1.getComponentId(), state2.getComponentId()
    )
    or
    staticFieldSharedStateStep(
      pred, succ, state1.getComponentId(), state2.getComponentId()
    )
  }

  /**
   * Enter a field-owned helper using its storage state. Normal CodeQL argument
   * flow remains responsible for value propagation; this edge changes only the
   * state dimension from execution component to owned storage.
   */
  private predicate ownedHelperCallStateStep(
    DataFlow::Node pred, DataFlow::Node succ,
    string ownerComponentId, string storageStateId
  ) {
    exists(MethodCall call, Field ownerField, int index |
      isOwnedHelperCall(call, ownerField) and
      index < call.getNumberOfArguments() and
      index < call.getTarget().getNumberOfParameters() and
      pred = DataFlow::exprNode(call.getArgument(index)) and
      succ = DataFlow::parameterNode(call.getTarget().getParameter(index)) and
      componentOwnsHelperField(ownerComponentId, ownerField) and
      storageStateId = ownedHelperStorageState(ownerComponentId, ownerField)
    )
  }

  /**
   * Replay an argument-to-parameter edge only to change component state when
   * the call receiver is a direct serialized field with a concrete binding.
   */
  private predicate serializedReferenceCallStep(
    DataFlow::Node pred, DataFlow::Node succ,
    string ownerComponentId, string targetComponentId
  ) {
    exists(MethodCall call, FieldAccess receiver, Field field, int index,
           Class ownerClass, Class targetClass,
           string ownerScript, string ownerType, string targetScript, string targetType |
      call.getQualifier() = receiver and
      receiver.getTarget() = field and
      pred = DataFlow::exprNode(call.getArgument(index)) and
      succ = DataFlow::parameterNode(call.getTarget().getParameter(index)) and
      ProjectModel::componentHasType(ownerComponentId, ownerScript, ownerType) and
      ownerClass.getName() = ownerType and ownerClass.getFile().getRelativePath() = ownerScript and
      field.getDeclaringType() = ownerClass.getABaseType*() and
      ProjectModel::hasDirectComponentFieldReference(
        ownerComponentId, field.getName(), targetComponentId
      ) and
      ProjectModel::componentHasType(targetComponentId, targetScript, targetType) and
      targetClass.getName() = targetType and targetClass.getFile().getRelativePath() = targetScript and
      call.getTarget().getDeclaringType() = targetClass.getABaseType*() and
      ownerComponentId != targetComponentId
    )
  }

  /**
   * Persistent state inside a concretely referenced serialized target. The
   * owner lifecycle supplies temporal order, while the target CID supplies
   * storage identity; the two concepts are intentionally kept separate.
   */
  private predicate serializedTargetPersistenceStep(
    DataFlow::Node pred, DataFlow::Node succ,
    string beforeState, string afterState
  ) {
    exists(
      string ownerComponentId, string targetComponentId,
      string ownerScript, string ownerType, string targetScript, string targetType,
      Class ownerClass, Class targetClass, Field ownerField,
      FieldAccess storeReceiver, FieldAccess readReceiver,
      MethodCall storeCall, MethodCall readCall,
      Method storeLifecycle, Method readLifecycle,
      FieldWrite write, FieldRead read, AssignExpr assign
    |
      beforeState = targetComponentId and afterState = targetComponentId and
      ProjectModel::componentHasType(ownerComponentId, ownerScript, ownerType) and
      ProjectModel::componentHasType(targetComponentId, targetScript, targetType) and
      ownerClass.getName() = ownerType and ownerClass.getFile().getRelativePath() = ownerScript and
      targetClass.getName() = targetType and targetClass.getFile().getRelativePath() = targetScript and
      ownerField.getDeclaringType() = ownerClass.getABaseType*() and
      ProjectModel::hasDirectComponentFieldReference(
        ownerComponentId, ownerField.getName(), targetComponentId
      ) and
      storeCall.getQualifier() = storeReceiver and storeReceiver.getTarget() = ownerField and
      readCall.getQualifier() = readReceiver and readReceiver.getTarget() = ownerField and
      storeCall.getTarget().getDeclaringType() = targetClass.getABaseType*() and
      readCall.getTarget().getDeclaringType() = targetClass.getABaseType*() and
      (write.getEnclosingCallable() = storeCall.getTarget() or
       SensitivityCore::hasContextCallee(storeCall.getTarget(), write.getEnclosingCallable())) and
      (read.getEnclosingCallable() = readCall.getTarget() or
       SensitivityCore::hasContextCallee(readCall.getTarget(), read.getEnclosingCallable())) and
      assign.getLeftOperand() = write and
      write.getTarget().getDeclaringType() = targetClass.getABaseType*() and
      SensitivityCore::isReceiverCompatibleFieldFlow(write, read) and
      pred = DataFlow::exprNode(assign.getRightOperand()) and
      succ = DataFlow::exprNode(read) and
      not SensitivityCore::isCleanFieldReadAfterBarrierWrite(succ) and
      (storeCall.getEnclosingCallable() = storeLifecycle or
       SensitivityCore::hasContextCallee(storeLifecycle, storeCall.getEnclosingCallable())) and
      (readCall.getEnclosingCallable() = readLifecycle or
       SensitivityCore::hasContextCallee(readLifecycle, readCall.getEnclosingCallable())) and
      isLifecycleMayReach(storeLifecycle, readLifecycle)
    )
  }

  /** Return from field-owned helper storage to its concrete owning component. */
  private predicate ownedHelperReturnStateStep(
    DataFlow::Node pred, DataFlow::Node succ,
    string storageStateId, string ownerComponentId
  ) {
    exists(MethodCall call, Field ownerField, ReturnStmt ret |
      isOwnedHelperCall(call, ownerField) and
      ret.getEnclosingCallable() = call.getTarget() and
      pred = DataFlow::exprNode(ret.getExpr()) and
      succ = DataFlow::exprNode(call) and
      componentOwnsHelperField(ownerComponentId, ownerField) and
      storageStateId = ownedHelperStorageState(ownerComponentId, ownerField)
    )
  }

  /** Return from a concretely serialized target object to the owner call site. */
  private predicate serializedReferenceReturnStateStep(
    DataFlow::Node pred, DataFlow::Node succ,
    string targetComponentId, string ownerComponentId
  ) {
    exists(MethodCall call, FieldAccess receiver, Field field, ReturnStmt ret,
           Class ownerClass, Class targetClass,
           string ownerScript, string ownerType, string targetScript, string targetType |
      call.getQualifier() = receiver and receiver.getTarget() = field and
      ret.getEnclosingCallable() = call.getTarget() and
      pred = DataFlow::exprNode(ret.getExpr()) and succ = DataFlow::exprNode(call) and
      ProjectModel::componentHasType(ownerComponentId, ownerScript, ownerType) and
      ownerClass.getName() = ownerType and ownerClass.getFile().getRelativePath() = ownerScript and
      field.getDeclaringType() = ownerClass.getABaseType*() and
      ProjectModel::hasDirectComponentFieldReference(ownerComponentId, field.getName(), targetComponentId) and
      ProjectModel::componentHasType(targetComponentId, targetScript, targetType) and
      targetClass.getName() = targetType and targetClass.getFile().getRelativePath() = targetScript and
      call.getTarget().getDeclaringType() = targetClass.getABaseType*() and
      ownerComponentId != targetComponentId
    )
  }

  /** Cross-instance state switch only for the exact serialized UnityEvent edge. */
  private predicate serializedUnityEventStateStep(
    DataFlow::Node pred, DataFlow::Node succ,
    string ownerComponentId, string targetComponentId
  ) {
    isSerializedUnityEventStateStep(pred, succ, ownerComponentId, targetComponentId) and
    ownerComponentId != targetComponentId
  }

  /** Static component fields are shared across concrete component instances. */
  private predicate staticFieldSharedStateStep(
    DataFlow::Node pred, DataFlow::Node succ, string beforeState, string afterState
  ) {
    exists(FieldWrite write, FieldRead read, AssignExpr assign |
      assign.getLeftOperand() = write and
      write.getTarget() = read.getTarget() and read.getTarget().isStatic() and
      pred = DataFlow::exprNode(assign.getRightOperand()) and
      succ = DataFlow::exprNode(read) and
      Core::isAdditionalFlowStep(pred, succ) and
      nodeMayExecuteInState(pred, "flow", beforeState) and
      nodeMayExecuteInState(succ, "flow", afterState)
    )
  }
}


