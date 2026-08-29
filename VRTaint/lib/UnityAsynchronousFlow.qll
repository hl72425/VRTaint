/**
 * @name UnityAsynchronousFlow
 * @description Bridges taint paths handled via implicit string-literal callbacks (e.g., SendMessage, Coroutines) and field-backed state persistence.
 */

import csharp
import UnityLifecycleBase
import UnityStationSkipping
import UnitySensitivityCore

/** Resolves the callback name without treating arbitrary runtime strings as constants. */
private predicate resolveCallbackName(Expr expression, string callbackName) {
  exists(StringLiteral literal |
    expression = literal and callbackName = literal.getValue()
  )
  or
  exists(NameOfExpr nameOf, MethodAccess access |
    expression = nameOf and access = nameOf.getAccess() and
    callbackName = access.getTarget().getName()
  )
}

/** The resolved API method is declared by the named Unity type or one of its bases. */
private predicate hasUnityApiType(Method method, string typeName) {
  method.getDeclaringType().hasFullyQualifiedName("UnityEngine", typeName)
}

/** Fast MethodCall-only context traversal used by asynchronous field hosting. */
private predicate isSameAsyncComponentHierarchy(
  ValueOrRefType left, ValueOrRefType right
) {
  left = right or left.getABaseType*() = right or right.getABaseType*() = left
}

private predicate isDirectAsyncContextCall(MethodCall call, Callable target) {
  target = call.getTarget() and
  (
    not call.getTarget().isStatic() and
    SensitivityCore::isImplicitThisReceiver(
      call.getQualifier(), call.getEnclosingCallable().getDeclaringType()
    ) and
    isSameAsyncComponentHierarchy(
      call.getTarget().getDeclaringType(), call.getEnclosingCallable().getDeclaringType()
    )
    or
    call.getTarget().isStatic() and
    not call.getTarget().getDeclaringType().getNamespace().getName().matches("System%") and
    not call.getTarget().getDeclaringType().getNamespace().getName().matches("UnityEngine%")
  )
}

private predicate hasDirectAsyncContextCallee(Callable start, Callable target) {
  exists(MethodCall call |
    call.getEnclosingCallable() = start and isDirectAsyncContextCall(call, target)
  )
}

private predicate hasAsyncContextCallee(Callable start, Callable target) {
  hasDirectAsyncContextCallee+(start, target)
}

/** A same-activation write can reach the later dispatch in the CFG. */
private predicate hasCfgOrderBefore(Expr before, Expr after) {
  before.getEnclosingCallable() = after.getEnclosingCallable() and
  before.getAControlFlowNode().getASuccessor+() = after.getAControlFlowNode()
}

/**
 * The first context-preserving helper invocation from `root` occurs before the
 * dispatch; deeper helper traversal retains the receiver constraints above.
 */
private predicate hasAsyncContextCalleeBeforeDispatch(
  Callable root, Callable target, MethodCall dispatch
) {
  exists(MethodCall firstCall, Callable firstTarget |
    firstCall.getEnclosingCallable() = root and
    isDirectAsyncContextCall(firstCall, firstTarget) and
    hasCfgOrderBefore(firstCall, dispatch) and
    (target = firstTarget or hasAsyncContextCallee(firstTarget, target))
  )
}

/** String-based Unity scheduling/message APIs, separated by argument semantics. */
private predicate isUnityStringCallbackDispatch(
  MethodCall call, string callbackName, string family
) {
  resolveCallbackName(call.getArgument(0), callbackName) and
  (
    family = "invoke" and
    call.getTarget().getName() in ["Invoke", "InvokeRepeating"] and
    hasUnityApiType(call.getTarget(), "MonoBehaviour")
    or
    family = "coroutine" and
    call.getTarget().getName() = "StartCoroutine" and
    hasUnityApiType(call.getTarget(), "MonoBehaviour") and
    call.getTarget().getParameter(0).getType().hasFullyQualifiedName("System", "String")
    or
    family = "message" and
    call.getTarget().getName() in ["SendMessage", "BroadcastMessage", "SendMessageUpwards"] and
    (
      hasUnityApiType(call.getTarget(), "Component")
      or hasUnityApiType(call.getTarget(), "GameObject")
    )
  )
}

/** `CancelInvoke` is intentionally absent: cancellation never dispatches a callback. */
predicate isUnityAsynchronousMethod(MethodCall call, Expr callbackExpression) {
  exists(string callbackName, string family |
    callbackExpression = call.getArgument(0) and
    isUnityStringCallbackDispatch(call, callbackName, family)
  )
}

/** Matches the runtime callback signature selected by a string dispatch. */
private predicate callbackMatchesDispatch(
  MethodCall dispatch, Class hostClass, string callbackName, string family,
  Method targetMethod
) {
  targetMethod.getDeclaringType() = hostClass and
  targetMethod.getName() = callbackName and
  (
    family = "invoke" and targetMethod.getNumberOfParameters() = 0
    or
    family = "coroutine" and
    targetMethod.getReturnType().hasFullyQualifiedName("System.Collections", "IEnumerator") and
    (
      dispatch.getNumberOfArguments() = 1 and targetMethod.getNumberOfParameters() = 0
      or dispatch.getNumberOfArguments() >= 2 and targetMethod.getNumberOfParameters() = 1
    )
    or
    family = "message" and
    (
      dispatch.getNumberOfArguments() = 1 and targetMethod.getNumberOfParameters() = 0
      or dispatch.getNumberOfArguments() >= 2 and targetMethod.getNumberOfParameters() = 1
    )
  )
}

/** Only these families pass argument 1 to callback parameter 0. */
private predicate hasCallbackPayload(MethodCall dispatch, string family) {
  dispatch.getNumberOfArguments() >= 2 and
  (
    family = "coroutine" and
    dispatch.getTarget().getParameter(1).getType().hasFullyQualifiedName("System", "Object")
    or
    family = "message" and
    dispatch.getTarget().getParameter(1).getType().hasFullyQualifiedName("System", "Object")
  )
}

/**
 * A field write visible when a literal-name Unity callback is dispatched.
 *
 * The lifecycle branch is evaluated only for the already correlated dispatch,
 * write, and field, avoiding a project-wide lifecycle x field x callback join.
 */
bindingset[mc, fw, f]
private predicate isWriteVisibleAtAsyncDispatch(MethodCall mc, FieldWrite fw, Field f) {
  fw.getTarget() = f and
  (
    hasCfgOrderBefore(fw, mc)
    or hasAsyncContextCalleeBeforeDispatch(
      mc.getEnclosingCallable(), fw.getEnclosingCallable(), mc
    )
    or
    exists(
      Method writeLifecycle, Method dispatchLifecycle,
      string writePhase, string dispatchPhase
    |
      (fw.getEnclosingCallable() = writeLifecycle or
       hasAsyncContextCallee(writeLifecycle, fw.getEnclosingCallable())) and
      (mc.getEnclosingCallable() = dispatchLifecycle or
       hasAsyncContextCallee(dispatchLifecycle, mc.getEnclosingCallable())) and
      isTaintBleedingThroughLifecycle(
        writeLifecycle, dispatchLifecycle, writePhase, dispatchPhase, f
      )
    )
  )
}

/** A literal/default/const strong update that definitely precedes dispatch. */
bindingset[mc, fw, f]
private predicate isIntrinsicallyCleanBeforeDispatch(MethodCall mc, FieldWrite fw, Field f) {
  exists(FieldWrite overwrite, AssignExpr assign |
    overwrite.getTarget() = f and
    SensitivityCore::isReceiverCompatible(fw, overwrite) and
    overwrite.getEnclosingCallable() = mc.getEnclosingCallable() and
    assign.getLeftOperand() = overwrite and
    SensitivityCore::isDefinitelyCleanDefinitionExpr(assign.getRightOperand()) and
    SensitivityCore::isViableExpr(assign.getRightOperand()) and
    overwrite.getAControlFlowNode().dominates(mc.getAControlFlowNode()) and
    not exists(FieldWrite laterWrite |
      laterWrite.getTarget() = f and
      SensitivityCore::isReceiverCompatible(fw, laterWrite) and
      laterWrite.getEnclosingCallable() = mc.getEnclosingCallable() and
      overwrite.getAControlFlowNode().getASuccessor+() = laterWrite.getAControlFlowNode() and
      laterWrite.getAControlFlowNode().dominates(mc.getAControlFlowNode())
    )
  )
}

/**
 * A deliberately narrow visibility relation for direct coroutine expressions.
 * It covers the common same-method write immediately scheduled by the direct
 * coroutine expression without reintroducing a project-wide callgraph/field
 * product. Earlier lifecycle writes remain available through the ordinary
 * VRTaint lifecycle field route.
 */
bindingset[startCall, write, field]
private predicate isWriteVisibleAtDirectCoroutine(
  MethodCall startCall, FieldWrite write, Field field
) {
  write.getTarget() = field and
  hasCfgOrderBefore(write, startCall)
}

/**
 * Implements a dual-route routing mechanism for asynchronous callback tracking.
 * Route A: Direct parameter reflection injection (e.g., SendMessage argument forwarding).
 * Route B: Global shadow-field tracking (bridges isolated states disrupted by asynchronous execution boundaries).
 */
predicate isAsynchronousFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(MethodCall mc, string callbackName, string family, Class hostClass |
    // 1. Scope alignment: Enforce constraints within the same MonoBehaviour boundary
    mc.getEnclosingCallable().getDeclaringType() = hostClass and
    hostClass.getABaseType*().hasFullyQualifiedName("UnityEngine", "MonoBehaviour") and
    
    isUnityStringCallbackDispatch(mc, callbackName, family) and

    (
      // ---- Route A: Direct Parameter Passing (e.g., SendMessage value injection) ----
      exists(Method targetMethod |
        callbackMatchesDispatch(mc, hostClass, callbackName, family, targetMethod) and
        hasCallbackPayload(mc, family) and
        SensitivityCore::isViableExpr(mc.getArgument(1)) and
        pred = DataFlow::exprNode(mc.getArgument(1)) and
        succ = DataFlow::parameterNode(targetMethod.getParameter(0))
      )
      or
      // ---- Route B: Callback-scoped field resumption ----
      // This keeps coroutine/string-callback support while avoiding the previous
      // class-wide "any async call connects any field write to any field read" over-approximation.
      exists(Field f, FieldWrite fw, FieldRead fr, Method targetMethod |
        callbackMatchesDispatch(mc, hostClass, callbackName, family, targetMethod) and
        isWriteVisibleAtAsyncDispatch(mc, fw, f) and
        fr.getTarget() = f and
        SensitivityCore::isReceiverCompatibleFieldFlow(fw, fr) and
        f.getDeclaringType() = hostClass and
        (fr.getEnclosingCallable() = targetMethod or
         hasAsyncContextCallee(targetMethod, fr.getEnclosingCallable())) and
        not isIntrinsicallyCleanBeforeDispatch(mc, fw, f) and
        
        // Propagate taint from the assigned RValue or the FieldWrite itself
        (
          pred = DataFlow::exprNode(fw.getParent().(AssignExpr).getRightOperand())
          and SensitivityCore::isViableExpr(fw.getParent().(AssignExpr).getRightOperand())
          or 
          pred = DataFlow::exprNode(fw)
        ) and
        
        // Force flow resumption at the corresponding FieldRead location
        succ = DataFlow::exprNode(fr)
      )
    )
  )
  or
  // ---- Route C: MethodInfo.Invoke with a literal GetMethod target cached in a field ----
  exists(
    MethodCall getMethodCall, MethodCall invokeCall, Field methodField,
    FieldWrite methodFieldWrite, FieldRead methodFieldRead,
    StringLiteral methodName, Method targetMethod,
    ArrayCreation argumentArray, ArrayInitializer argumentInitializer, Expr actual, int index
  |
    getMethodCall.getTarget().hasName("GetMethod") and
    getMethodCall.getArgument(0) = methodName and
    targetMethod.getName() = methodName.getValue() and
    targetMethod.getDeclaringType() = getMethodCall.getEnclosingCallable().getDeclaringType() and

    methodFieldWrite.getTarget() = methodField and
    methodFieldWrite.getParent().(AssignExpr).getRightOperand() = getMethodCall and
    methodFieldRead.getTarget() = methodField and

    invokeCall.getQualifier() = methodFieldRead and
    invokeCall.getTarget().getName() = "Invoke" and
    invokeCall.getTarget().getDeclaringType().hasFullyQualifiedName(
      "System.Reflection", ["MethodInfo", "MethodBase"]
    ) and
    argumentArray = invokeCall.getArgument(1) and
    argumentInitializer = argumentArray.getInitializer() and
    actual = argumentInitializer.getElement(index) and
    index < targetMethod.getNumberOfParameters() and
    SensitivityCore::isViableExpr(actual) and

    pred = DataFlow::exprNode(actual) and
    succ = DataFlow::parameterNode(targetMethod.getParameter(index))
  )
  or
  // ---- Route D: Direct StartCoroutine(Foo(x)) argument-to-coroutine-parameter bridge ----
  exists(MethodCall startCall, MethodCall coroutineCall, Method coroutineTarget, int index |
    startCall.getTarget().hasName("StartCoroutine") and
    hasUnityApiType(startCall.getTarget(), "MonoBehaviour") and
    coroutineCall = startCall.getArgument(0) and
    SensitivityCore::isContextPreservingCall(coroutineCall, coroutineTarget) and
    coroutineTarget = coroutineCall.getTarget() and
    coroutineTarget.getReturnType().hasFullyQualifiedName("System.Collections", "IEnumerator") and
    index < coroutineCall.getNumberOfArguments() and
    index < coroutineCall.getTarget().getNumberOfParameters() and
    SensitivityCore::isViableExpr(coroutineCall.getArgument(index)) and
    pred = DataFlow::exprNode(coroutineCall.getArgument(index)) and
    succ = DataFlow::parameterNode(coroutineCall.getTarget().getParameter(index))
  )
  or
  // ---- Route E: Direct StartCoroutine(Foo()) persistent-field resumption ----
  exists(
    MethodCall startCall, MethodCall coroutineCall, Method coroutineTarget,
    Class hostClass, Field field, FieldWrite write, FieldRead read
  |
    startCall.getEnclosingCallable().getDeclaringType() = hostClass and
    hostClass.getABaseType*().hasFullyQualifiedName("UnityEngine", "MonoBehaviour") and
    startCall.getTarget().hasName("StartCoroutine") and
    hasUnityApiType(startCall.getTarget(), "MonoBehaviour") and
    coroutineCall = startCall.getArgument(0) and
    SensitivityCore::isContextPreservingCall(coroutineCall, coroutineTarget) and
    coroutineTarget = coroutineCall.getTarget() and
    coroutineTarget.getReturnType().hasFullyQualifiedName("System.Collections", "IEnumerator") and
    isWriteVisibleAtDirectCoroutine(startCall, write, field) and
    field.getDeclaringType() = hostClass and
    read.getTarget() = field and
    SensitivityCore::isReceiverCompatibleFieldFlow(write, read) and
    (read.getEnclosingCallable() = coroutineTarget or
     SensitivityCore::hasContextCallee(coroutineTarget, read.getEnclosingCallable())) and
    not isIntrinsicallyCleanBeforeDispatch(startCall, write, field) and
    (
      pred = DataFlow::exprNode(write.getParent().(AssignExpr).getRightOperand()) and
      SensitivityCore::isViableExpr(write.getParent().(AssignExpr).getRightOperand())
      or pred = DataFlow::exprNode(write)
    ) and
    succ = DataFlow::exprNode(read)
  )
}

