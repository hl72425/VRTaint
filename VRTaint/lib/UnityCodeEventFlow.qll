/**
 * @name UnityCodeEventFlow
 * @description Taint propagation bridging code-bound UnityEvent subscription (AddListener) and publication (Invoke).
 */

import csharp
import UnityStationSkipping
import UnitySensitivityCore
import UnitySerializedConfig

/**
 * Holds if a taint step exists between an Invoke argument and the parameter of its dynamically registered handler.
 * Aligns data flows across structurally decoupled event dispatches via common field/type contexts.
 *
 * Resolves the target delegate method registered inside an AddListener invocation.
 */
predicate getMethodFromAddListenerArg(MethodCall mcAdd, Method targetMethod) {
  exists(Expr arg, MethodAccess ma |
    arg = mcAdd.getArgument(0) and
    (
      arg.(MethodAccess).getTarget() = targetMethod or
      ma = arg.getAChildExpr*() and ma.getTarget() = targetMethod or
      arg.(ImplicitDelegateCreation).getAChildExpr*().(MethodAccess).getTarget() = targetMethod or
      exists(LambdaExpr lambda | lambda = arg and ma.getEnclosingCallable() = lambda and ma.getTarget() = targetMethod) or
      exists(AnonymousMethodExpr ame | ame = arg and ma.getEnclosingCallable() = ame and ma.getTarget() = targetMethod)
    )
  )
}

 predicate isUnityEventFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(
    FieldAccess faInvoke, FieldAccess faAdd,
    MethodCall mcInvoke, MethodCall mcAdd,
    Method targetMethod, int paramIndex
  |
    // 1. Identify UnityEvent Invoke calls
    mcInvoke.getQualifier() = faInvoke and
    mcInvoke.getTarget().hasName("Invoke") and
    (
      mcInvoke.getTarget().getDeclaringType().getABaseType*().hasFullyQualifiedName("UnityEngine.Events", "UnityEventBase") or
      mcInvoke.getTarget().getDeclaringType().getName().matches("UnityEvent%")
    ) and
    SensitivityCore::isViableExpr(mcInvoke.getArgument(paramIndex)) and
    pred = DataFlow::exprNode(mcInvoke.getArgument(paramIndex)) and

    // 2. Identify UnityEvent AddListener subscriptions
    mcAdd.getQualifier() = faAdd and
    mcAdd.getTarget().hasName("AddListener") and

    // 3. Coordinate context: Verify they target the exact same field/instance topology
    faInvoke.getTarget() = faAdd.getTarget() and
    SensitivityCore::isReceiverCompatible(faInvoke, faAdd) and
    (
      faInvoke.getTarget().(Field).isStatic() or
      faInvoke.getQualifier().getType() = faAdd.getQualifier().getType()
    ) and

    // 4. Resolve the callback target method from AddListener arguments
    getMethodFromAddListenerArg(mcAdd, targetMethod) and

    // 5. Connect the tainted argument to the resolved handler's parameter
    succ = DataFlow::parameterNode(targetMethod.getParameter(paramIndex))
  )
  or
  isSerializedUnityEventFlowStep(pred, succ)
}

