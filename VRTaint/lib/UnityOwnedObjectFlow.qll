/**
 * @name UnityOwnedObjectFlow
 * @description Flow through plain C# helper-object state owned by a MonoBehaviour.
 *              Native CodeQL models value flow up to a helper-field write; this
 *              library adds only the missing write-RValue-to-future-read edge.
 */

import csharp
import UnityLifecycleBase
import UnitySensitivityCore

predicate isOwnedHelperObjectField(Field ownerField) {
  ownerField.getDeclaringType().getABaseType*().hasFullyQualifiedName("UnityEngine", "MonoBehaviour") and
  ownerField.getType() instanceof Class and
  not ownerField.getType().(Class).getABaseType*().hasFullyQualifiedName("UnityEngine", "Object") and
  not ownerField.getType().(Class).getNamespace().getName().matches("System%")
}

predicate isOwnedHelperCall(MethodCall call, Field ownerField) {
  exists(FieldAccess qualifier |
    call.getQualifier() = qualifier and
    qualifier.getTarget() = ownerField and
    isOwnedHelperObjectField(ownerField)
  )
}

/** A callback hosts operations in its body and in transitively invoked methods. */
private predicate isHostedByLifecycle(Method lifecycle, Callable operationHost) {
  operationHost = lifecycle or SensitivityCore::hasContextCallee(lifecycle, operationHost)
}

/** Transparent may-order for callbacks of the same component implementation. */
private predicate ownedLifecycleMayReach(
  Method before, Method after, string beforeName, string afterName
) {
  before.getDeclaringType() = after.getDeclaringType() and
  isUnityLifecycleMethod(before, beforeName) and
  isUnityLifecycleMethod(after, afterName) and
  (
    exists(string ignoredBefore, string ignoredAfter |
      isNextLifecycleStation(before, after, ignoredBefore, ignoredAfter)
    )
    or lifecycleMayOrder(beforeName, afterName)
  )
}

/** Deterministic phases valid for all-path helper-state kill reasoning. */
bindingset[beforeName, middleName, afterName]
private predicate ownedMustBetween(
  string beforeName, string middleName, string afterName
) {
  lifecycleMustBetween(beforeName, middleName, afterName)
}

private predicate isStableHelperFieldDefinition(Field helperField, FieldWrite overwrite) {
  not exists(FieldWrite laterWrite |
    laterWrite.getTarget() = helperField and
    laterWrite.getEnclosingCallable() = overwrite.getEnclosingCallable() and
    SensitivityCore::isReceiverCompatible(overwrite, laterWrite) and
    overwrite.getAControlFlowNode().getASuccessor+() = laterWrite.getAControlFlowNode()
  )
}

/** A helper method definitely replaces its own field with an intrinsic clean value. */
private predicate helperMethodDefinitelyCleansField(Method helperMethod, Field helperField) {
  exists(FieldWrite overwrite, AssignExpr assign |
    overwrite.getEnclosingCallable() = helperMethod and
    overwrite.getTarget() = helperField and
    assign.getLeftOperand() = overwrite and
    SensitivityCore::isImplicitThisReceiver(
      overwrite.getQualifier(), helperMethod.getDeclaringType()
    ) and
    SensitivityCore::isDefinitelyCleanDefinitionExpr(assign.getRightOperand()) and
    SensitivityCore::isViableExpr(assign.getRightOperand()) and
    overwrite.getAControlFlowNode().postDominates(helperMethod.getEntryPoint()) and
    isStableHelperFieldDefinition(helperField, overwrite)
  )
}

/** No later call through the same owner field may invalidate a proven reset. */
private predicate noLaterOwnedHelperCall(MethodCall resetCall, Field ownerField) {
  not exists(MethodCall laterCall |
    laterCall.getEnclosingCallable() = resetCall.getEnclosingCallable() and
    isOwnedHelperCall(laterCall, ownerField) and
    resetCall.getAControlFlowNode().getASuccessor+() = laterCall.getAControlFlowNode()
  )
}

/**
 * A deterministic intermediate callback definitely invokes a helper reset.
 * Post-dominance plus an intrinsic clean strong update makes this a must-kill,
 * rather than treating any write as a sanitizer.
 */
bindingset[before, after, beforeName, afterName, ownerField, helperField]
private predicate helperStateDefinitelyKilledBetween(
  Method before, Method after, string beforeName, string afterName,
  Field ownerField, Field helperField
) {
  exists(
    Method middle, string middleName, MethodCall resetCall, Method resetMethod
  |
    middle.getDeclaringType() = before.getDeclaringType() and
    middle.getDeclaringType() = after.getDeclaringType() and
    isUnityLifecycleMethod(middle, middleName) and
    ownedMustBetween(beforeName, middleName, afterName) and
    resetCall.getEnclosingCallable() = middle and
    isOwnedHelperCall(resetCall, ownerField) and
    resetMethod = resetCall.getTarget() and
    resetMethod.getDeclaringType() = helperField.getDeclaringType() and
    helperMethodDefinitelyCleansField(resetMethod, helperField) and
    resetCall.getAControlFlowNode().postDominates(middle.getEntryPoint()) and
    noLaterOwnedHelperCall(resetCall, ownerField)
  )
}

private predicate helperFieldWriteRValue(
  Method storeMethod, Field helperField, FieldWrite helperWrite, Expr rhs
) {
  helperWrite.getTarget() = helperField and
  (
    helperWrite.getEnclosingCallable() = storeMethod
    or hasCalleeTransitive(storeMethod, helperWrite.getEnclosingCallable())
  ) and
  exists(AssignExpr assign |
    assign.getLeftOperand() = helperWrite and rhs = assign.getRightOperand()
  )
}

private predicate helperFieldReadInMethod(Method readMethod, Field helperField, FieldRead read) {
  read.getTarget() = helperField and
  (read.getEnclosingCallable() = readMethod or hasCalleeTransitive(readMethod, read.getEnclosingCallable()))
}

predicate isOwnedObjectFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(
    Method storeLifecycle, Method readLifecycle, string storeName, string readName,
    Field ownerField, Field helperField,
    MethodCall storeCall, MethodCall readCall,
    Method storeMethod, Method readMethod,
    FieldWrite helperWrite, FieldRead helperRead, Expr rhs
  |
    ownedLifecycleMayReach(storeLifecycle, readLifecycle, storeName, readName) and
    isHostedByLifecycle(storeLifecycle, storeCall.getEnclosingCallable()) and
    isHostedByLifecycle(readLifecycle, readCall.getEnclosingCallable()) and

    isOwnedHelperCall(storeCall, ownerField) and
    isOwnedHelperCall(readCall, ownerField) and
    storeMethod = storeCall.getTarget() and
    readMethod = readCall.getTarget() and
    storeMethod.getDeclaringType() = readMethod.getDeclaringType() and
    helperField.getDeclaringType() = storeMethod.getDeclaringType() and

    helperFieldWriteRValue(storeMethod, helperField, helperWrite, rhs) and
    helperFieldReadInMethod(readMethod, helperField, helperRead) and
    SensitivityCore::isViableExpr(rhs) and
    SensitivityCore::isViableExpr(helperRead) and

    not helperStateDefinitelyKilledBetween(
      storeLifecycle, readLifecycle, storeName, readName, ownerField, helperField
    ) and

    pred = DataFlow::exprNode(rhs) and
    succ = DataFlow::exprNode(helperRead)
  )
}
