/**
 * @name UnitySensitivityCore
 * @description Shared precision predicates for Unity VR taint analysis:
 *              conservative path/value pruning, receiver-sensitive field matching,
 *              context-preserving runtime call chains, and index-sensitive collection flow.
 */

import csharp

module SensitivityCore {

  // -------------------------------------------------------------------------
  // Path/value sensitivity
  // -------------------------------------------------------------------------

  private predicate isNonInitializerFieldWrite(FieldWrite fw, Field f) {
    fw.getTarget() = f and
    fw.getLocation() != f.getLocation()
  }

  predicate isCompileTimeBool(Expr e, boolean value) {
    e.(BoolLiteral).getBoolValue() = value
    or
    exists(LogicalNotExpr notExpr, boolean innerValue |
      e = notExpr and
      isCompileTimeBool(notExpr.getOperand(), innerValue) and
      (
        innerValue = true and value = false
        or
        innerValue = false and value = true
      )
    )
    or
    exists(Field f, BoolLiteral init |
      e instanceof FieldRead and
      e.(FieldRead).getTarget() = f and
      init = f.getInitializer() and
      init.getBoolValue() = value and
      (
        f.hasModifier("const") or
        f.hasModifier("readonly") and f.hasModifier("private")
      ) and
      not exists(FieldWrite fw | isNonInitializerFieldWrite(fw, f))
    )
    or
    exists(Field f, BoolLiteral init |
      e instanceof FieldAccess and
      e.(FieldAccess).getTarget() = f and
      init = f.getInitializer() and
      init.getBoolValue() = value and
      (
        f.hasModifier("const") or
        f.hasModifier("readonly") and f.hasModifier("private")
      ) and
      not exists(FieldWrite fw | isNonInitializerFieldWrite(fw, f))
    )
  }

  predicate isInDeadConstantBranch(Expr e) {
    exists(IfStmt ifs, Stmt deadBranch, boolean value |
      isCompileTimeBool(ifs.getCondition(), value) and
      (
        value = true and deadBranch = ifs.getElse()
        or
        value = false and deadBranch = ifs.getThen()
      ) and
      deadBranch.getAChild*() = e
    )
  }

  predicate isViableExpr(Expr e) {
    not isInDeadConstantBranch(e)
  }

  /**
   * A value that is intrinsically independent of runtime input and can therefore
   * serve as the RHS of a definite strong update.
   *
   * Keep this separate from a query's `isBarrier`: a barrier is a node-level
   * taint-stopping policy, whereas this predicate proves that a replacement
   * value itself is clean.  Casts are transparent, and const-field reads are
   * accepted because C# requires their initializers to be compile-time values.
   */
  bindingset[e]
  predicate isDefinitelyCleanDefinitionExpr(Expr e) {
    e.stripCasts() instanceof Literal
    or e.stripCasts() instanceof DefaultValueExpr
    or
    exists(FieldRead read |
      read = e.stripCasts() and
      read.getTarget().isConst()
    )
  }

  // -------------------------------------------------------------------------
  // Context sensitivity
  // -------------------------------------------------------------------------

  /** Holds when two declaring types can denote the same component instance. */
  private predicate isSameComponentHierarchy(ValueOrRefType left, ValueOrRefType right) {
    left = right
    or left.getABaseType*() = right
    or right.getABaseType*() = left
  }

  /**
   * Resolves a call through CodeQL's runtime-target abstraction while retaining
   * only targets that preserve the current Unity component/object context.
   *
   * Unlike the previous MethodCall.getTarget() model, `Call` also covers
   * delegate/local-function/accessor/operator/constructor calls and
   * getARuntimeTarget() accounts for virtual dispatch.
   */
  predicate isContextPreservingCall(Call call, Callable target) {
    call.getARuntimeTarget() = target and
    target.fromSource() and
    (
      // Instance helper on the current component receiver. A call on another
      // object of the same C# type is not a context-preserving lifecycle jump.
      (
        not target instanceof Method
        or
        not target.(Method).isStatic() and
        call instanceof MethodCall and
        isImplicitThisReceiver(
          call.(MethodCall).getQualifier(), call.getEnclosingCallable().getDeclaringType()
        )
      ) and
      isSameComponentHierarchy(
        target.getDeclaringType(), call.getEnclosingCallable().getDeclaringType()
      )
      or
      // Project-owned static helper. The component identity is carried by the
      // caller context rather than fabricated from the helper's declaring type.
      target instanceof Method and target.(Method).isStatic() and
      not target.getDeclaringType().getNamespace().getName().matches("System%") and
      not target.getDeclaringType().getNamespace().getName().matches("UnityEngine%")
    )
  }

  /** Backwards-compatible MethodCall view used by existing libraries. */
  predicate isContextPreservingCall(MethodCall mc) {
    exists(Callable target | isContextPreservingCall(mc, target))
  }

  predicate hasDirectContextCallee(Callable start, Callable target) {
    exists(Call call |
      call.getEnclosingCallable() = start and
      isContextPreservingCall(call, target)
    )
  }

  /**
   * True fixed-point transitive closure of context-preserving runtime calls.
   * CodeQL evaluates `+` declaratively, including SCCs, rather than using a
   * depth-three command-style traversal.
   */
  predicate hasContextCallee(Callable start, Callable target) {
    hasDirectContextCallee(start, target)
    or
    exists(Callable intermediate |
      hasDirectContextCallee(start, intermediate) and
      hasContextCallee(intermediate, target)
    )
  }

  // -------------------------------------------------------------------------
  // Object/field receiver sensitivity
  // -------------------------------------------------------------------------

  predicate isImplicitThisReceiver(Expr e, Type t) {
    e.stripCasts() instanceof ThisAccess and
    e.getEnclosingCallable().getDeclaringType() = t
  }

  predicate isReceiverCompatible(FieldAccess a, FieldAccess b) {
    a.getTarget() = b.getTarget() and
    (
      a.getTarget().isStatic()
      or
      exists(ValueOrRefType leftType, ValueOrRefType rightType |
        isImplicitThisReceiver(a.getQualifier(), leftType) and
        isImplicitThisReceiver(b.getQualifier(), rightType) and
        isSameComponentHierarchy(leftType, rightType)
      )
      or
      a.getQualifier() = b.getQualifier()
      or
      exists(FieldAccess qa, FieldAccess qb |
        qa = a.getQualifier() and
        qb = b.getQualifier() and
        isReceiverCompatible(qa, qb)
      )
    )
  }

  predicate isReceiverCompatibleFieldFlow(FieldWrite writeExpr, FieldRead readExpr) {
    writeExpr.getTarget() = readExpr.getTarget() and
    isReceiverCompatible(writeExpr, readExpr)
  }

  predicate isCleanFieldReadAfterBarrierWrite(DataFlow::Node node) {
    exists(FieldRead readExpr, FieldWrite overwrite, AssignExpr assign |
      node = DataFlow::exprNode(readExpr) and
      assign.getLeftOperand() = overwrite and
      overwrite.getTarget() = readExpr.getTarget() and
      isReceiverCompatible(overwrite, readExpr) and
      isDefinitelyCleanDefinitionExpr(assign.getRightOperand()) and
      overwrite.getEnclosingCallable() = readExpr.getEnclosingCallable() and
      overwrite.getAControlFlowNode().dominates(readExpr.getAControlFlowNode()) and
      not exists(FieldWrite laterWrite |
        laterWrite.getTarget() = readExpr.getTarget() and
        isReceiverCompatible(laterWrite, readExpr) and
        laterWrite.getEnclosingCallable() = readExpr.getEnclosingCallable() and
        overwrite.getAControlFlowNode().getASuccessor+() = laterWrite.getAControlFlowNode() and
        (
          laterWrite.getLocation().getStartLine() < readExpr.getLocation().getStartLine()
          or
          laterWrite.getLocation().getStartLine() = readExpr.getLocation().getStartLine() and
          laterWrite.getLocation().getStartColumn() <= readExpr.getLocation().getStartColumn()
        )
      ) and
      isViableExpr(assign.getRightOperand())
    )
  }

  predicate isCleanLocalReadAfterBarrierWrite(DataFlow::Node node) {
    exists(VariableRead readExpr, VariableWrite overwrite, AssignExpr assign |
      node = DataFlow::exprNode(readExpr) and
      assign.getLeftOperand() = overwrite and
      overwrite.getTarget() = readExpr.getTarget() and
      overwrite.getEnclosingCallable() = readExpr.getEnclosingCallable() and
      overwrite.getAControlFlowNode().dominates(readExpr.getAControlFlowNode()) and
      not exists(VariableWrite laterWrite |
        laterWrite.getTarget() = readExpr.getTarget() and
        laterWrite.getEnclosingCallable() = readExpr.getEnclosingCallable() and
        overwrite.getAControlFlowNode().getASuccessor+() = laterWrite.getAControlFlowNode() and
        (
          laterWrite.getLocation().getStartLine() < readExpr.getLocation().getStartLine()
          or
          laterWrite.getLocation().getStartLine() = readExpr.getLocation().getStartLine() and
          laterWrite.getLocation().getStartColumn() <= readExpr.getLocation().getStartColumn()
        )
      ) and
      isViableExpr(assign.getRightOperand()) and
      (
        isDefinitelyCleanDefinitionExpr(assign.getRightOperand())
        or
        exists(FieldRead cleanFieldRead |
          cleanFieldRead = assign.getRightOperand().getAChildExpr*() and
          isCleanFieldReadAfterBarrierWrite(DataFlow::exprNode(cleanFieldRead))
        )
      )
    )
  }

  // -------------------------------------------------------------------------
  // Array/collection index sensitivity
  // -------------------------------------------------------------------------

  predicate isSameConstantIndex(Expr a, Expr b) {
    exists(Literal la, Literal lb |
      a = la and b = lb and la.toString() = lb.toString() and la.getType() = lb.getType()
    )
    or
    exists(MemberConstantAccess ma, MemberConstantAccess mb |
      a = ma and b = mb and ma.getTarget() = mb.getTarget()
    )
  }

  private predicate isSameStorageIdentity(Expr a, Expr b) {
    exists(VariableRead va, VariableRead vb |
      a = va and b = vb and va.getTarget() = vb.getTarget()
    )
    or
    exists(FieldAccess fa, FieldAccess fb |
      a = fa and b = fb and fa.getTarget() = fb.getTarget() and isReceiverCompatible(fa, fb)
    )
    or
    exists(ThisAccess ta, ThisAccess tb |
      a = ta and b = tb and
      ta.getEnclosingCallable().getDeclaringType() = tb.getEnclosingCallable().getDeclaringType()
    )
  }

  predicate isSameElementSlot(ElementAccess writeAccess, ElementAccess readAccess) {
    isSameStorageIdentity(writeAccess.getQualifier().stripCasts(), readAccess.getQualifier().stripCasts()) and
    forall(int i |
      exists(writeAccess.getIndex(i))
      |
      exists(readAccess.getIndex(i)) and
      isSameConstantIndex(writeAccess.getIndex(i), readAccess.getIndex(i))
    ) and
    forall(int i |
      exists(readAccess.getIndex(i))
      |
      exists(writeAccess.getIndex(i))
    )
  }

  predicate isIndexSensitiveElementFlow(DataFlow::Node pred, DataFlow::Node succ) {
    exists(ElementWrite ew, ElementRead er, AssignExpr assign |
      assign.getLeftOperand() = ew and
      isSameElementSlot(ew, er) and
      isViableExpr(assign.getRightOperand()) and
      pred = DataFlow::exprNode(assign.getRightOperand()) and
      succ = DataFlow::exprNode(er)
    )
    or
    exists(MethodCall mc, ElementRead er |
      mc.getTarget().getName() in ["Add", "TryAdd"] and
      mc.getNumberOfArguments() >= 2 and
      isSameStorageIdentity(mc.getQualifier().stripCasts(), er.getQualifier().stripCasts()) and
      isSameConstantIndex(mc.getArgument(0), er.getIndex(0)) and
      isViableExpr(mc.getArgument(1)) and
      pred = DataFlow::exprNode(mc.getArgument(1)) and
      succ = DataFlow::exprNode(er)
    )
    or
    exists(MethodCall mc, ElementRead er |
      mc.getTarget().getName() = "Insert" and
      mc.getNumberOfArguments() >= 2 and
      isSameStorageIdentity(mc.getQualifier().stripCasts(), er.getQualifier().stripCasts()) and
      isSameConstantIndex(mc.getArgument(0), er.getIndex(0)) and
      isViableExpr(mc.getArgument(1)) and
      pred = DataFlow::exprNode(mc.getArgument(1)) and
      succ = DataFlow::exprNode(er)
    )
  }
}

