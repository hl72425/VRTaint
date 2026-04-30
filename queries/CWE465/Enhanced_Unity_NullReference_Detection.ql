/**
 * Enhanced_Unity_NullReference_Detection_fixed.ql
 * 适用于 Unity VR 项目的 CWE-465 空指针污点分析（C# / CodeQL 正确 API）
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.Type
import semmle.code.csharp.exprs.Expr
import semmle.code.csharp.Element

// ========== Unity 基础识别模块 ==========
predicate isMonoBehaviour(Class c) {
  // 检查自身或任一超类是不是 UnityEngine.MonoBehaviour
  exists(Class sup |
    // 修正 #1：使用 getQualifiedName() = "..."
    sup.getFullyQualifiedName() = "UnityEngine.MonoBehaviour" and
    (c = sup or c.getASuperType*() = sup)
  )
}

predicate isUnityLifecycleMethod(Method m) {
  m.getDeclaringType() instanceof Class and
  isMonoBehaviour(m.getDeclaringType()) and
  (
    m.getName() = "Awake" or
    m.getName() = "OnEnable" or
    m.getName() = "Start" or
    m.getName() = "Update" or
    m.getName() = "FixedUpdate" or
    m.getName() = "LateUpdate"
  )
}

// 更稳健的空检查：检测 if 条件是二元比较且一边为 null
predicate hasNullCheck(Expr e) {
  exists(IfStmt ifs, BinaryOperation be |
    ifs.getCondition() = be and
    (be.getOperator() = "==" or be.getOperator() = "!=") and
    (be.getLeftOperand() instanceof NullLiteral or be.getRightOperand() instanceof NullLiteral) and
    (
      be.getLeftOperand() = e or
      be.getRightOperand() = e or
      exists(ParenthesizedExpr pe |
        pe.getExpr() = e and
        (be.getLeftOperand() = pe or be.getRightOperand() = pe)
      )
    )
  )
}


// ========== 污点传播配置（使用 C# DataFlow::ConfigSig 风格） ==========
module UnityNullRefConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(Field f |
      // 引用型字段（不是值类型/原始类型）
      f.getType() instanceof RefType and
      src.asExpr() = f.getAnAccess() and
      // 没有非空的字段初始化器（初始化器不是 null）
      not exists(Expr init | f.getInitializer() = init and not init instanceof NullLiteral)
    )
    or
    // Match calls like someObj.GetComponent<...>() 或 GetComponent(...) 的调用（用 MethodCall）
    exists(MethodCall mc |
      src.asExpr() = mc and
      mc.getTarget().getName().matches("%GetComponent%")
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MemberAccess ma |
      ma.getQualifier() = sink.asExpr() and
      exists(Method m | isUnityLifecycleMethod(m) and ma.getEnclosingCallable() = m)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    hasNullCheck(node.asExpr())
  }
}

module UnityNullRefFlow = DataFlow::Global<UnityNullRefConfig>;

// ========== 主查询 ==========
from Expr src, Expr sink
where UnityNullRefFlow::flow(DataFlow::exprNode(src), DataFlow::exprNode(sink))
select sink, "潜在的空引用风险: 值可能来自未初始化字段或 GetComponent 调用: " + src.toString()