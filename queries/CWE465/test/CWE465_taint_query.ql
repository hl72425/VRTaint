/**
 * @name LLM-driven CWE-465 taint flow
 * @description Auto-generated taint flow for Unity VR projects (C#)
 * @kind path-problem
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.Type
import semmle.code.csharp.exprs.Expr
import semmle.code.csharp.Element

// =======================
//  LLM 自动生成的源点与汇点
// =======================

predicate isLLMSource(Method m) {
  exists(TypeDecl t |
    (
      t.getNamespace().getName() = "Reflection" and
      t.getName() = "Assembly" and
      m.getDeclaringType() = t and
      m.getName() = "GetType" and
      m.getSignature().matches("%Type GetType(String name)%")
    )
    or
    (
      t.getNamespace().getName() = "Generic" and
      t.getName() = "List<Byte>" and
      m.getDeclaringType() = t and
      m.getName() = "AddRange" and
      m.getSignature().matches("%Void AddRange(IEnumerable<Byte> collection)%")
    )
  )
}

predicate isLLMSink(Method m) {
  exists(TypeDecl t |
    (
      t.getNamespace().getName() = "Reflection" and
      t.getName() = "FieldInfo" and
      m.getDeclaringType() = t and
      m.getName() = "GetValue" and
      m.getSignature().matches("%Object GetValue(Object obj)%")
    )
    or
    (
      t.getNamespace().getName() = "Reflection" and
      t.getName() = "FieldInfo" and
      m.getDeclaringType() = t and
      m.getName() = "SetValue" and
      m.getSignature().matches("%Void SetValue(Object obj, Object value)%")
    )
  )
}

predicate isCandidateSource(Method m) { isLLMSource(m) }
predicate isCandidateSink(Method m)   { isLLMSink(m) }

// =======================
//  数据流配置（C# 正确语法）
// =======================

module LLMConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(MethodCall mc, Method callee |
      src.asExpr() = mc and
      mc.getTarget() = callee and
      isCandidateSource(callee)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc, Method callee |
      sink.asExpr() = mc and
      mc.getTarget() = callee and
      isCandidateSink(callee)
    )
  }

  // optional
  predicate isBarrier(DataFlow::Node _) { false }
}

module LLMFlow = DataFlow::Global<LLMConfig>;

// =======================
//  查询入口
// =======================
from Expr src, Expr sink
where LLMFlow::flow(DataFlow::exprNode(src), DataFlow::exprNode(sink))
select sink, "LLM-driven taint flow detected: data from " + src.toString()
