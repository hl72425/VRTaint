/**
 * @name Unity VR LLM-based taint analysis
 * @description Performs taint tracking on Unity VR projects using LLM-labeled Unity API methods and lifecycle propagation.
 * @kind path-problem
 * @id csharp/unity-vr-taint
 * @problem.severity warning
 * @precision high
 * @tags security, unity, taint, vr
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow
import GeneratedAPIs

// ========== 辅助类：虚拟污点汇 ==========
class VirtualSink extends Expr {
  VirtualSink() {
    this instanceof MemberAccess or
    this instanceof ElementAccess
  }
}

// ========== 污点分析配置 ==========
module UnityVRTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(MethodCall call |
      GeneratedAPIs::isLLMDetectedSourceMethod(call.getTarget()) and
      source = DataFlow::exprNode(call)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      GeneratedAPIs::isLLMDetectedSinkMethod(call.getTarget()) and
      sink = DataFlow::exprNode(call)
    ) or
    exists(VirtualSink vs |
      sink = DataFlow::exprNode(vs)
    )
  }

  // 而是使用 isAdditionalFlowStep（用于路径问题）
  predicate isAdditionalFlowStep(DataFlow::Node src, DataFlow::Node dst) {
    exists(MethodCall call, Method m, Expr arg |
      m = call.getTarget() and
      GeneratedAPIs::isLLMDetectedPropagator(m) and
      arg = call.getAnArgument() and
      src = DataFlow::exprNode(arg) and
      dst = DataFlow::exprNode(call)
    )
  }

  // 可选：定义屏障（sanitizer）
  predicate isBarrier(DataFlow::Node n) {
    none() // 无屏障
  }
}

// 全局污点流分析器
module UnityVRTaintFlow = DataFlow::Global<UnityVRTaintConfig>;

// ========== 主查询 ==========
from UnityVRTaintFlow::PathNode source, UnityVRTaintFlow::PathNode sink
where UnityVRTaintFlow::flowPath(source, sink)
select sink, source, sink,
  "Tainted data flows from $@ to $@ through Unity VR LLM-labeled APIs or lifecycle propagation.",
  source.getNode(), "source",
  sink.getNode(), "sink"