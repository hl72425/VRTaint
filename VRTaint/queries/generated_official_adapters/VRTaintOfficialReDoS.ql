/**
 * @name VRTaint lifecycle extension for official ReDoS flow model
 * @description Preserves the official Source, Sink, and Sanitizer model and adds VRTaint
 *              lifecycle, event, coroutine, asynchronous, field, and owned-object propagation.
 * @kind path-problem
 * @id cs/vrtaint-official-redos
 * @problem.severity warning
 * @security-severity 8.0
 * @precision high
 * @tags security
 */

import csharp
import semmle.code.csharp.security.dataflow.ReDoSQuery
import lib.VRTaintFlowFramework
import lib.UnityExternalInput

module Config implements ProjectConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source or UnityExternalInput::isExternalSource(source) and UnityExternalInput::isRuntimeNode(source) }
  predicate isSink(DataFlow::Node sink) {
    sink instanceof Sink and
    exists(Callable c | c = sink.getEnclosingCallable() and c.fromSource())
  }
  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { none() }
}

module VRTaintConfig = VRTaintInstanceFlow<Config>;
module Flow = TaintTracking::GlobalWithState<VRTaintConfig>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Official ReDoS source reaches its official sink through Unity semantic propagation."
