/**
 * @name Unity external input controls a file-system path (fast direct-flow tier)
 * @description External Unity/network/HTTP/file-picker input reaches an official CodeQL path sink.
 *              This tier uses standard CodeQL flow for scalable direct/interprocedural paths; the
 *              companion cs/unity-tainted-file-path query adds VRTaint lifecycle/event propagation.
 * @kind path-problem
 * @id cs/unity-tainted-file-path-fast
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @tags security external/cwe/cwe-022
 */

import csharp
import lib.UnityExternalInput
import lib.UnityPathRiskModel

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    UnityExternalInput::isExternalSource(source) and UnityExternalInput::isRuntimeNode(source)
  }
  predicate isSink(DataFlow::Node sink) {
    UnityPathRiskModel::isSink(sink) and UnityPathRiskModel::isProjectOwnedNode(sink)
  }
  predicate isBarrier(DataFlow::Node node) { UnityPathRiskModel::isBarrier(node) }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink, string kind,
     string objectId, string fieldPath, string phase, string context
where Flow::flowPath(source, sink) and
  UnityExternalInput::sourceKind(source.getNode(), kind) and
  UnityExternalInput::objectId(source.getNode(), objectId) and
  UnityExternalInput::fieldPath(source.getNode(), fieldPath) and
  UnityExternalInput::phase(source.getNode(), phase) and
  UnityExternalInput::context(source.getNode(), context)
select sink.getNode(), source, sink,
  "External input controls an official file-system path sink. " +
  "Tuple=<" + objectId + ", " + fieldPath + ", " + phase + ", " + context + ", " + kind + ">."
