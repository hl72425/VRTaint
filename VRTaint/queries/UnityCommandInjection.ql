/**
 * @name Unity external input reaches a command execution API
 * @description External Unity/network/file input reaches an official CodeQL command sink.
 * @kind path-problem
 * @id cs/unity-command-injection
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security external/cwe/cwe-078
 */

import csharp
import lib.UnityExternalInput
import lib.UnityCommandRiskModel
import lib.VRTaintFlowFramework

module Config implements ProjectConfigSig {
  predicate isSource(DataFlow::Node source) {
    UnityExternalInput::isExternalSource(source) and UnityExternalInput::isRuntimeNode(source)
  }
  predicate isSink(DataFlow::Node sink) {
    UnityCommandRiskModel::isSink(sink) and UnityCommandRiskModel::isProjectOwnedNode(sink)
  }
  predicate isBarrier(DataFlow::Node node) { UnityCommandRiskModel::isBarrier(node) }
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { none() }
}

module Flow = VRTaintInstanceFlow<Config>;
module Tracking = TaintTracking::GlobalWithState<Flow>;
import Tracking::PathGraph

from Tracking::PathNode source, Tracking::PathNode sink, string kind,
     string objectId, string fieldPath, string phase, string context
where
  Tracking::flowPath(source, sink) and
  UnityExternalInput::sourceKind(source.getNode(), kind) and
  UnityExternalInput::objectId(source.getNode(), objectId) and
  UnityExternalInput::fieldPath(source.getNode(), fieldPath) and
  UnityExternalInput::phase(source.getNode(), phase) and
  UnityExternalInput::context(source.getNode(), context)
select sink.getNode(), source, sink,
  "External input reaches an official command-execution sink. " +
  "Tuple=<" + objectId + ", " + fieldPath + ", " + phase + ", " + context + ", " + kind + ">."
