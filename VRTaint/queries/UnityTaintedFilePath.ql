/**
 * @name Unity external input controls a file-system path
 * @description Unity/network/file-picker input reaches an official CodeQL file path sink.
 * @kind path-problem
 * @id cs/unity-tainted-file-path
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @tags security external/cwe/cwe-022
 */

import csharp
import lib.UnityExternalInput
import lib.UnityPathRiskModel
import lib.VRTaintFlowFramework

module Config implements ProjectConfigSig {
  predicate isSource(DataFlow::Node source) {
    UnityExternalInput::isExternalSource(source) and UnityExternalInput::isRuntimeNode(source)
  }
  predicate isSink(DataFlow::Node sink) {
    UnityPathRiskModel::isSink(sink) and UnityPathRiskModel::isProjectOwnedNode(sink)
  }
  predicate isBarrier(DataFlow::Node node) { UnityPathRiskModel::isBarrier(node) }
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
  "External input controls an official file-system path sink. " +
  "Tuple=<" + objectId + ", " + fieldPath + ", " + phase + ", " + context + ", " + kind + ">."
