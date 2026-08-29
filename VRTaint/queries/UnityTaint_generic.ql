/**
 * @name Unity Taint Flow - Generic (Standard Sources/Sinks)
 * @description Generic taint tracking query using the standard Unity source/sink/barrier library.
 *              Intended for new databases that don't yet have project-specific additional flow steps.
 *              Uses the VRTaintFlowFramework with UnityStandardSourceSink.
 * @kind path-problem
 * @precision high
 * @id cs/vr-taint-generic
 * @severity error
 * @tags security
 */

import csharp
import lib.VRTaintFlowFramework
import lib.UnityStandardSourceSink
import lib.UnitySensitivityCore

module UnityVRConfig implements ProjectConfigSig {
  predicate isSource(DataFlow::Node source) {
    UnityStandardSourceSink::isStandardSource(source) and
    (
      not exists(Expr e | e = source.asExpr())
      or
      exists(Expr e | e = source.asExpr() and SensitivityCore::isViableExpr(e))
    )
  }
  predicate isSink(DataFlow::Node sink) {
    UnityStandardSourceSink::isStandardSink(sink) and
    not SensitivityCore::isCleanFieldReadAfterBarrierWrite(sink) and
    not SensitivityCore::isCleanLocalReadAfterBarrierWrite(sink)
  }
  predicate isBarrier(DataFlow::Node node) {
    UnityStandardSourceSink::isStandardBarrier(node)
    or
    SensitivityCore::isCleanFieldReadAfterBarrierWrite(node)
    or
    SensitivityCore::isCleanLocalReadAfterBarrierWrite(node)
  }
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Placeholder: add project-specific UnityEvent wiring here when needed.
    none()
  }
}

module Flow = VRTaintFlow<UnityVRConfig>;
module Tracking = TaintTracking::Global<Flow>;
import Tracking::PathGraph

from Tracking::PathNode source, Tracking::PathNode sink, string flowKind
where
  Tracking::flowPath(source, sink) and
  UnityStandardSourceSink::isCompatibleStandardFlow(source.getNode(), sink.getNode(), flowKind)
select sink.getNode(), source, sink,
  "Kind: " + flowKind +
  " | Source: " + source.getNode().getLocation().toString() +
  " | Sink: " + sink.getNode().getLocation().toString()

