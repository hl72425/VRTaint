/**
 * @name Unity sensitive data exposure (endpoint-directed)
 * @description Tracks Unity/VR sensitive values to outbound transports with
 *              focused audio-buffer and C# event summaries. Serialized
 *              configuration disclosures are handled by the companion
 *              configuration query.
 * @kind path-problem
 * @precision high
 * @id cs/unity-sensitive-data-exposure-fast
 * @problem.severity warning
 * @security-severity 7.5
 * @tags security
 *       external/cwe/cwe-359
 */

import csharp
import lib.UnitySensitivePrivacy
import lib.UnityDotNetEventFlow

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    UnitySensitivePrivacy::isSensitiveSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    UnitySensitivePrivacy::isDisclosureSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    node.asExpr() instanceof Literal
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    UnitySensitivePrivacy::isPrivacyAdditionalFlowStep(pred, succ) or
    UnityDotNetEventFlow::isDotNetEventFlowStep(pred, succ)
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink, string sourceKind, string sinkKind
where
  Flow::flowPath(source, sink) and
  UnitySensitivePrivacy::isCompatiblePrivacyFlow(
    source.getNode(), sink.getNode(), sourceKind, sinkKind
  )
select sink.getNode(), source, sink,
  "Sensitive Unity data (" + sourceKind + ") reaches outbound " + sinkKind +
  " handling through endpoint-directed CodeQL flow."
