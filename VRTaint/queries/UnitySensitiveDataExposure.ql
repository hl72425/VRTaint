/**
 * @name Unity sensitive data exposure through outbound transports
 * @description Tracks microphone audio, XR pose/controller data, device identifiers,
 *              and location data to HTTP, WebSocket, socket, Photon, ROS, and gRPC
 *              disclosure points. VRTaint adds lifecycle/event/field/async propagation.
 * @kind path-problem
 * @precision high
 * @id cs/unity-sensitive-data-exposure
 * @problem.severity warning
 * @security-severity 7.5
 * @tags security
 *       external/cwe/cwe-359
 */

import csharp
import lib.VRTaintFlowFramework
import lib.UnitySensitivePrivacy
import lib.UnityDotNetEventFlow

module Config implements ProjectConfigSig {
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
    // Privacy-specific API summaries are layered on the shared VRTaint core.
    // Ordinary C# event/delegate dispatch is also an implicit invocation edge,
    // but remains a reusable language model rather than a project-specific fact.
    UnitySensitivePrivacy::isPrivacyAdditionalFlowStep(pred, succ) or
    UnityDotNetEventFlow::isDotNetEventFlowStep(pred, succ)
  }
}

module PrivacyConfig = VRTaintInstanceFlow<Config>;
module Flow = TaintTracking::GlobalWithState<PrivacyConfig>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink, string sourceKind, string sinkKind
where
  Flow::flowPath(source, sink) and
  UnitySensitivePrivacy::isCompatiblePrivacyFlow(
    source.getNode(), sink.getNode(), sourceKind, sinkKind
  )
select sink.getNode(), source, sink,
  "Sensitive Unity data (" + sourceKind + ") reaches outbound " + sinkKind +
  " payload handling. Validate user action, recipient, endpoint, and serialized scene binding."
