/**
 * @name Unity semantic taint trace endpoints
 * @description Emits evidence rows for generic five-tuple semantic seeds and project-owned effects.
 * @kind table
 * @id cs/unity-semantic-taint-trace
 */

import csharp
import lib.VRTaintFlowFramework
import lib.UnityStandardSourceSink
import lib.SemanticTaintFacts
import lib.SemanticTaintDomain

module SemanticTraceConfig implements ProjectConfigSig {
  predicate isSource(DataFlow::Node source) { SemanticTaintFacts::isSeed(source) }
  predicate isSink(DataFlow::Node sink) { SemanticTaintDomain::isObservation(sink) }
  predicate isBarrier(DataFlow::Node node) { UnityStandardSourceSink::isStandardBarrier(node) }
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    SemanticTaintFacts::methodEdge(pred, succ)
  }
}

module SemanticTraceFlow = VRTaintFlow<SemanticTraceConfig>;
module SemanticTraceTracking = TaintTracking::Global<SemanticTraceFlow>;

from DataFlow::Node source, DataFlow::Node sink,
     string factId, string objectId, string accessPath, string phase,
     string context, string sourceKind, string influenceKind, string confidence
where
  SemanticTaintFacts::seed(source, factId, objectId, accessPath, phase, context,
                           sourceKind, influenceKind, confidence) and
  SemanticTraceTracking::flow(source, sink)
select factId, objectId, accessPath, phase, context, sourceKind, influenceKind,
  confidence, source, sink, SemanticTaintDomain::endpointKind(sink),
  SemanticTaintDomain::endpointObject(sink), SemanticTaintDomain::endpointPath(sink),
  SemanticTaintDomain::endpointPhase(sink), SemanticTaintDomain::endpointContext(sink)
