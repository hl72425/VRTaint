/**
 * @name Unity semantic external input to security sink
 * @description A runtime data-bearing Unity semantic source reaches a standard security sink.
 * @kind path-problem
 * @id cs/unity-semantic-taint-security
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @tags security
 */

import csharp
import lib.VRTaintFlowFramework
import lib.UnityStandardSourceSink
import lib.SemanticTaintFacts

module SemanticSecurityConfig implements ProjectConfigSig {
  predicate isSource(DataFlow::Node source) { SemanticTaintFacts::isSecurityDataSeed(source) }
  predicate isSink(DataFlow::Node sink) { UnityStandardSourceSink::isStandardSink(sink) }
  predicate isBarrier(DataFlow::Node node) { UnityStandardSourceSink::isStandardBarrier(node) }
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    SemanticTaintFacts::methodEdge(pred, succ)
  }
}

module SemanticSecurityFlow = VRTaintFlow<SemanticSecurityConfig>;
module SemanticSecurityTracking = TaintTracking::Global<SemanticSecurityFlow>;
import SemanticSecurityTracking::PathGraph

from SemanticSecurityTracking::PathNode source, SemanticSecurityTracking::PathNode sink,
     string factId, string objectId, string accessPath, string phase,
     string context, string sourceKind, string influenceKind, string confidence,
     string sinkKind
where
  SemanticSecurityTracking::flowPath(source, sink) and
  SemanticTaintFacts::seed(source.getNode(), factId, objectId, accessPath, phase,
                           context, sourceKind, influenceKind, confidence) and
  influenceKind = "data" and
  SemanticTaintFacts::isProjectRuntimeNode(source.getNode()) and
  SemanticTaintFacts::isProjectRuntimeNode(sink.getNode()) and
  UnityStandardSourceSink::isStandardSinkKind(sink.getNode(), sinkKind) and
  SemanticTaintFacts::isCompatibleSecurityFlow(source.getNode(), sink.getNode())
select sink.getNode(), source, sink,
  "Semantic source " + sourceKind + " (" + factId + ") reaches $@.",
  sink.getNode(), sinkKind
