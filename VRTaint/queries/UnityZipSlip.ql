/**
 * @name Arbitrary file write during Unity archive extraction (Zip Slip)
 * @description A path derived from a Unity SharpZipLib archive entry is used in a file-system
 *              operation without an official Zip Slip path sanitizer. The query combines
 *              CodeQL's official Zip Slip sinks and sanitizers with VRTaint's Unity-specific
 *              interprocedural and lifecycle flow semantics.
 * @kind path-problem
 * @id cs/unity-zipslip
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @tags security
 *       external/cwe/cwe-022
 */

import csharp
import semmle.code.csharp.security.dataflow.ZipSlipQuery
import lib.UnityArchiveZipSlip
import lib.VRTaintFlowFramework

module UnityZipSlipConfig implements ProjectConfigSig {
  predicate isSource(DataFlow::Node source) {
    isUnityArchiveEntryPathSource(source)
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { none() }
}

module UnityZipSlipFlow = VRTaintFlow<UnityZipSlipConfig>;
module UnityZipSlipTracking = TaintTracking::Global<UnityZipSlipFlow>;
import UnityZipSlipTracking::PathGraph

from UnityZipSlipTracking::PathNode source, UnityZipSlipTracking::PathNode sink
where UnityZipSlipTracking::flowPath(source, sink)
select source.getNode(), source, sink,
  "Unsanitized Unity archive entry path is used in a $@.", sink.getNode(),
  "file system operation"
