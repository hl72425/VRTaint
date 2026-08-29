/**
 * @name Unity recovered sensitive data exposure
 * @kind problem
 * @id cs/unity-recovered-sensitive-data-exposure
 * @precision high
 * @problem.severity warning
 * @security-severity 7.5
 * @tags security external/cwe/cwe-359
 */
import csharp
import lib.UnitySensitivePrivacy
import lib.UnityPrivacyLegacyFacts

from MethodCall sink, string sourcePath, int sourceLine, string sourceKind,
     string sinkKind, string bridge, string confidence
where
  unityRecoveredPrivacyExposureModel(
    sourcePath, sourceLine, sourceKind,
    sink.getFile().getRelativePath(), sink.getLocation().getStartLine(), sinkKind,
    bridge, confidence
  ) and confidence in ["high", "medium"]
select sink, "Recovered Unity semantic flow from " + sourceKind + " at " + sourcePath +
  ":" + sourceLine.toString() + " reaches " + sinkKind + ". bridge=" + bridge
