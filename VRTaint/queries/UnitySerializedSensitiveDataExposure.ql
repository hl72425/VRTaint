/**
 * @name Unity serialized privacy exposure
 * @kind problem
 * @id cs/unity-serialized-sensitive-data-exposure
 * @precision high
 * @problem.severity warning
 * @security-severity 7.5
 * @tags security external/cwe/cwe-359
 */
import csharp
import lib.UnitySensitivePrivacy
import lib.UnityPrivacyLegacyFacts

from Class anchor, string sourceKind, string sinkKind, string assetPath,
     int configLine, string evidence, string confidence
where
  unitySerializedPrivacyExposureModel(
    anchor.getFile().getRelativePath(), anchor.getLocation().getStartLine(),
    sourceKind, sinkKind, assetPath, configLine, evidence, confidence
  ) and
  confidence in ["high", "medium"]
select anchor,
  "Serialized Unity configuration exposes " + sourceKind + " through " + sinkKind +
  " in " + assetPath + ":" + configLine.toString() + ". " + evidence
