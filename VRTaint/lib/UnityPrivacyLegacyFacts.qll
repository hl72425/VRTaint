/**
 * Compatibility contract for historical configuration/result projections.
 * Production VRTaint privacy flow does not import this module.
 */
import csharp

/** Compatibility declaration for historical buildless source-location facts. */
extensible predicate unityPrivacySourceLocationModel(
  string scriptPath, int sourceLine, string sourceKind, string evidence
);

extensible predicate unitySerializedPrivacyExposureModel(
  string scriptPath, int codeLine, string sourceKind, string sinkKind,
  string assetPath, int configLine, string evidence, string confidence
);

extensible predicate unityRecoveredPrivacyExposureModel(
  string sourcePath, int sourceLine, string sourceKind,
  string sinkPath, int sinkLine, string sinkKind,
  string bridge, string confidence
);
