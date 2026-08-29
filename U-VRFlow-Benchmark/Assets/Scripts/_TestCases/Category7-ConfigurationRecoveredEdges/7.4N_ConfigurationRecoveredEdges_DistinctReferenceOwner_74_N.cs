using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.3N
/// EXPECTED: TRUE NEGATIVE
/// 7.4 Distinct serialized reference targets [Negative]
public class ConfigurationRecoveredEdges_DistinctReferenceOwner_74_N : MonoBehaviour
{
    public ConfigurationRecoveredEdges_DistinctReferenceTarget_74_N writerTarget;
    public ConfigurationRecoveredEdges_DistinctReferenceTarget_74_N readerTarget;
    void Awake() { writerTarget.Store(TestSources.GetNetworkInput()); }
    void Start() { readerTarget.Execute(); }
}
