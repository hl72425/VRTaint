using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.3P
/// EXPECTED: TRUE POSITIVE
/// 7.4 Serialized reference owner [Positive]
public class ConfigurationRecoveredEdges_ReferenceOwner_74_P : MonoBehaviour
{
    public ConfigurationRecoveredEdges_ReferenceTarget_74_P target;
    void Awake() { target.Store(TestSources.GetNetworkInput()); }
    void Start() { target.Execute(); }
}
