using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.7P
/// EXPECTED: TRUE POSITIVE
/// 7.7 Serialized reference return owner [Positive]
public class ConfigurationRecoveredEdges_ReferenceReturnOwner_77_P : MonoBehaviour
{
    public ConfigurationRecoveredEdges_ReferenceReturnTarget_77_P target;
    void Awake() { target.Store(TestSources.GetNetworkInput()); }
    void Start() { TestSinks.DangerousLoad(target.Read()); }
}
