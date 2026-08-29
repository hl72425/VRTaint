using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.4N
/// EXPECTED: TRUE NEGATIVE
/// 7.5 Disabled serialized event owner [Negative]
public class ConfigurationRecoveredEdges_DisabledEventOwner_75_N : MonoBehaviour
{
    public UnityEvent<string> onDisabled;
    void Start() { onDisabled.Invoke(TestSources.GetNetworkInput()); }
}
