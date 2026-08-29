using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.6P
/// EXPECTED: TRUE POSITIVE
/// 7.6 Serialized event argument index owner [Positive]
public class ConfigurationRecoveredEdges_ArgumentIndexOwner_76_P : MonoBehaviour
{
    public UnityEvent<string, string> onPair;
    void Start() { onPair.Invoke("safe_default", TestSources.GetNetworkInput()); }
}
