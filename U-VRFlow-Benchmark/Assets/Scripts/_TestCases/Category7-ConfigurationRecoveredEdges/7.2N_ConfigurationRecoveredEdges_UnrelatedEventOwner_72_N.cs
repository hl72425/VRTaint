using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.1N
/// EXPECTED: TRUE NEGATIVE
/// 7.2 Unrelated serialized event field [Negative]
public class ConfigurationRecoveredEdges_UnrelatedEventOwner_72_N : MonoBehaviour
{
    public UnityEvent<string> onBound;
    public UnityEvent<string> onUnbound;
    void Start() { onBound.Invoke("safe_default"); onUnbound.Invoke(TestSources.GetNetworkInput()); }
}
