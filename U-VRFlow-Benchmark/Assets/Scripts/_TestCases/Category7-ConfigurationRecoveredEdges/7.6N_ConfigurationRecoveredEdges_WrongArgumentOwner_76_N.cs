using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.6N
/// EXPECTED: TRUE NEGATIVE
/// 7.6 Unconfigured event argument index owner [Negative]
public class ConfigurationRecoveredEdges_WrongArgumentOwner_76_N : MonoBehaviour
{
    public UnityEvent<string, string> onPair;
    void Start() { onPair.Invoke(TestSources.GetNetworkInput(), "safe_default"); }
}
