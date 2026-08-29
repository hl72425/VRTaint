using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.1N
/// EXPECTED: TRUE NEGATIVE
/// 7.2 Only onBound targets this sink [Negative]
public class ConfigurationRecoveredEdges_UnrelatedEventTarget_72_N : MonoBehaviour
{
    public void HandleBound(string value) { TestSinks.DangerousLoad(value); }
}
