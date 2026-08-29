using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.6N
/// EXPECTED: TRUE NEGATIVE
/// 7.6 Unconfigured event argument index target [Negative]
public class ConfigurationRecoveredEdges_WrongArgumentTarget_76_N : MonoBehaviour
{
    public void HandleSecond(string value) { TestSinks.DangerousLoad(value); }
}
