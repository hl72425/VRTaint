using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.4N
/// EXPECTED: TRUE NEGATIVE
/// 7.5 Disabled serialized event target [Negative]
public class ConfigurationRecoveredEdges_DisabledEventTarget_75_N : MonoBehaviour
{
    public void HandleDisabled(string value) { TestSinks.DangerousLoad(value); }
}
