using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.6P
/// EXPECTED: TRUE POSITIVE
/// 7.6 Serialized event argument index target [Positive]
public class ConfigurationRecoveredEdges_ArgumentIndexTarget_76_P : MonoBehaviour
{
    public void HandleSecond(string value) { TestSinks.DangerousLoad(value); }
}
