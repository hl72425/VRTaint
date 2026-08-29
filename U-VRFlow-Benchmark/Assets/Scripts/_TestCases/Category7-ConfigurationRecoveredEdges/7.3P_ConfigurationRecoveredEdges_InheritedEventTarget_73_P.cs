using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.2P
/// EXPECTED: TRUE POSITIVE
/// 7.3 Inherited event target [Positive]
public class ConfigurationRecoveredEdges_InheritedEventTarget_73_P : MonoBehaviour
{
    public void HandleInherited(string value) { TestSinks.DangerousLoad(value); }
}
