using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.3P
/// EXPECTED: TRUE POSITIVE
/// 7.4 Serialized reference target [Positive]
public class ConfigurationRecoveredEdges_ReferenceTarget_74_P : MonoBehaviour
{
    private string _payload_74_P;
    public void Store(string value) { _payload_74_P = value; }
    public void Execute() { TestSinks.DangerousLoad(_payload_74_P); }
}
