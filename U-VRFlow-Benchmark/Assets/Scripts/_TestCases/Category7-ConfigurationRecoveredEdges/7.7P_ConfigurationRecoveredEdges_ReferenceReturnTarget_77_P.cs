using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.7P
/// EXPECTED: TRUE POSITIVE
/// 7.7 Serialized reference return target [Positive]
public class ConfigurationRecoveredEdges_ReferenceReturnTarget_77_P : MonoBehaviour
{
    private string _payload_77_P;
    public void Store(string value) { _payload_77_P = value; }
    public string Read() { return _payload_77_P; }
}
