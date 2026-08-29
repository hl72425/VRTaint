using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.3N
/// EXPECTED: TRUE NEGATIVE
/// 7.4 Distinct reference target type [Negative]
public class ConfigurationRecoveredEdges_DistinctReferenceTarget_74_N : MonoBehaviour
{
    private string _payload_74_N;
    public void Store(string value) { _payload_74_N = value; }
    public void Execute() { TestSinks.DangerousLoad(_payload_74_N); }
}
