using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.1N
/// EXPECTED: TRUE NEGATIVE
/// 5.1 MonoBehaviour.Invoke [Negative]
public class DynamicInvocation_Invoke_51_N : MonoBehaviour
{
    private string _payload_51_N;

    void Awake()
    {
        _payload_51_N = TestSources.GetCmdArgs()[0];
    }

    void Start()
    {
        _payload_51_N="_Safe"; // Barrier
        Invoke(_payload_51_N, 0.0f);
    }
}
