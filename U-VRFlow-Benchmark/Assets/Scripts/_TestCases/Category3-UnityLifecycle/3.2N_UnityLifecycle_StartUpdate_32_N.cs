using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.2N
/// EXPECTED: TRUE NEGATIVE
/// 3.2 Start → Update [Negative]
public class UnityLifecycle_StartUpdate_32_N : MonoBehaviour
{
    private string _payload_32_N;

    void Start()
    {
        _payload_32_N = TestSources.GetNetworkInput();
        HelperMethod();
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_32_N))
            TestSinks.DangerousLoad(_payload_32_N);
    }

    void HelperMethod() { _payload_32_N = "safe_default"; }
}
