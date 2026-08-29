using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.4N
/// EXPECTED: TRUE NEGATIVE
/// 3.4 FixedUpdate → LateUpdate [Negative]
public class UnityLifecycle_FixedUpdateLateUpdate_34_N : MonoBehaviour
{
    private string _payload_34_N;

    void FixedUpdate()
    {
        _payload_34_N = TestSources.GetNetworkInput();
    }

    void LateUpdate()
    {
        Helper1();
        if (!string.IsNullOrEmpty(_payload_34_N))
            TestSinks.DangerousLoad(_payload_34_N);
    }

    void Helper1()
    {
        Helper2();
    }

    void Helper2()
    {
        _payload_34_N = "safe_default";
    }
}
