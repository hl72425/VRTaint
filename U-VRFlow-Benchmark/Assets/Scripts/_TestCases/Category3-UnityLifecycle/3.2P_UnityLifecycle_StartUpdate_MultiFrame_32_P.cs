using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.2P
/// EXPECTED: TRUE POSITIVE
/// 3.2 Start → Update [Positive]
public class UnityLifecycle_StartUpdate_MultiFrame_32_P : MonoBehaviour
{
    private string _payload_32_P;

    void Start()
    {
        _payload_32_P = TestSources.GetNetworkInput();
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_32_P))
            Helper();
    }
    void Helper()
    {
        TestSinks.DangerousLoad(_payload_32_P);
    }
}
