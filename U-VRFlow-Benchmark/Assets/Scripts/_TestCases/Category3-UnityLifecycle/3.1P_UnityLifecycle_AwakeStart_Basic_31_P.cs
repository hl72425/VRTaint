using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.1P
/// EXPECTED: TRUE POSITIVE
/// 3.1 Awake → Start [Positive]
public class UnityLifecycle_AwakeStart_Basic_31_P : MonoBehaviour
{
    private string _payload_31_P;

    void Awake()
    {
        _payload_31_P = TestSources.GetNetworkInput();
    }

    void Start()
    {
        if (!string.IsNullOrEmpty(_payload_31_P))
            TestSinks.DangerousLoad(_payload_31_P);
    }
}
