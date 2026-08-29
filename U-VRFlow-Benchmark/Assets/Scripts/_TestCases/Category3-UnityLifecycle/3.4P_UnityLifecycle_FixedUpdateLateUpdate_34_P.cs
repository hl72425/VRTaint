using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.4P
/// EXPECTED: TRUE POSITIVE
/// 3.4 FixedUpdate �� LateUpdate [Positive]
///
public class UnityLifecycle_FixedUpdateLateUpdate_34_P : MonoBehaviour
{
    private string _payload_34_P;
    public bool enableSanitizer;

    void FixedUpdate()
    {
        _payload_34_P = TestSources.GetNetworkInput();
    }

    void LateUpdate()
    {
        Helper();
        if (!string.IsNullOrEmpty(_payload_34_P))
            TestSinks.DangerousLoad(_payload_34_P);
    }

    void Helper()
    {
        if (enableSanitizer)
        {
            _payload_34_P = "safe_default";
        }
    }
}
