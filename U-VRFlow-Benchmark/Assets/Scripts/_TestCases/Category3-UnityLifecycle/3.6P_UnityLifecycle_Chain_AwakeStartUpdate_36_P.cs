using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.6P
/// EXPECTED: TRUE POSITIVE
/// 3.6 Lifecycle_Chain [Positive]
public class UnityLifecycle_Chain_AwakeStartUpdate_36_P : MonoBehaviour
{
    private string _payload_36_P;

    void Awake()
    {
        _payload_36_P = TestSources.GetNetworkInput();
    }

    void Start()
    {
        if (!string.IsNullOrEmpty(_payload_36_P))
            _payload_36_P = "[MODIFIED] " + _payload_36_P;
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_36_P))
            TestSinks.DangerousLoad(_payload_36_P);
    }
}
