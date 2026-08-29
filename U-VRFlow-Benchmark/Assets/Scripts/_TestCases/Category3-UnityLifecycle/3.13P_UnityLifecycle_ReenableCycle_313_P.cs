using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category11-Lifecycle/11.6P
/// EXPECTED: TRUE POSITIVE
/// 3.13 OnEnable re-entry across frames [Positive]
public class UnityLifecycle_ReenableCycle_313_P : MonoBehaviour
{
    private bool _initialized;
    private string _payload_313_P;
    void OnEnable()
    {
        if (!_initialized) { _payload_313_P = TestSources.GetNetworkInput(); _initialized = true; }
        else { TestSinks.DangerousLoad(_payload_313_P); }
    }
}
