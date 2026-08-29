using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category11-Lifecycle/11.7P
/// EXPECTED: TRUE POSITIVE
/// 3.14 OnEnable to OnDisable to OnEnable to Update [Positive]
public class UnityLifecycle_DisableReenableClosure_314_P : MonoBehaviour
{
    private string _payload_314_P;
    private bool _initialized;
    void OnEnable() { if (!_initialized) { _payload_314_P = TestSources.GetNetworkInput(); _initialized = true; } }
    void OnDisable() { _initialized = true; }
    void Update() { TestSinks.DangerousLoad(_payload_314_P); }
}
