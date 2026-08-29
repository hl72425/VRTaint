using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category11-Lifecycle/11.8P
/// EXPECTED: TRUE POSITIVE
/// 3.15 Conditional trigger callback cannot kill lifecycle taint [Positive]
public class UnityLifecycle_ConditionalEventKill_315_P : MonoBehaviour
{
    private string _payload_315_P;
    void Awake() { _payload_315_P = TestSources.GetNetworkInput(); }
    void OnTriggerEnter() { _payload_315_P = "safe_default"; }
    void Update() { TestSinks.DangerousLoad(_payload_315_P); }
}
