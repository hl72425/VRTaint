using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category11-Lifecycle/11.3P
/// EXPECTED: TRUE POSITIVE
public class UnityLifecycle_InheritedBase_312_P : MonoBehaviour
{
    protected string _payload_312_P;
    protected virtual void Update() { TestSinks.DangerousLoad(_payload_312_P); }
}

/// 3.12 Inherited callback and field [Positive]
public class UnityLifecycle_InheritedDerived_312_P : UnityLifecycle_InheritedBase_312_P
{
    void Awake() { _payload_312_P = TestSources.GetNetworkInput(); }
}
