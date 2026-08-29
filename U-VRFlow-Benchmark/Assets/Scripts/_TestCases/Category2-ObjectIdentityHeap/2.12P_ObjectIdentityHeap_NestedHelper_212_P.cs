using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category11-Lifecycle/11.5P
/// EXPECTED: TRUE POSITIVE
/// 2.12 Nested lifecycle helper [Positive]
public class ObjectIdentityHeap_NestedHelper_212_P : MonoBehaviour
{
    private string _payload_212_P;
    void Awake() { Initialize(); }
    void Start() { Consume(); }
    private void Initialize() { Store(); }
    private void Store() { _payload_212_P = TestSources.GetNetworkInput(); }
    private void Consume() { TestSinks.DangerousLoad(_payload_212_P); }
}
