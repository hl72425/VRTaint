using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category11-Lifecycle/11.5N
/// EXPECTED: TRUE NEGATIVE
/// 2.12 Nested helper on wrong receiver [Negative]
public class ObjectIdentityHeap_NestedWrongReceiver_212_N : MonoBehaviour
{
    public ObjectIdentityHeap_NestedWrongReceiver_212_N other;
    private string _payload_212_N;
    void Awake() { other.Initialize(); }
    void Start() { Consume(); }
    private void Initialize() { Store(); }
    private void Store() { _payload_212_N = TestSources.GetNetworkInput(); }
    private void Consume() { TestSinks.DangerousLoad(_payload_212_N); }
}
