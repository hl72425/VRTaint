using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category11-Lifecycle/11.1N
/// EXPECTED: TRUE NEGATIVE
/// 2.11 Lifecycle wrong receiver [Negative]
public class ObjectIdentityHeap_WrongReceiver_211_N : MonoBehaviour
{
    public ObjectIdentityHeap_WrongReceiver_211_N other;
    private string _payload_211_N;
    void Update() { other.WriteOther(); }
    void LateUpdate() { TestSinks.DangerousLoad(_payload_211_N); }
    private void WriteOther() { _payload_211_N = TestSources.GetNetworkInput(); }
}
