using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category11-Lifecycle/11.1P
/// EXPECTED: TRUE POSITIVE
/// 2.11 Lifecycle receiver preserved [Positive]
public class ObjectIdentityHeap_ReceiverSame_211_P : MonoBehaviour
{
    private string _payload_211_P;
    void Update() { WriteCurrent(); }
    void LateUpdate() { TestSinks.DangerousLoad(_payload_211_P); }
    private void WriteCurrent() { _payload_211_P = TestSources.GetNetworkInput(); }
}
