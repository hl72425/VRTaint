using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category13-Asynchronous/13.23P
/// EXPECTED: TRUE POSITIVE
/// 5.17 BroadcastMessage payload [Positive]
public class DynamicInvocation_BroadcastMessagePayload_517_P : MonoBehaviour
{
    void Start() { BroadcastMessage("ReceiveBroadcast", TestSources.GetNetworkInput()); }
    private void ReceiveBroadcast(object value) { TestSinks.DangerousLoad(value.ToString()); }
}
