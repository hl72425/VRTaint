using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.8N
/// EXPECTED: TRUE NEGATIVE
/// 4.6 Invoke delay parameter semantics [Negative]
public class AsyncTemporal_InvokeDelay_46_N : MonoBehaviour
{
    void Start() { string value = TestSources.GetNetworkInput(); Invoke("Emit", value.Length); }
    private void Emit(float delay) { TestSinks.DangerousLoad(delay.ToString()); }
}
