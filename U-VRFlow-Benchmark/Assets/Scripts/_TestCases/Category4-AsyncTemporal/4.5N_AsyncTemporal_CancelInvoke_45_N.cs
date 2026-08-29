using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.7N
/// EXPECTED: TRUE NEGATIVE
/// 4.5 CancelInvoke is not propagation [Negative]
public class AsyncTemporal_CancelInvoke_45_N : MonoBehaviour
{
    private string _payload_45_N;
    void Start() { _payload_45_N = TestSources.GetNetworkInput(); CancelInvoke("Emit"); }
    private void Emit() { TestSinks.DangerousLoad(_payload_45_N); }
}
