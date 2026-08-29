using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.17N
/// EXPECTED: TRUE NEGATIVE
/// 4.9 InvokeRepeating timing arguments [Negative]
public class AsyncTemporal_InvokeRepeatingTiming_49_N : MonoBehaviour
{
    void Start() { string value = TestSources.GetNetworkInput(); InvokeRepeating(nameof(Emit), value.Length, value.Length); }
    private void Emit(float value) { TestSinks.DangerousLoad(value.ToString()); }
}
