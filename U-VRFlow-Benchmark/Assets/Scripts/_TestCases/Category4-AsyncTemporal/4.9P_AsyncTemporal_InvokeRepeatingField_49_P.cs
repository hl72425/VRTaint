using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.17P
/// EXPECTED: TRUE POSITIVE
/// 4.9 InvokeRepeating persistent field [Positive]
public class AsyncTemporal_InvokeRepeatingField_49_P : MonoBehaviour
{
    private string _payload_49_P;
    void Start() { _payload_49_P = TestSources.GetNetworkInput(); InvokeRepeating(nameof(Emit), 0.1f, 1.0f); }
    private void Emit() { TestSinks.DangerousLoad(_payload_49_P); }
}
