using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.19P
/// EXPECTED: TRUE POSITIVE
/// 4.10 Coroutine pre-yield read [Positive]
public class AsyncTemporal_PreYieldRead_410_P : MonoBehaviour
{
    private string _payload_410_P;
    void Start() { _payload_410_P = TestSources.GetNetworkInput(); StartCoroutine(Emit()); }
    private IEnumerator Emit() { TestSinks.DangerousLoad(_payload_410_P); yield return null; }
}
