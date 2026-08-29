using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.15N
/// EXPECTED: TRUE NEGATIVE
/// 4.8 Definite clean before coroutine [Negative]
public class AsyncTemporal_DefiniteClean_48_N : MonoBehaviour
{
    private string _payload_48_N;
    void Start() { _payload_48_N = TestSources.GetNetworkInput(); _payload_48_N = "safe_default"; StartCoroutine(Emit()); }
    private IEnumerator Emit() { yield return null; TestSinks.DangerousLoad(_payload_48_N); }
}
