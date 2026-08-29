using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.6N
/// EXPECTED: TRUE NEGATIVE
/// 4.4 Write after coroutine dispatch [Negative]
public class AsyncTemporal_WriteAfterDispatch_44_N : MonoBehaviour
{
    private string _payload_44_N;
    void Start() { StartCoroutine(Emit()); _payload_44_N = TestSources.GetNetworkInput(); }
    private IEnumerator Emit() { TestSinks.DangerousLoad(_payload_44_N); yield return null; }
}
