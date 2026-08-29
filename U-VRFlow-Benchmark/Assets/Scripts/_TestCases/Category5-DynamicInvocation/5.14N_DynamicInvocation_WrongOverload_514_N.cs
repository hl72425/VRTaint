using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category13-Asynchronous/13.10N
/// EXPECTED: TRUE NEGATIVE
/// 5.14 Wrong coroutine overload [Negative]
public class DynamicInvocation_WrongOverload_514_N : MonoBehaviour
{
    private string _payload_514_N;
    void Start() { _payload_514_N = TestSources.GetNetworkInput(); StartCoroutine("Emit"); }
    private IEnumerator Emit(string unused) { yield return null; TestSinks.DangerousLoad(_payload_514_N); }
}
