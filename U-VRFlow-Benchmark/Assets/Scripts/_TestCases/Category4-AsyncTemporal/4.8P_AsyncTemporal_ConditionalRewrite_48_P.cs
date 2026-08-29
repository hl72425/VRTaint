using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.15P
/// EXPECTED: TRUE POSITIVE
/// 4.8 Conditional tainted rewrite after clean [Positive]
public class AsyncTemporal_ConditionalRewrite_48_P : MonoBehaviour
{
    public bool reload;
    private string _payload_48_P;
    void Start() { _payload_48_P = "safe_default"; if (reload) _payload_48_P = TestSources.GetNetworkInput(); StartCoroutine(Emit()); }
    private IEnumerator Emit() { yield return null; TestSinks.DangerousLoad(_payload_48_P); }
}
