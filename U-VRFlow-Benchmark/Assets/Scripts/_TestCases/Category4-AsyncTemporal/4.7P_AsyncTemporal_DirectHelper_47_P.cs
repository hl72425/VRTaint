using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.13P
/// EXPECTED: TRUE POSITIVE
/// 4.7 Direct coroutine helper write [Positive]
public class AsyncTemporal_DirectHelper_47_P : MonoBehaviour
{
    private string _payload_47_P;
    void Start() { Prepare(); StartCoroutine(Emit()); }
    private void Prepare() { _payload_47_P = TestSources.GetNetworkInput(); }
    private IEnumerator Emit() { yield return null; TestSinks.DangerousLoad(_payload_47_P); }
}
