using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.5P
/// EXPECTED: TRUE POSITIVE
/// 4.3 Direct coroutine field resumption [Positive]
public class AsyncTemporal_DirectField_43_P : MonoBehaviour
{
    private string _payload_43_P;
    void Start() { _payload_43_P = TestSources.GetNetworkInput(); StartCoroutine(Emit()); }
    private IEnumerator Emit() { yield return null; TestSinks.DangerousLoad(_payload_43_P); }
}
