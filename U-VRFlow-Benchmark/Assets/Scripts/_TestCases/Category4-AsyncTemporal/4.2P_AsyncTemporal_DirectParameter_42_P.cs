using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category13-Asynchronous/13.4P
/// EXPECTED: TRUE POSITIVE
/// 4.2 Direct coroutine parameter [Positive]
public class AsyncTemporal_DirectParameter_42_P : MonoBehaviour
{
    void Start() { StartCoroutine(Emit(TestSources.GetNetworkInput())); }
    private IEnumerator Emit(string value) { yield return null; TestSinks.DangerousLoad(value); }
}
