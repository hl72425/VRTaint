using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category13-Asynchronous/13.3P
/// EXPECTED: TRUE POSITIVE
/// 5.12 String coroutine payload [Positive]
public class DynamicInvocation_StringPayload_512_P : MonoBehaviour
{
    void Start() { StartCoroutine("Emit", TestSources.GetNetworkInput()); }
    private IEnumerator Emit(object value) { yield return null; TestSinks.DangerousLoad(value.ToString()); }
}
