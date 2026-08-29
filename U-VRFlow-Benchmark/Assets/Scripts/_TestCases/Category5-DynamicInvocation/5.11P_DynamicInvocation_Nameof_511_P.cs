using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category13-Asynchronous/13.2P
/// EXPECTED: TRUE POSITIVE
/// 5.11 StartCoroutine nameof [Positive]
public class DynamicInvocation_Nameof_511_P : MonoBehaviour
{
    private string _payload_511_P;
    void Start() { _payload_511_P = TestSources.GetNetworkInput(); StartCoroutine(nameof(Emit)); }
    private IEnumerator Emit() { yield return null; TestSinks.DangerousLoad(_payload_511_P); }
}
