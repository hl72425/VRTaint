using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category13-Asynchronous/13.9N
/// EXPECTED: TRUE NEGATIVE
/// 5.13 Custom same-name StartCoroutine [Negative]
public class DynamicInvocation_CustomApi_513_N : MonoBehaviour
{
    private string _payload_513_N;
    private new void StartCoroutine(string callback) { }
    void Start() { _payload_513_N = TestSources.GetNetworkInput(); StartCoroutine("Emit"); }
    private IEnumerator Emit() { yield return null; TestSinks.DangerousLoad(_payload_513_N); }
}
