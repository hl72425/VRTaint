using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category13-Asynchronous/13.11N
/// EXPECTED: TRUE NEGATIVE
/// 5.15 Wrong receiver before coroutine [Negative]
public class DynamicInvocation_WrongReceiver_515_N : MonoBehaviour
{
    public DynamicInvocation_WrongReceiver_515_N other;
    private string _payload_515_N;
    void Start() { other.Prepare(); StartCoroutine(nameof(Emit)); }
    private void Prepare() { _payload_515_N = TestSources.GetNetworkInput(); }
    private IEnumerator Emit() { yield return null; TestSinks.DangerousLoad(_payload_515_N); }
}
