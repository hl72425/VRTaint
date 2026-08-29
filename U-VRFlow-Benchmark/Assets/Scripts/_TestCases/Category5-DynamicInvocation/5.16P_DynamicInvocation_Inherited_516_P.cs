using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category13-Asynchronous/13.14P
/// EXPECTED: TRUE POSITIVE
public class DynamicInvocation_InheritedBase_516_P : MonoBehaviour
{
    protected string _payload_516_P;
    protected IEnumerator Emit() { yield return null; TestSinks.DangerousLoad(_payload_516_P); }
}
/// 5.16 Inherited coroutine [Positive]
public class DynamicInvocation_InheritedDerived_516_P : DynamicInvocation_InheritedBase_516_P
{
    void Start() { _payload_516_P = TestSources.GetNetworkInput(); StartCoroutine(Emit()); }
}
