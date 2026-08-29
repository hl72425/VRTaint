using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.2P
/// EXPECTED: TRUE POSITIVE
/// 5.3 StartCoroutine with string [Positive]
/// Tainted coroutine name stored in field, used in StartCoroutine.
/// Sink: StartCoroutine(methodName)
public class DynamicInvocation_StartCoroutine_53_P : MonoBehaviour
{
    private string _payload_53_P;

    void Awake()
    {
        _payload_53_P = TestSources.GetNetworkInput();
    }

    void Start()
    {
        StartCoroutine(_payload_53_P);
    }
}
