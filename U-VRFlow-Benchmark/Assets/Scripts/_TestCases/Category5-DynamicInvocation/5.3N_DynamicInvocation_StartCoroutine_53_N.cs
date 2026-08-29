using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.2N
/// EXPECTED: TRUE NEGATIVE
/// 5.3 StartCoroutine with string [Negative]
/// Tainted coroutine name is sanitized via ToUpper (Barrier) before use.
public class DynamicInvocation_StartCoroutine_53_N : MonoBehaviour
{
    private string _payload_53_N;

    void Awake()
    {
        _payload_53_N = TestSources.GetCmdArgs()[0];
        _payload_53_N = _payload_53_N.ToUpper(); // Barrier
    }

    void Start()
    {
        StartCoroutine(_payload_53_N);
    }
}
