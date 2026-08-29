using UnityEngine;
using System.Reflection;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.4N
/// EXPECTED: TRUE NEGATIVE
/// 5.7 MethodInfo.Invoke [Negative]
/// Argument sanitized via ToUpper (Barrier) before placed into parameters array.
public class DynamicInvocation_MethodInfoInvoke_57_N : MonoBehaviour
{
    private string _payload_57_N;
    private MethodInfo _cachedMethod;

    void Awake()
    {
        _payload_57_N = TestSources.GetCmdArgs()[0];
        _cachedMethod = GetType().GetMethod("DummyMethod");
    }

    void Start()
    {
        if (_cachedMethod != null)
        {
            string safe = _payload_57_N.ToUpper(); // Barrier
            _cachedMethod.Invoke(this, new object[] { safe });
        }
    }

    public void DummyMethod() { }
}
