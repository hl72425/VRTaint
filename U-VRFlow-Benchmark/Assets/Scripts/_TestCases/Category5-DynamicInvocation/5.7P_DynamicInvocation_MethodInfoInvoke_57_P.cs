using UnityEngine;
using System.Reflection;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.4P
/// EXPECTED: TRUE POSITIVE
/// 5.7 MethodInfo.Invoke [Positive]
/// Tainted data stored in field, then passed as argument to Invoke in another method.
/// Sink: MethodInfo.Invoke(parameters...)
public class DynamicInvocation_MethodInfoInvoke_57_P : MonoBehaviour
{
    private string _payload_57_P;
    private MethodInfo _cachedMethod;

    void Awake()
    {
        _payload_57_P = TestSources.GetNetworkInput();
        _cachedMethod = GetType().GetMethod("DummyMethod");
    }

    void Start()
    {
        if (_cachedMethod != null)
            _cachedMethod.Invoke(this, new object[] { _payload_57_P });
    }

    public void DummyMethod() { }
}
