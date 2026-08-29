using UnityEngine;
using System.Reflection;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.4bP
/// EXPECTED: TRUE POSITIVE
/// 5.8 MethodInfo.Invoke with tainted parameter [Positive]
/// Tainted data flows into Invoke's object[] array and reaches the
/// callback's string parameter.
public class DynamicInvocation_MethodInfoInvoke_Callback_58_P : MonoBehaviour
{
    private string _payload_58_P;
    private MethodInfo _cachedMethod;

    void Awake()
    {
        _payload_58_P = TestSources.GetNetworkInput();
        _cachedMethod = GetType().GetMethod("HandleData");
    }

    void Start()
    {
        if (_cachedMethod != null)
            _cachedMethod.Invoke(this, new object[] { _payload_58_P });
    }

    public void HandleData(string _payload_58_P_T)
    {
        if (!string.IsNullOrEmpty(_payload_58_P_T))
            TestSinks.DangerousLoad(_payload_58_P_T);
    }
}
