using UnityEngine;
using System.Reflection;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.4bN
/// EXPECTED: TRUE NEGATIVE
/// 5.8 MethodInfo.Invoke with tainted parameter [Negative]
/// Argument sanitized via ToLower (Barrier) before placed into Invoke's object[] array.
public class DynamicInvocation_MethodInfoInvoke_Callback_58_N : MonoBehaviour
{
    private string _payload_58_N;
    private MethodInfo _cachedMethod;

    void Awake()
    {
        _payload_58_N = TestSources.GetCmdArgs()[0];
        _cachedMethod = GetType().GetMethod("HandleData");
    }

    void Start()
    {
        if (_cachedMethod != null)
        {
            string safe = _payload_58_N.ToLower(); // Barrier
            _cachedMethod.Invoke(this, new object[] { safe });
        }
    }

    public void HandleData(string data)
    {
        TestSinks.DangerousFileWrite("/tmp/safe.txt", data);
    }
}
