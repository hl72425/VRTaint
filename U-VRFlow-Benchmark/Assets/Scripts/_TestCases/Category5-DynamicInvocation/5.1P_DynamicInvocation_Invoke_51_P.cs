using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.1P
/// EXPECTED: TRUE POSITIVE
/// 5.1 MonoBehaviour.Invoke [Positive]
/// Tainted method name stored in field, then passed to Invoke in another lifecycle method.
/// Sink: Invoke(methodName) where methodName is tainted.
public class DynamicInvocation_Invoke_51_P : MonoBehaviour
{
    private string _payload_51_P;

    void Awake()
    {
        _payload_51_P = TestSources.GetUIInput();
    }

    void Start()
    {
        Invoke(_payload_51_P, 0.0f);
    }
}
