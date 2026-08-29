using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.3P
/// EXPECTED: TRUE POSITIVE
/// 5.5 SendMessage with string [Positive]
/// Tainted method name stored in field, then sent via SendMessage.
/// Sink: SendMessage(methodName)
public class DynamicInvocation_SendMessage_55_P : MonoBehaviour
{
    private string _payload_55_P;

    void Awake()
    {
        _payload_55_P = TestSources.GetUIInput();
    }

    void Start()
    {
        gameObject.SendMessage(_payload_55_P);
    }
}
