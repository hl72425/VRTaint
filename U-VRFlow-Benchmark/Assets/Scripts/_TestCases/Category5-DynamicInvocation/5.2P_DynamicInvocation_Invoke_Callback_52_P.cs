using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.1bP
/// EXPECTED: TRUE POSITIVE
/// 5.2 MonoBehaviour.Invoke callback reads tainted field [Positive]
/// Invoke dispatches to a callback that reads the tainted field and passes it to a Helper Sink.
/// Sink: DangerousLoad via Invoke → callback chain.
public class DynamicInvocation_Invoke_Callback_52_P : MonoBehaviour
{
    private string _payload_52_P;

    void Awake()
    {
        _payload_52_P = TestSources.GetUIInput();
    }

    void Start()
    {
        Invoke("HandleTainted", 0.0f);
    }

    void HandleTainted()
    {
        if (!string.IsNullOrEmpty(_payload_52_P))
            TestSinks.DangerousLoad(_payload_52_P);
    }
}
