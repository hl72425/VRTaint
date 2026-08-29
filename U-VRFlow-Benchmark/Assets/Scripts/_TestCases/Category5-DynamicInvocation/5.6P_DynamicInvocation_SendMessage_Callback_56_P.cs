using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.3bP
/// EXPECTED: TRUE POSITIVE
/// 5.6 SendMessage with tainted parameter [Positive]
/// Method name is hardcoded ("HandleData"), taint flows through SendMessage's
/// second parameter (object) into the callback's string parameter.
public class DynamicInvocation_SendMessage_Callback_56_P : MonoBehaviour
{
    private string _payload_56_P;

    void Awake()
    {
        _payload_56_P = TestSources.GetUIInput();
    }

    void Start()
    {
        gameObject.SendMessage("HandleData", _payload_56_P);
    }

    void HandleData(string _payload_56_P_T)
    {
        if (!string.IsNullOrEmpty(_payload_56_P_T))
            TestSinks.DangerousLoad(_payload_56_P_T);
    }
}
