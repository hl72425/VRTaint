using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.3P
/// EXPECTED: TRUE POSITIVE
/// 3.3 OnEnable → OnDisable [Positive]
public class UnityLifecycle_OnEnableOnDisable_33_P : MonoBehaviour
{
    private string _payload_33_P;

    void OnEnable()
    {
        _payload_33_P = TestSources.GetUIInput();
    }

    void Update()
    {
        print("test");
    }

    void OnDisable()
    {
        if (!string.IsNullOrEmpty(_payload_33_P))
            TestSinks.DangerousLoad(_payload_33_P);
    }
}
