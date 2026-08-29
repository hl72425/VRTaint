using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.3N
/// EXPECTED: TRUE NEGATIVE
/// 3.3 OnEnable → OnDisable [Negative]
public class UnityLifecycle_OnEnableOnDisable_Reassign_33_N : MonoBehaviour
{
    private string _payload_33_N;

    void OnEnable()
    {
        _payload_33_N = TestSources.GetCmdArgs()[0];
    }

    void OnDisable()
    {
        Helper();
        TestSinks.DangerousFileWrite("/tmp/dis.txt", _payload_33_N);
    }

    void Helper()
    {
        _payload_33_N = "safe_default";
    }
}
