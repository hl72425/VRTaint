using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.1N
/// EXPECTED: TRUE NEGATIVE
/// 3.1 Awake �� Start [Negative]
public class UnityLifecycle_AwakeStart_Overwritten_31_N : MonoBehaviour
{
    private string _payload_31_N;

    void Awake()
    {
        _payload_31_N = TestSources.GetUIInput();
    }

    void Start()
    {
        _payload_31_N = "safe_default";
        TestSinks.DangerousFileWrite("/tmp/test.txt", _payload_31_N);
    }
}
