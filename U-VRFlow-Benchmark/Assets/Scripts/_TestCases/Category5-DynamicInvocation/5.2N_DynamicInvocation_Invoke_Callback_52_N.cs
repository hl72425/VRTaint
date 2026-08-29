using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.1bN
/// EXPECTED: TRUE NEGATIVE
/// 5.2 MonoBehaviour.Invoke callback reads field [Negative]
/// Callback sanitizes field via ToUpper before passing to Sink.
public class DynamicInvocation_Invoke_Callback_52_N : MonoBehaviour
{
    private string _payload_52_N;

    void Awake()
    {
        _payload_52_N = TestSources.GetCmdArgs()[0];
    }

    void Start()
    {
        Invoke("HandleSafe", 0.0f);
    }

    void HandleSafe()
    {
        string safe = _payload_52_N.ToUpper(); // Barrier
        TestSinks.DangerousFileWrite("/tmp/safe.txt", safe);
    }
}
