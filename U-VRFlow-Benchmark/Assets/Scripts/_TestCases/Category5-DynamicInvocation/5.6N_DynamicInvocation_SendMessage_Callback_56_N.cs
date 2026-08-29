using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.3bN
/// EXPECTED: TRUE NEGATIVE
/// 5.6 SendMessage with tainted parameter [Negative]
/// Parameter sanitized via ToUpper (Barrier) before passed into SendMessage.
public class DynamicInvocation_SendMessage_Callback_56_N : MonoBehaviour
{
    private string _payload_56_N;

    void Awake()
    {
        _payload_56_N = TestSources.GetFileContent();
    }

    void Start()
    {
        string safe = _payload_56_N.ToUpper(); // Barrier
        gameObject.SendMessage("HandleData", safe);
    }

    void HandleData(string _payload_56_N_T)
    {
        TestSinks.DangerousFileWrite("/tmp/safe.txt", _payload_56_N_T);
    }
}
