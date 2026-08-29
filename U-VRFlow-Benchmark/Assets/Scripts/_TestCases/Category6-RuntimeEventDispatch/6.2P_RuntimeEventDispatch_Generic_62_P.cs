using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category6-RuntimeEventDispatch
/// LEGACY CASE: Category3-UnityEvent/3.3P
/// EXPECTED: TRUE POSITIVE
/// 6.2 Generic UnityEvent<int> [Positive]
/// AddListener in Awake, source is int-parsed from UI input, invoke in Start.
/// Callback uses tainted int in Sink (via length).
public class RuntimeEventDispatch_Generic_62_P : MonoBehaviour
{
    public UnityEvent<int> onNumberReceived;
    private string _payload_62_P;

    void Awake()
    {
        onNumberReceived.AddListener(HandleNumber);
        _payload_62_P = TestSources.GetUIInput();
    }

    void Start()
    {
        if (int.TryParse(_payload_62_P, out int num))
            onNumberReceived.Invoke(num);
    }

    void HandleNumber(int _payload_62_P_T)
    {
        // Use value as argument to dangerous operation (e.g., file write)
        TestSinks.DangerousFileWrite("/tmp/number.txt", _payload_62_P_T.ToString());
    }
}
