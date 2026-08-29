using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category6-RuntimeEventDispatch
/// LEGACY CASE: Category3-UnityEvent/3.1P
/// EXPECTED: TRUE POSITIVE
/// 6.1 Code binding via AddListener [Positive]
/// Registers callback in Awake, stores source in field, invokes in Start.
/// Callback receives tainted parameter and passes to Sink.
public class RuntimeEventDispatch_AddListener_61_P : MonoBehaviour
{
    public UnityEvent<string> onDataReceived;
    private string _payload_61_P;

    void Awake()
    {
        onDataReceived.AddListener(HandleData);
        _payload_61_P = TestSources.GetNetworkInput();
    }

    void Start()
    {
        onDataReceived.Invoke(_payload_61_P);
    }

    void HandleData(string _payload_61_P_T)
    {
        TestSinks.DangerousLoad(_payload_61_P_T);
    }
}
