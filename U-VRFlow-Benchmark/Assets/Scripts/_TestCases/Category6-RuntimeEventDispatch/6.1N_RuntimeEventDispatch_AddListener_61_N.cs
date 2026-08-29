using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category6-RuntimeEventDispatch
/// LEGACY CASE: Category3-UnityEvent/3.1N
/// EXPECTED: TRUE NEGATIVE
/// 6.1 Code binding via AddListener [Negative]
public class RuntimeEventDispatch_AddListener_61_N : MonoBehaviour
{
    public UnityEvent<string> onDataReceived;
    private string _payload_61_N;

    void Awake()
    {
        onDataReceived.AddListener(HandleSafe);
        _payload_61_N = TestSources.GetCmdArgs()[0];
    }

    void Start()
    {
        _payload_61_N = "_Safe"; // Barrier
        onDataReceived.Invoke(_payload_61_N);
    }

    void HandleSafe(string _payload_61_N_T)
    {
        TestSinks.DangerousFileWrite("/tmp/event.txt", _payload_61_N_T);
    }
}
