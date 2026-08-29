using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category6-RuntimeEventDispatch
/// LEGACY CASE: Category3-UnityEvent/3.4P
/// EXPECTED: TRUE POSITIVE
/// 6.3 Multiple listeners [Positive]
/// Same event has two AddListener calls.
/// Both callbacks should be connected to the Invoke argument.
public class RuntimeEventDispatch_MultiListener_63_P : MonoBehaviour
{
    public UnityEvent<string> onMultiEvent;
    private string _payload_63_P;

    void Awake()
    {
        onMultiEvent.AddListener(FirstHandler);
        onMultiEvent.AddListener(SecondHandler);
        _payload_63_P = TestSources.GetFileContent();
    }

    void Start()
    {
        onMultiEvent.Invoke(_payload_63_P);
    }

    void FirstHandler(string _payload_63_P_T)
    {
        TestSinks.DangerousLoad(_payload_63_P_T);
    }

    void SecondHandler(string _payload_63_P_T)
    {
        TestSinks.DangerousFileWrite("/tmp/second.txt", _payload_63_P_T);
    }
}
