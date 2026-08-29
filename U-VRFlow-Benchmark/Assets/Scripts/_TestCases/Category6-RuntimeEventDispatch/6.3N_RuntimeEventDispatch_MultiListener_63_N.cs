using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category6-RuntimeEventDispatch
/// LEGACY CASE: Category3-UnityEvent/3.4N
/// EXPECTED: TRUE NEGATIVE
/// 6.3 Multiple listeners [Negative]
/// No alert should be raised.
public class RuntimeEventDispatch_MultiListener_63_N : MonoBehaviour
{
    public UnityEvent<string> onMultiEvent;
    private string _payload_63_N;

    void Awake()
    {
        onMultiEvent.AddListener(FirstSafe);
        onMultiEvent.AddListener(SecondSafe);
        _payload_63_N = TestSources.GetCmdArgs()[0];
    }

    void Start()
    {
        onMultiEvent.Invoke(_payload_63_N);
    }

    void FirstSafe(string _payload_63_N_T)
    {
        _payload_63_N_T = "_Safe"; // Barrier
        TestSinks.DangerousFileWrite("/tmp/first.txt", _payload_63_N_T);
    }

    void SecondSafe(string _payload_63_N_T)
    {
        _payload_63_N_T = _payload_63_N_T.ToUpper(); // Barrier
        TestSinks.DangerousLoad(_payload_63_N_T);
    }
}
