using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category6-RuntimeEventDispatch
/// LEGACY CASE: Category3-UnityEvent/3.3N
/// EXPECTED: TRUE NEGATIVE
/// 6.2 Generic UnityEvent<int> [Negative]
/// Callback clamps the value (Mathf barrier) before Sink.
public class RuntimeEventDispatch_Generic_62_N : MonoBehaviour
{
    public UnityEvent<int> onNumberReceived;
    private string _payload_62_N;

    void Awake()
    {
        onNumberReceived.AddListener(HandleClamped);
        _payload_62_N = TestSources.GetNetworkInput();
    }

    void Start()
    {
        if (int.TryParse(_payload_62_N, out int num))
            onNumberReceived.Invoke(num);
    }

    void HandleClamped(int _payload_62_N_T)
    {
        int clamped = Mathf.Clamp(_payload_62_N_T, 0, 100); // Barrier
        TestSinks.DangerousFileWrite("/tmp/clamped.txt", clamped.ToString());
    }
}
