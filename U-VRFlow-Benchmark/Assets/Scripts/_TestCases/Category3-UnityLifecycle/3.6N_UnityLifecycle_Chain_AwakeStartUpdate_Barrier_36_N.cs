using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.6N
/// EXPECTED: TRUE NEGATIVE
/// 3.6 Lifecycle_Chain [Negative]
public class UnityLifecycle_Chain_AwakeStartUpdate_Barrier_36_N : MonoBehaviour
{
    private string _payload_36_N;

    void Awake()
    {
        _payload_36_N = TestSources.GetFileContent();
    }

    void Start()
    {
        _payload_36_N = _payload_36_N.ToUpper(); // Barrier
    }

    void Update()
    {
        TestSinks.DangerousFileWrite("/tmp/chain.txt", _payload_36_N);
    }
}
