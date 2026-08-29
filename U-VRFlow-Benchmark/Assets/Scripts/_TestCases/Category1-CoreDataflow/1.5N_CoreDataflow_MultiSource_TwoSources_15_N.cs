using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category6-Multi/6.1N
/// EXPECTED: TRUE NEGATIVE
/// 1.5 Multiple sources writing to the same field [Negative]
/// Both sources are sanitized (barriered) before storage, so no taint reaches Sink.
public class CoreDataflow_MultiSource_TwoSources_15_N : MonoBehaviour
{
    private string _payload_15_N;

    void Awake()
    {
        _payload_15_N = TestSources.GetNetworkInput().ToUpper(); // Barrier
    }

    void OnEnable()
    {
        _payload_15_N = TestSources.GetUIInput().ToLower(); // Barrier
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_15_N))
            TestSinks.DangerousFileWrite("/tmp/out.txt", _payload_15_N);
    }
}
