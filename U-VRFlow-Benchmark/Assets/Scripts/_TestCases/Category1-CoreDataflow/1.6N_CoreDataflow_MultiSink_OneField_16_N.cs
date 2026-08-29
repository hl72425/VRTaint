using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category6-Multi/6.2N
/// EXPECTED: TRUE NEGATIVE
/// 1.6 Single tainted field flows to multiple Sinks [Negative]
public class CoreDataflow_MultiSink_OneField_16_N : MonoBehaviour
{
    private string _payload_16_N;

    void Awake()
    {
        _payload_16_N = TestSources.GetUIInput();
    }

    void Start()
    {
        _payload_16_N = "_Safe";
        if (!string.IsNullOrEmpty(_payload_16_N))
            TestSinks.DangerousLoad(_payload_16_N);
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_16_N) && Time.frameCount % 60 == 0)
            TestSinks.DangerousFileWrite("/tmp/update.txt", _payload_16_N);
    }
}
