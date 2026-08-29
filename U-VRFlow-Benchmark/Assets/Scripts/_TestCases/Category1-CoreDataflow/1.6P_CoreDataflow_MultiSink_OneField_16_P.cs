using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category6-Multi/6.2P
/// EXPECTED: TRUE POSITIVE
/// 1.6 Single tainted field flows to multiple Sinks [Positive]
/// Field written in Awake, read in two different lifecycle methods and passed to two different Sinks.
public class CoreDataflow_MultiSink_OneField_16_P : MonoBehaviour
{
    private string _payload_16_P;

    void Awake()
    {
        _payload_16_P = TestSources.GetNetworkInput();
    }

    void Start()
    {
        if (!string.IsNullOrEmpty(_payload_16_P))
            TestSinks.DangerousLoad(_payload_16_P);
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_16_P) && Time.frameCount % 60 == 0)
            TestSinks.DangerousFileWrite("/tmp/update.txt", _payload_16_P);
    }
}
