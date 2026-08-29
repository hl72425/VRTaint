using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category6-Multi/6.1P
/// EXPECTED: TRUE POSITIVE
/// 1.5 Multiple sources writing to the same field [Positive]
/// Two different sources (network, UI) write to the same field in different lifecycle methods.
/// In Update, the field is passed to Sink. Two distinct paths should be reported.
public class CoreDataflow_MultiSource_TwoSources_15_P : MonoBehaviour
{
    private string _payload_15_P;

    void Awake()
    {
        _payload_15_P = TestSources.GetNetworkInput();
    }

    void OnEnable()
    {
        _payload_15_P = TestSources.GetUIInput();
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_15_P))
            TestSinks.DangerousLoad(_payload_15_P);
    }
}
