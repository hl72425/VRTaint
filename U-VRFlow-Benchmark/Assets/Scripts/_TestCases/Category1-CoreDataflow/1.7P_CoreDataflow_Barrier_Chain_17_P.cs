using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category6-Multi/6.3P
/// EXPECTED: TRUE POSITIVE
/// 1.7 Barrier chain [Positive]
/// Tainted data goes through a custom validation function that is NOT modelled as Barrier.
/// The flow should reach Sink.
public class CoreDataflow_Barrier_Chain_17_P : MonoBehaviour
{
    private string _payload_17_P;

    void Awake()
    {
        _payload_17_P = TestSources.GetCmdArgs()[0];
    }

    void Start()
    {
        string _payload_17_P_T = CustomValidate(_payload_17_P);
        TestSinks.DangerousLoad(_payload_17_P_T);
    }

    // Custom validator not in Barrier list – taint should survive
    private string CustomValidate(string input)
    {
        return input.Trim();
    }
}
