using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category8-DirectFlow/8.1P
/// EXPECTED: TRUE POSITIVE
/// 1.8 Direct flow in same method [Positive]
/// Source value is passed directly to Sink without any intermediate step.
/// Rule should detect this direct taint propagation.
public class CoreDataflow_DirectPass_18_P : MonoBehaviour
{
    void Start()
    {
        TestSinks.DangerousLoad(TestSources.GetNetworkInput());
    }
}
