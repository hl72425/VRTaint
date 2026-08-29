using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category8-DirectFlow/8.2P
/// EXPECTED: TRUE POSITIVE
/// 1.9 Direct flow via local variable [Positive]
/// Source value is stored in a local variable, then passed to Sink in the same method.
/// Rule should detect this direct taint propagation.
public class CoreDataflow_LocalVar_19_P : MonoBehaviour
{
    void Start()
    {
        string _payload_19_P = TestSources.GetUIInput();
        TestSinks.DangerousFileWrite("/tmp/out.txt", _payload_19_P);
    }
}
