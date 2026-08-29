using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category10-Precision/10.5P
/// EXPECTED: TRUE POSITIVE
/// 2.8 Distinct field isolation [Positive]
/// Cleaning one field must not sanitize another field declared on the same component.
public class ObjectIdentityHeap_FieldIsolation_28_P : MonoBehaviour
{
    private string _taintedPayload_28_P;
    private string _cleanPayload_28_P;

    private void Awake()
    {
        _taintedPayload_28_P = TestSources.GetUIInput();
        _cleanPayload_28_P = "safe_default";
    }

    private void Update()
    {
        if (string.IsNullOrEmpty(_cleanPayload_28_P))
        {
            return;
        }

        TestSinks.DangerousLoad(_taintedPayload_28_P);
    }
}
