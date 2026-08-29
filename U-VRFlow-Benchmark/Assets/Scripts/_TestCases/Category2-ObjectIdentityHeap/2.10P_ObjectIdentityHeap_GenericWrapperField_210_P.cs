using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category10-Precision/10.10P
/// EXPECTED: TRUE POSITIVE
/// Generic wrapper used by case 10.10.
public sealed class ObjectIdentityHeap_PrecisionWrapper_210_P<T>
{
    public T Data;
}

/// 2.10 Generic wrapper field propagation [Positive]
/// Taint passes through a closed generic field before reaching a persistent component field.
public class ObjectIdentityHeap_GenericWrapperField_210_P : MonoBehaviour
{
    private string _payload_210_P;

    private void Awake()
    {
        var wrapper = new ObjectIdentityHeap_PrecisionWrapper_210_P<string>();
        wrapper.Data = TestSources.GetUIInput();
        _payload_210_P = wrapper.Data;
    }

    private void Update()
    {
        TestSinks.DangerousLoad(_payload_210_P);
    }
}
