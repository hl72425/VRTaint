using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category9-NonUnity/9.1N
/// EXPECTED: TRUE NEGATIVE
/// 2.7 Non‑MonoBehaviour field flow [Negative]
/// Plain C# object sanitises data (Barrier) before storing,
/// so taint should not reach Sink.
public class ObjectIdentityHeap_NonUnity_MonoCaller_27_N : MonoBehaviour
{
    private ObjectIdentityHeap_DataStorage_27_N _storage;

    void Awake()
    {
        _storage = new ObjectIdentityHeap_DataStorage_27_N();
        _storage.Store(TestSources.GetUIInput());
    }

    // no execution flow
}
