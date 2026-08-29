using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category9-NonUnity/9.1P
/// EXPECTED: TRUE POSITIVE
/// 2.7 Non‑MonoBehaviour field flow [Positive]
/// Awake stores tainted data into a plain C# object's field,
/// Start triggers execution which uses the field in a Sink.
public class ObjectIdentityHeap_NonUnity_MonoCaller_27_P : MonoBehaviour
{
    private ObjectIdentityHeap_DataStorage_27_P _storage;

    void Awake()
    {
        _storage = new ObjectIdentityHeap_DataStorage_27_P();
        _storage.Store(TestSources.GetNetworkInput());
    }

    void Start()
    {
        _storage.Execute();
    }
}
