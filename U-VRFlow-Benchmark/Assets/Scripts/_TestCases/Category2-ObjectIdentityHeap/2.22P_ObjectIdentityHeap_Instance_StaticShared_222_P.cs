using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category15-InstanceContext/15.4P
/// EXPECTED: TRUE POSITIVE
/// 2.22 Static field shared by distinct components [Positive]
/// CONFIGURATION: Fixtures/2.22P_ObjectIdentityHeap_StaticShared.unity
public class ObjectIdentityHeap_Instance_StaticShared_222_P : MonoBehaviour
{
    public ObjectIdentityHeap_StaticInstanceBuffer writer;
    public ObjectIdentityHeap_StaticInstanceBuffer reader;

    private void Start()
    {
        writer.Store(TestSources.GetNetworkInput());
        reader.Upload();
    }
}
