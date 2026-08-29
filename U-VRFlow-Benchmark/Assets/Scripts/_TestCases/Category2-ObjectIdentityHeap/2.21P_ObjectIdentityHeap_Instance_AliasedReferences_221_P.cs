using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category15-InstanceContext/15.3P
/// EXPECTED: TRUE POSITIVE
/// 2.21 Two serialized references alias one component [Positive]
/// CONFIGURATION: Fixtures/2.21P_ObjectIdentityHeap_AliasedReferences.unity
public class ObjectIdentityHeap_Instance_AliasedReferences_221_P : MonoBehaviour
{
    public ObjectIdentityHeap_InstanceBuffer writer;
    public ObjectIdentityHeap_InstanceBuffer reader;

    private void Start()
    {
        writer.Store(TestSources.GetNetworkInput());
        reader.Upload();
    }
}
