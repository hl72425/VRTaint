using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category15-InstanceContext/15.2N
/// EXPECTED: TRUE NEGATIVE
/// 2.20 Distinct component receivers [Negative]
/// CONFIGURATION: Fixtures/2.20N_ObjectIdentityHeap_DistinctReceivers.unity
public class ObjectIdentityHeap_Instance_DistinctReceivers_220_N : MonoBehaviour
{
    public ObjectIdentityHeap_InstanceBuffer writer;
    public ObjectIdentityHeap_InstanceBuffer reader;

    private void Start()
    {
        writer.Store(TestSources.GetNetworkInput());
        reader.Upload();
    }
}
