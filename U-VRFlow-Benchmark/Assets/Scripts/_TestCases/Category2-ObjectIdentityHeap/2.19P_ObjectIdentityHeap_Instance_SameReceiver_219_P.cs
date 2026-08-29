using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category15-InstanceContext/15.1P
/// EXPECTED: TRUE POSITIVE
/// 2.19 Same component receiver [Positive]
/// CONFIGURATION: Fixtures/2.19P_ObjectIdentityHeap_SameReceiver.unity
public class ObjectIdentityHeap_Instance_SameReceiver_219_P : MonoBehaviour
{
    public ObjectIdentityHeap_InstanceBuffer buffer;

    private void Start()
    {
        buffer.Store(TestSources.GetNetworkInput());
        buffer.Upload();
    }
}
