using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category7-UnityAdvanced/7.1P
/// EXPECTED: TRUE POSITIVE
/// 2.3 Instantiate clone [Positive]
/// Tainted data written to prefab field, then clone is instantiated and uses the field.
public class ObjectIdentityHeap_Clone_Instantiate_23_P : MonoBehaviour
{
    public PrefabPayload prefab;
    private string _payload_23_P;

    void Awake()
    {
        _payload_23_P = TestSources.GetNetworkInput();
    }

    void Start()
    {
        prefab.payload = _payload_23_P;
        Instantiate(prefab);
    }
}
