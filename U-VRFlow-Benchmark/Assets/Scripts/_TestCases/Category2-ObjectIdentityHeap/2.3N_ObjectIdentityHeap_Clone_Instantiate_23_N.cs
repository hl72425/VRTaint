using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category7-UnityAdvanced/7.1N
/// EXPECTED: TRUE NEGATIVE
/// 2.3 Instantiate clone [Negative]
/// Prefab field is overwritten with safe constant before instantiation, so clone should be clean.
public class ObjectIdentityHeap_Clone_Instantiate_23_N : MonoBehaviour
{
    public PrefabPayload prefab;
    private string _payload_23_N;

    void Awake()
    {
        _payload_23_N = TestSources.GetUIInput();
    }

    void Start()
    {
        prefab.payload = _payload_23_N;
        prefab.payload = "safe_default"; // Overwrite tainted value
        Instantiate(prefab);
    }
}
