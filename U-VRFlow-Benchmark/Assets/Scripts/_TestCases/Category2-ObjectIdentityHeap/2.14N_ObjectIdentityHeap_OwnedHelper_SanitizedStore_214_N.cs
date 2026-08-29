using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category12-OwnedObject/12.2N
/// EXPECTED: TRUE NEGATIVE
class ObjectIdentityHeap_OwnedHelper_214_N
{
    private string _payload;
    public void Store(string value) { _payload = value.ToUpper(); }
    public void Execute() { TestSinks.DangerousLoad(_payload); }
}

/// 2.14 Sanitized parameter to helper field [Negative]
public class ObjectIdentityHeap_OwnedHelper_SanitizedStore_214_N : MonoBehaviour
{
    private ObjectIdentityHeap_OwnedHelper_214_N _helper = new ObjectIdentityHeap_OwnedHelper_214_N();
    void Awake() { _helper.Store(TestSources.GetNetworkInput()); }
    void Start() { _helper.Execute(); }
}
