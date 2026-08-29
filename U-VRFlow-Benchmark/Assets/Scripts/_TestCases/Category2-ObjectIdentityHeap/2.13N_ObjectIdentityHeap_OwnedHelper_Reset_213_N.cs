using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category12-OwnedObject/12.1N
/// EXPECTED: TRUE NEGATIVE
class ObjectIdentityHeap_OwnedHelper_213_N
{
    private string _payload;
    public void Store(string value) { _payload = value; }
    public void Reset() { _payload = "safe_default"; }
    public void Execute() { TestSinks.DangerousLoad(_payload); }
}

/// 2.13 Owned helper internal reset [Negative]
public class ObjectIdentityHeap_OwnedHelper_Reset_213_N : MonoBehaviour
{
    private ObjectIdentityHeap_OwnedHelper_213_N _helper = new ObjectIdentityHeap_OwnedHelper_213_N();
    void Awake() { _helper.Store(TestSources.GetNetworkInput()); }
    void Start() { _helper.Reset(); _helper.Execute(); }
}
