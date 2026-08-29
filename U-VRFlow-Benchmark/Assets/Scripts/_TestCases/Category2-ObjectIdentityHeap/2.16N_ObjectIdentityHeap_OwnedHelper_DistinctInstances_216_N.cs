using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category12-OwnedObject/12.4N
/// EXPECTED: TRUE NEGATIVE
class ObjectIdentityHeap_OwnedHelper_216_N
{
    private string _payload;
    public void Store(string value) { _payload = value; }
    public void Execute() { TestSinks.DangerousLoad(_payload); }
}

/// 2.16 Distinct helper instances [Negative]
public class ObjectIdentityHeap_OwnedHelper_DistinctInstances_216_N : MonoBehaviour
{
    private ObjectIdentityHeap_OwnedHelper_216_N _writer = new ObjectIdentityHeap_OwnedHelper_216_N();
    private ObjectIdentityHeap_OwnedHelper_216_N _reader = new ObjectIdentityHeap_OwnedHelper_216_N();
    void Awake() { _writer.Store(TestSources.GetNetworkInput()); }
    void Start() { _reader.Execute(); }
}
