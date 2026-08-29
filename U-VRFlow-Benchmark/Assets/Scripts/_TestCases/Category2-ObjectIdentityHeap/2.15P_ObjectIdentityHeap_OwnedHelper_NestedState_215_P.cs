using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category12-OwnedObject/12.3P
/// EXPECTED: TRUE POSITIVE
class ObjectIdentityHeap_OwnedHelper_215_P
{
    private string _payload;
    public void Store(string value) { Assign(value); }
    private void Assign(string value) { _payload = value; }
    public void Execute() { Consume(); }
    private void Consume() { TestSinks.DangerousLoad(_payload); }
}

/// 2.15 Nested owned-helper state [Positive]
public class ObjectIdentityHeap_OwnedHelper_NestedState_215_P : MonoBehaviour
{
    private ObjectIdentityHeap_OwnedHelper_215_P _helper = new ObjectIdentityHeap_OwnedHelper_215_P();
    void Awake() { _helper.Store(TestSources.GetNetworkInput()); }
    void Start() { _helper.Execute(); }
}
