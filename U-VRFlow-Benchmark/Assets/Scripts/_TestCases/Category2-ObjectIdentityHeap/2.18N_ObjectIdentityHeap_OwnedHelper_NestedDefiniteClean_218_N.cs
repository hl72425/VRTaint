using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category12-OwnedObject/12.7N
/// EXPECTED: TRUE NEGATIVE
public class ObjectIdentityHeap_OwnedHelperState_218_N
{
    private string _data;
    public void Store(string value) { _data = value; }
    public void ResetThroughHelper() { ResetCore(); }
    private void ResetCore() { _data = "safe_default"; }
    public string Read() { return _data; }
}
/// 2.18 Nested definite helper clean [Negative]
public class ObjectIdentityHeap_OwnedHelper_NestedDefiniteClean_218_N : MonoBehaviour
{
    private ObjectIdentityHeap_OwnedHelperState_218_N _helper = new ObjectIdentityHeap_OwnedHelperState_218_N();
    void Awake() { _helper.Store(TestSources.GetNetworkInput()); _helper.ResetThroughHelper(); }
    void Start() { TestSinks.DangerousLoad(_helper.Read()); }
}
