using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category12-OwnedObject/12.7P
/// EXPECTED: TRUE POSITIVE
public class ObjectIdentityHeap_OwnedHelperState_218_P
{
    private string _data;
    public void Store(string value) { _data = value; }
    public void MaybeReset(bool reset) { if (reset) _data = "safe_default"; }
    public string Read() { return _data; }
}
/// 2.18 Conditional helper clean [Positive]
public class ObjectIdentityHeap_OwnedHelper_ConditionalClean_218_P : MonoBehaviour
{
    public bool reset;
    private ObjectIdentityHeap_OwnedHelperState_218_P _helper = new ObjectIdentityHeap_OwnedHelperState_218_P();
    void Awake() { _helper.Store(TestSources.GetNetworkInput()); _helper.MaybeReset(reset); }
    void Start() { TestSinks.DangerousLoad(_helper.Read()); }
}
