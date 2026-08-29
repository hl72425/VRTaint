using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category12-OwnedObject/12.5P
/// EXPECTED: TRUE POSITIVE
class ObjectIdentityHeap_OwnedHelper_217_P
{
    private string _payload;
    public void Store(string value) { _payload = value; }
    public string Read() { return _payload; }
}

/// 2.17 Owned helper return direction [Positive]
public class ObjectIdentityHeap_OwnedHelper_Return_217_P : MonoBehaviour
{
    private ObjectIdentityHeap_OwnedHelper_217_P _helper = new ObjectIdentityHeap_OwnedHelper_217_P();
    void Awake() { _helper.Store(TestSources.GetNetworkInput()); }
    void Start() { TestSinks.DangerousLoad(_helper.Read()); }
}
