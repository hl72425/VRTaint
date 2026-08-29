using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category7-UnityAdvanced/7.2P
/// EXPECTED: TRUE POSITIVE
/// 2.4 GetComponent and pass data [Positive]
/// Tainted data stored in field, then retrieved via GetComponent and sent to Sink.
public class ObjectIdentityHeap_GetComponent_24_P : MonoBehaviour
{
    private string _payload_24_P;

    void Awake()
    {
        _payload_24_P = TestSources.GetNetworkInput();
    }

    void Start()
    {
        var receiver = GetComponent<TargetReceiver>();
        if (receiver != null)
            receiver.HandleData_1(_payload_24_P); // Tainted data passed to another component
    }
}
