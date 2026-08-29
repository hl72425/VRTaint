using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category7-UnityAdvanced/7.2N
/// EXPECTED: TRUE NEGATIVE
/// 2.4 GetComponent and pass data [Negative]
public class ObjectIdentityHeap_GetComponent_24_N : MonoBehaviour
{
    private string _payload_24_N;

    void Awake()
    {
        _payload_24_N = TestSources.GetCmdArgs()[0];
    }

    void Start()
    {
        _payload_24_N="_Safe"; // Barrier
        var receiver = GetComponent<TargetReceiver>();
        if (receiver != null)
            receiver.HandleData_1(_payload_24_N);
    }
}
