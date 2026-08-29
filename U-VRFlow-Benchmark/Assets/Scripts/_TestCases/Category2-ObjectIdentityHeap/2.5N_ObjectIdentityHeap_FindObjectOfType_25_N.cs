using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category7-UnityAdvanced/7.3N
/// EXPECTED: TRUE NEGATIVE
/// 2.5 FindObjectOfType and pass data [Negative]
/// Data sanitized via ToUpper before passing to found component.
public class ObjectIdentityHeap_Find_25_N : MonoBehaviour
{
    private string _payload_25_N;

    void Awake()
    {
        _payload_25_N = TestSources.GetNetworkInput();
    }

    void Start()
    {
        string safe = _payload_25_N.ToUpper(); // Barrier
        var receiver = FindObjectOfType<TargetReceiver>();
        if (receiver != null)
            receiver.HandleData_1(safe);
    }
}
