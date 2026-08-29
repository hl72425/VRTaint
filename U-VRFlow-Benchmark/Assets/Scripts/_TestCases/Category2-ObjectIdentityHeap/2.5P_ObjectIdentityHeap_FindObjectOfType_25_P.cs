using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category7-UnityAdvanced/7.3P
/// EXPECTED: TRUE POSITIVE
/// 2.5 FindObjectOfType and pass data [Positive]
/// Tainted data stored, then a found component receives it via method call.
public class ObjectIdentityHeap_Find_25_P : MonoBehaviour
{
    private string _payload_25_P;

    void Awake()
    {
        _payload_25_P = TestSources.GetUIInput();
    }

    void Start()
    {
        var receiver = FindObjectOfType<TargetReceiver>();
        if (receiver != null)
            receiver.HandleData_2(_payload_25_P);
    }
}
