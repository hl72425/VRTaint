using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category2-CrossClass/2.1P
/// EXPECTED: TRUE POSITIVE
/// Reader for 2.1 Static field cross-class [Positive]
public class ObjectIdentityHeap_GameScene_StaticReader_21_P : MonoBehaviour
{
    private string _payload_21_P;

    void Start()
    {
        _payload_21_P = StaticPayload.CrossClassData_P;
        if (!string.IsNullOrEmpty(_payload_21_P))
            TestSinks.DangerousLoad(_payload_21_P);
    }
}
