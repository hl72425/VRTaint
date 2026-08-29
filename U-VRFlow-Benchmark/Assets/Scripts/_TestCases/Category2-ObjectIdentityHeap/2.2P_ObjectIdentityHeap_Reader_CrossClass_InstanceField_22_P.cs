using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category2-CrossClass/2.2P
/// EXPECTED: TRUE POSITIVE
/// Reader for 2.2 Instance cross-class [Positive]
public class ObjectIdentityHeap_GameScene_InstanceReader_22_P : MonoBehaviour
{
    private string _payload_22_P;

    void Start()
    {
        if (InstancePayload.Instance != null)
        {
            _payload_22_P = InstancePayload.Instance.CrossClassData_P;
            if (!string.IsNullOrEmpty(_payload_22_P))
                TestSinks.DangerousLoad(_payload_22_P);
        }
    }
}
