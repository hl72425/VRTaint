using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category2-CrossClass/2.2N
/// EXPECTED: TRUE NEGATIVE
/// Reader for 2.2 Instance cross-class [Negative]
public class ObjectIdentityHeap_GameScene_InstanceReader_22_N : MonoBehaviour
{
    private string _payload_22_N;

    void Start()
    {
        if (InstancePayload.Instance != null)
        {
            InstancePayload.Instance.CrossClassData_N = "cleaned";
            _payload_22_N = InstancePayload.Instance.CrossClassData_N;
            TestSinks.DangerousFileWrite("/tmp/out.txt", _payload_22_N);
        }
    }
}
