using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category2-CrossClass/2.1N
/// EXPECTED: TRUE NEGATIVE
/// Reader for 2.1 Static field cross-class [Negative]
public class ObjectIdentityHeap_GameScene_StaticReader_21_N : MonoBehaviour
{
    private string _payload_21_N;

    void Start()
    {
        _payload_21_N = StaticPayload.CrossClassData_N;

        _payload_21_N = _payload_21_N.ToUpper();
        TestSinks.DangerousFileWrite("/tmp/out.txt", _payload_21_N);
    }
}
