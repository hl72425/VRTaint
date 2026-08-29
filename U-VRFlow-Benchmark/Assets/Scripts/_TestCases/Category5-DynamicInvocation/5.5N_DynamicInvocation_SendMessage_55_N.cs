using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.3N
/// EXPECTED: TRUE NEGATIVE
/// 5.5 SendMessage with string [Negative]
public class DynamicInvocation_SendMessage_55_N : MonoBehaviour
{
    private string _payload_55_N;

    void Awake()
    {
        _payload_55_N = TestSources.GetFileContent();
    }

    void Start()
    {
        _payload_55_N = _payload_55_N.ToUpper(); // Barrier
        gameObject.SendMessage(_payload_55_N);
    }
}
