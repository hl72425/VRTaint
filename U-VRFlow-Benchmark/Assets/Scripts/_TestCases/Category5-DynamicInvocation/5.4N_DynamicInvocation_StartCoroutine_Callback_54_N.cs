using UnityEngine;
using System.Collections;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.2bN
/// EXPECTED: TRUE NEGATIVE
/// 5.4 StartCoroutine callback reads field [Negative]
/// Callback sanitizes field via ToUpper before Sink.
public class DynamicInvocation_StartCoroutine_Callback_54_N : MonoBehaviour
{
    private string _payload_54_N;

    void Awake()
    {
        _payload_54_N = TestSources.GetCmdArgs()[0];
    }

    void Start()
    {
        StartCoroutine("CoroutineSafe");
    }

    IEnumerator CoroutineSafe()
    {
        yield return null;
        string safe = _payload_54_N.ToUpper(); // Barrier
        TestSinks.DangerousFileWrite("/tmp/safe.txt", safe);
    }
}
