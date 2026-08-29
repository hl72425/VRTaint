using UnityEngine;
using System.Collections;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.2bP
/// EXPECTED: TRUE POSITIVE
/// 5.4 StartCoroutine callback reads tainted field [Positive]
/// StartCoroutine dispatches to an IEnumerator that reads the tainted field
/// and passes it to a Helper Sink.
public class DynamicInvocation_StartCoroutine_Callback_54_P : MonoBehaviour
{
    private string _payload_54_P;

    void Awake()
    {
        _payload_54_P = TestSources.GetNetworkInput();
    }

    void Start()
    {
        StartCoroutine("CoroutineTainted");
    }

    IEnumerator CoroutineTainted()
    {
        yield return null;
        if (!string.IsNullOrEmpty(_payload_54_P))
            TestSinks.DangerousLoad(_payload_54_P);
    }
}
