using System.Collections;
using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category8-Composite
/// LEGACY CASE: Category16-Composite/16.1N
/// EXPECTED: TRUE NEGATIVE
/// 8.1 Cleaned lifecycle async event owner [Negative]
public class Composite_CleanedAsyncEventOwner_81_N : MonoBehaviour
{
    public UnityEvent<string> onReady;
    private string _payload_81_N;
    void Awake() { _payload_81_N = TestSources.GetNetworkInput(); }
    void Start() { _payload_81_N = "safe_default"; StartCoroutine(Dispatch()); }
    private IEnumerator Dispatch() { yield return null; onReady.Invoke(_payload_81_N); }
}
