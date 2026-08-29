using System.Collections;
using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category8-Composite
/// LEGACY CASE: Category16-Composite/16.1P
/// EXPECTED: TRUE POSITIVE
/// 8.1 Lifecycle to coroutine to configured event owner [Positive]
public class Composite_LifecycleAsyncEventOwner_81_P : MonoBehaviour
{
    public UnityEvent<string> onReady;
    private string _payload_81_P;
    void Awake() { _payload_81_P = TestSources.GetNetworkInput(); }
    void Start() { StartCoroutine(Dispatch()); }
    private IEnumerator Dispatch() { yield return null; onReady.Invoke(_payload_81_P); }
}
