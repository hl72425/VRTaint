using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category8-Composite
/// LEGACY CASE: Category16-Composite/16.2P
/// EXPECTED: TRUE POSITIVE
/// 8.2 Serialized reference to coroutine owner [Positive]
public class Composite_ReferenceAsyncOwner_82_P : MonoBehaviour
{
    public Composite_ReferenceAsyncTarget_82_P target;
    void Awake() { target.Store(TestSources.GetNetworkInput()); }
    void Start() { StartCoroutine(Upload(target.Read())); }
    private IEnumerator Upload(string value) { yield return null; TestSinks.DangerousLoad(value); }
}
