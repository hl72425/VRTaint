using UnityEngine;

/// INTEGRATED CATEGORY: Category8-Composite
/// LEGACY CASE: Category16-Composite/16.1P
/// EXPECTED: TRUE POSITIVE
/// 8.1 Lifecycle async configured event target [Positive]
public class Composite_LifecycleAsyncEventTarget_81_P : MonoBehaviour
{
    public void Upload(string value) { TestSinks.DangerousLoad(value); }
}
