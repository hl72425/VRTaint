using UnityEngine;

/// INTEGRATED CATEGORY: Category8-Composite
/// LEGACY CASE: Category16-Composite/16.1N
/// EXPECTED: TRUE NEGATIVE
/// 8.1 Cleaned lifecycle async event target [Negative]
public class Composite_CleanedAsyncEventTarget_81_N : MonoBehaviour
{
    public void Upload(string value) { TestSinks.DangerousLoad(value); }
}
