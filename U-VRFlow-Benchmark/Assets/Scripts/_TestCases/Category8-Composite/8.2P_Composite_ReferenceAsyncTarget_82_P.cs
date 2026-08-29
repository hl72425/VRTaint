using UnityEngine;

/// INTEGRATED CATEGORY: Category8-Composite
/// LEGACY CASE: Category16-Composite/16.2P
/// EXPECTED: TRUE POSITIVE
/// 8.2 Serialized reference persistent target [Positive]
public class Composite_ReferenceAsyncTarget_82_P : MonoBehaviour
{
    private string _payload_82_P;
    public void Store(string value) { _payload_82_P = value; }
    public string Read() { return _payload_82_P; }
}
