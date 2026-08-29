using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category5-Property/5.2P
/// EXPECTED: TRUE POSITIVE
/// 1.2 Property setter as Sink [Positive]
/// Tainted data stored in field, then used to set transform.position in another method.
/// Sink: transform.position = new Vector3(...) where value comes from tainted field.
public class CoreDataflow_Property_SetSink_12_P : MonoBehaviour
{
    private float _payload_12_P;

    void Awake()
    {
        _payload_12_P = float.Parse(TestSources.GetUIInput()); // Source
    }

    void Update()
    {
        transform.position = new Vector3(_payload_12_P, 0, 0); // Sink via property setter
    }
}
