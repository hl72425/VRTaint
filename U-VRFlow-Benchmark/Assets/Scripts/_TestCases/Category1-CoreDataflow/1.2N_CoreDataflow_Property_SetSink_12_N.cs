using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category5-Property/5.2N
/// EXPECTED: TRUE NEGATIVE
/// 1.2 Property setter as Sink [Negative]
/// Tainted value is clamped (Mathf barrier) before assigning to position, breaking taint.
public class CoreDataflow_Property_SetSink_12_N : MonoBehaviour
{
    private float _payload_12_N;

    void Awake()
    {
        _payload_12_N = float.Parse(TestSources.GetCmdArgs()[0]);
    }

    void Update()
    {
        float safe = Mathf.Clamp(_payload_12_N, -10f, 10f); // Barrier
        transform.position = new Vector3(safe, 0, 0);
    }
}
