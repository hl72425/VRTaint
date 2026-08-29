using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category5-Property/5.2bN
/// EXPECTED: TRUE NEGATIVE
/// 5.2 Property setter as Sink (Rigidbody.velocity) [Negative]
/// Value clamped before velocity assignment, breaking taint.
[RequireComponent(typeof(Rigidbody))]
public class CoreDataflow_Property_SetSink_Rigidbody_13_N : MonoBehaviour
{
    private Rigidbody _rb;
    private float _payload_13_N;

    void Awake()
    {
        _rb = GetComponent<Rigidbody>();
        _payload_13_N = float.Parse(TestSources.GetCmdArgs()[0]);
    }

    void FixedUpdate()
    {
        float safe = Mathf.Clamp(_payload_13_N, -5f, 5f); // Barrier
        _rb.velocity = new Vector3(safe, 0, 0);
    }
}
