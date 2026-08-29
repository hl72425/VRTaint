using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category5-Property/5.2bP
/// EXPECTED: TRUE POSITIVE
/// 5.2 Property setter as Sink (Rigidbody.velocity) [Positive]
/// Tainted vector components stored, then assigned to Rigidbody.velocity.
[RequireComponent(typeof(Rigidbody))]
public class CoreDataflow_Property_SetSink_Rigidbody_13_P : MonoBehaviour
{
    private Rigidbody _rb;
    private float _payload_13_P;

    void Awake()
    {
        _rb = GetComponent<Rigidbody>();
        _payload_13_P = float.Parse(TestSources.GetNetworkInput());
    }

    void FixedUpdate()
    {
        _rb.velocity = new Vector3(_payload_13_P, 0, 0); // Sink
    }
}
