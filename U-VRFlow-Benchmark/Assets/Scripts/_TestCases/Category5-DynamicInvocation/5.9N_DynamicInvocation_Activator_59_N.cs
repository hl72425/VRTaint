using UnityEngine;
using System;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.5N
/// EXPECTED: TRUE NEGATIVE
/// 5.9 Activator.CreateInstance [Negative]
/// Tainted type name sanitized by ToLower (Barrier) before conversion and instance creation.
public class DynamicInvocation_Activator_59_N : MonoBehaviour
{
    private string _payload_59_N;

    void Awake()
    {
        _payload_59_N = TestSources.GetNetworkInput();
    }

    void Start()
    {
        string safe = _payload_59_N.ToLower(); // Barrier
        Type t = Type.GetType(safe);
        if (t != null)
            Activator.CreateInstance(t);
    }
}
