using UnityEngine;
using System;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category4-Reflection/4.5P
/// EXPECTED: TRUE POSITIVE
/// 5.9 Activator.CreateInstance [Positive]
/// Tainted type name stored in field, converted to Type, then used to create instance.
/// Sink: Activator.CreateInstance(Type)
public class DynamicInvocation_Activator_59_P : MonoBehaviour
{
    private string _payload_59_P;

    void Awake()
    {
        _payload_59_P = TestSources.GetUIInput();
    }

    void Start()
    {
        Type _payload_59_P_T = Type.GetType(_payload_59_P);
        if (_payload_59_P_T != null)
            Activator.CreateInstance(_payload_59_P_T);
    }
}
