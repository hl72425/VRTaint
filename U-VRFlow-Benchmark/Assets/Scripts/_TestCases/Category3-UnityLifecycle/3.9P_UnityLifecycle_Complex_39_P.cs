using System.Collections;
using System.Collections.Generic;
using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.9P
/// EXPECTED: TRUE POSITIVE
public class UnityLifecycle_Complex_39_P : MonoBehaviour
{
    private string _payload_39_P;
    void Start()
    {
        _payload_39_P = TestSources.GetNetworkInput();
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_39_P))
            HelperMethod();
    }

    void HelperMethod()
    {
        string _payload_39_P_T = _payload_39_P;
        TestSinks.DangerousLoad(_payload_39_P_T);
    }
}
