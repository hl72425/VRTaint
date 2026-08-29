using System.Collections;
using System.Collections.Generic;
using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.9N
/// EXPECTED: TRUE NEGATIVE
public class UnityLifecycle_Complex_39_N : MonoBehaviour
{
    private string _payload_39_N;
    void Start()
    {
        _payload_39_N = TestSources.GetNetworkInput();
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_39_N))
            HelperMethod();
    }

    void HelperMethod()
    {
        string x = _payload_39_N;
        x = "safe_default";
        TestSinks.DangerousLoad(x);
    }
}
