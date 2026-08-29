using System.Collections;
using System.Collections.Generic;
using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.7N
/// EXPECTED: TRUE NEGATIVE
public class UnityLifecycle_Branch_CFG_37_N : MonoBehaviour
{
    private string _payload_37_N;
    public bool isSafeMode = true;

    void Awake()
    {
        _payload_37_N = TestSources.GetNetworkInput();
        if (isSafeMode)
        {
            _payload_37_N = "SAFE";
        }
        else
        {
            _payload_37_N = "SAFE_FALLBACK";
        }
    }

    void Start()
    {
        if (!string.IsNullOrEmpty(_payload_37_N))
            TestSinks.DangerousLoad(_payload_37_N);
    }
}
