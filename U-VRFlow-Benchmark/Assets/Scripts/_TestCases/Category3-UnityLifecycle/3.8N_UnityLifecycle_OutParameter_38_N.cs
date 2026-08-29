using System.Collections;
using System.Collections.Generic;
using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.8N
/// EXPECTED: TRUE NEGATIVE
public class UnityLifecycle_OutParameter_38_N : MonoBehaviour
{
    private string _payload_38_N;

    private void FetchNetworkData(out string result)
    {
        result = TestSources.GetNetworkInput();
    }

    void Awake()
    {
        FetchNetworkData(out _payload_38_N);
    }

    void Start()
    {
        _payload_38_N = "_SAFE";
        if (!string.IsNullOrEmpty(_payload_38_N))
            TestSinks.DangerousLoad(_payload_38_N);
    }
}
