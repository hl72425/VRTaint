using System.Collections;
using System.Collections.Generic;
using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.8P
/// EXPECTED: TRUE POSITIVE
public class UnityLifecycle_OutParameter_38_P : MonoBehaviour
{
    private string _payload_38_P;

    private void FetchNetworkData(out string result)
    {
        result = TestSources.GetNetworkInput();
    }

    void Awake()
    {
        FetchNetworkData(out _payload_38_P);
    }

    void Start()
    {
        if (!string.IsNullOrEmpty(_payload_38_P))
            TestSinks.DangerousLoad(_payload_38_P);
    }
}
