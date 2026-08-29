using System.Collections;
using System.Collections.Generic;
using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.7P
/// EXPECTED: TRUE POSITIVE
public class UnityLifecycle_Branch_CFG_37_P : MonoBehaviour
{
    private string _payload_37_P;
    public bool isSafeMode = false;

    void Awake()
    {
        if (isSafeMode)
        {
            _payload_37_P = "SAFE";
        }
        else
        {
            _payload_37_P = TestSources.GetNetworkInput();
        }
    }

    void Start()
    {
        if (!string.IsNullOrEmpty(_payload_37_P))
            TestSinks.DangerousLoad(_payload_37_P);
    }
}
