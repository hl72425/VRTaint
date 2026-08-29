using System.Collections;
using System.Collections.Generic;
using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.10N
/// EXPECTED: TRUE NEGATIVE
public class UnityLifecycle_StartUpdate_MultiFrame_310_N : MonoBehaviour
{
    private string _payload_310_N;
    void Start()
    {
        _payload_310_N = TestSources.GetNetworkInput();
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_310_N))
            HelperLevel1();
    }

    void HelperLevel1()
    {
        _payload_310_N = "safe_default";
        HelperLevel2();
    }

    void HelperLevel2()
    {
        TestSinks.DangerousLoad(_payload_310_N);
    }
}
