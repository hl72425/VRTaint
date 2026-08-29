using System.Collections;
using System.Collections.Generic;
using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.10P
/// EXPECTED: TRUE POSITIVE
public class UnityLifecycle_StartUpdate_MultiFrame_310_P : MonoBehaviour
{
    private string _payload_310_P;

    void Start()
    {
        _payload_310_P = TestSources.GetNetworkInput();
    }

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_310_P))
            HelperLevel1();
    }

    void HelperLevel1()
    {
        HelperLevel2();
    }

    void HelperLevel2()
    {
        TestSinks.DangerousLoad(_payload_310_P);
    }
}
