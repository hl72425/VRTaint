using System.Collections;
using System.Collections.Generic;
using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category7-UnityAdvanced/7.4P
/// EXPECTED: TRUE POSITIVE
/// 2.6 CrossClass [Positive]
public class ObjectIdentityHeap_Cross_Class_26_P : MonoBehaviour
{
    public PrefabPayload prefab;
    private string _payload_26_P;

    void Awake()
    {
        _payload_26_P = TestSources.GetNetworkInput();
    }

    void Start()
    {
        var receiver = GetComponent<TargetReceiver>();
        receiver.payload = _payload_26_P;
        if (receiver != null)
            receiver.HandleData_3();
    }
}
