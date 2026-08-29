using System.Collections.Generic;
using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category10-Precision/10.7P
/// EXPECTED: TRUE POSITIVE
/// 2.9 Dictionary key isolation [Positive]
/// A clean write under one constant key must not sanitize a value under another key.
public class ObjectIdentityHeap_DictionaryKeyIsolation_29_P : MonoBehaviour
{
    private readonly Dictionary<string, string> _payloads_29_P =
        new Dictionary<string, string>();

    private void Awake()
    {
        _payloads_29_P["unsafe_key"] = TestSources.GetUIInput();
        _payloads_29_P["safe_key"] = "safe_default";
    }

    private void Update()
    {
        TestSinks.DangerousLoad(_payloads_29_P["unsafe_key"]);
    }
}
