using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category10-Precision/10.9N
/// EXPECTED: TRUE NEGATIVE
/// 1.12 Context-sensitive call-site separation [Negative]
/// The same identity method receives tainted and clean inputs, but only the clean result is sunk.
public class CoreDataflow_ContextSensitiveCleanCallSite_112_N : MonoBehaviour
{
    private string _taintedNotSunk_112_N;
    private string _cleanAndSunk_112_N;

    private void Awake()
    {
        _taintedNotSunk_112_N = Identity(TestSources.GetUIInput());
        _cleanAndSunk_112_N = Identity("safe_default");
    }

    private static string Identity(string input)
    {
        return input;
    }

    private void Update()
    {
        TestSinks.DangerousLoad(_cleanAndSunk_112_N);
    }
}
