using System;
using System.Runtime.CompilerServices;
using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category10-Precision/10.6N
/// EXPECTED: TRUE NEGATIVE
/// 1.11 Exceptional-flow definite clean [Negative]
/// The only normal path to the sink passes through the catch-block overwrite.
public class CoreDataflow_ExceptionalFlowDefiniteClean_111_N : MonoBehaviour
{
    private string _payload_111_N;

    private void Start()
    {
        _payload_111_N = TestSources.GetUIInput();

        try
        {
            ThrowAlways();
        }
        catch (InvalidOperationException)
        {
            _payload_111_N = "safe_default";
        }

        TestSinks.DangerousLoad(_payload_111_N);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowAlways()
    {
        throw new InvalidOperationException("benchmark control-flow edge");
    }
}
