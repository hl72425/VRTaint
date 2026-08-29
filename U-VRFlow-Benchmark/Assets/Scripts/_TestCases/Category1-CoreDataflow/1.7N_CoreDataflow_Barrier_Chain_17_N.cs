using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category6-Multi/6.3N
/// EXPECTED: TRUE NEGATIVE
/// 1.7 Barrier chain [Negative]
/// Multiple barriers applied consecutively: ToUpper, Mathf.Clamp.
/// Taint should be completely removed before reaching Sink.
public class CoreDataflow_Barrier_Chain_17_N : MonoBehaviour
{
    private string _payload_17_N;

    void Awake()
    {
        _payload_17_N = TestSources.GetNetworkInput();
    }

    void Start()
    {
        // Barrier 1: String operation
        string lower = _payload_17_N.ToUpper();
        // Barrier 2: Mathf (on numeric conversion example, here we just reuse string)
        // Since Mathf barrier is only defined for Mathf functions, we'll apply a dummy clamp
        float numeric = lower.Length; // Not tainted, but let's stick to string barrier chain
        // Apply ToLower again (another string barrier)
        string final = lower.ToLower();
        TestSinks.DangerousFileWrite("/tmp/chain.txt", final);
    }
}
