using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category3-UnityEvent/3.2N
/// EXPECTED: TRUE NEGATIVE
/// 7.1 Listener for panel binding [Negative].
public class ConfigurationRecoveredEdges_EventListener_71_N : MonoBehaviour
{
    // Assigned in Inspector
    public void SafeHandler(string _payload_71_N_T)
    {
        _payload_71_N_T = "_Safe"; // Barrier
        TestSinks.DangerousFileWrite("/tmp/safe.txt", _payload_71_N_T);
    }
}
