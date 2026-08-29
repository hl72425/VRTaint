using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category3-UnityEvent/3.2N
/// EXPECTED: TRUE NEGATIVE
/// 7.1 Listener for panel binding [Negative]
/// Invoked with tainted data, but listener will apply barrier.
public class ConfigurationRecoveredEdges_EventSource_71_N : MonoBehaviour
{
    public UnityEvent<string> onSafeEvent;

    void Start()
    {
        string _payload_71_N = TestSources.GetUIInput();
        onSafeEvent.Invoke(_payload_71_N);
    }
}
