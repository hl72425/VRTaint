using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category3-UnityEvent/3.2P
/// EXPECTED: TRUE POSITIVE
/// 7.1 Listener for panel binding [Positive]
/// Has a public UnityEvent that will be triggered with tainted data.
public class ConfigurationRecoveredEdges_EventSource_71_P : MonoBehaviour
{
    public UnityEvent<string> onPanelEvent;

    void Start()
    {
        string _payload_71_P = TestSources.GetUIInput();
        onPanelEvent.Invoke(_payload_71_P);
    }
}
