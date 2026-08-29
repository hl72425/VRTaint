using UnityEngine;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category3-UnityEvent/3.2P
/// EXPECTED: TRUE POSITIVE
/// 7.1 Listener for panel binding [Positive]
/// Method will be bound to ConfigurationRecoveredEdges_EventSource_71 via Inspector.
public class ConfigurationRecoveredEdges_EventListener_71_P : MonoBehaviour
{
    // This method is assigned in the Inspector to onPanelEvent.
    public void HandleFromPanel(string _payload_71_P_T)
    {
        TestSinks.DangerousLoad(_payload_71_P_T);
    }
}
