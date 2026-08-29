using UnityEngine;
using UnityEngine.Events;

/// INTEGRATED CATEGORY: Category7-ConfigurationRecoveredEdges
/// LEGACY CASE: Category14-Configuration/14.2P
/// EXPECTED: TRUE POSITIVE
public class ConfigurationRecoveredEdges_InheritedEventBase_73_P : MonoBehaviour
{
    public UnityEvent<string> inheritedEvent;
}
/// 7.3 Inherited serialized event owner [Positive]
public class ConfigurationRecoveredEdges_InheritedEventOwner_73_P : ConfigurationRecoveredEdges_InheritedEventBase_73_P
{
    void Start() { inheritedEvent.Invoke(TestSources.GetNetworkInput()); }
}
