using UnityEngine;
using UnityEngine.UI;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category5-Property/5.1P
/// EXPECTED: TRUE POSITIVE
/// 1.1 Property getter as Source [Positive]
/// InputField.text is read in Awake, stored in field, then used in Sink in Start.
public class CoreDataflow_Property_GetSource_11_P : MonoBehaviour
{
    public InputField inputField;
    private string _payload_11_P;

    void Awake()
    {
        if (inputField != null)
            _payload_11_P = inputField.text; // Source via property getter
    }

    void Start()
    {
        if (!string.IsNullOrEmpty(_payload_11_P))
            TestSinks.DangerousLoad(_payload_11_P);
    }
}
