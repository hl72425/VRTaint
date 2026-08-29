using UnityEngine;
using UnityEngine.UI;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category5-Property/5.1N
/// EXPECTED: TRUE NEGATIVE
/// 1.1 Property getter as Source [Negative]
/// InputField.text is sanitized via ToUpper (Barrier) before storing, breaking taint.
public class CoreDataflow_Property_GetSource_11_N : MonoBehaviour
{
    public InputField inputField;
    private string _payload_11_N;

    void Awake()
    {
        if (inputField != null)
            _payload_11_N = inputField.text.ToUpper(); // Barrier
    }

    void Start()
    {
        if (!string.IsNullOrEmpty(_payload_11_N))
            TestSinks.DangerousFileWrite("/tmp/out.txt", _payload_11_N);
    }
}
