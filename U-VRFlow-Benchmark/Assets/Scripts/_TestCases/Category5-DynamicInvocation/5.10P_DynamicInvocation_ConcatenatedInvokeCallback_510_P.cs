using UnityEngine;

/// INTEGRATED CATEGORY: Category5-DynamicInvocation
/// LEGACY CASE: Category10-Precision/10.8P
/// EXPECTED: TRUE POSITIVE
/// 5.10 Concatenated Invoke callback [Positive]
/// Constant-string concatenation resolves to a callback that reads the tainted field.
public class DynamicInvocation_ConcatenatedInvokeCallback_510_P : MonoBehaviour
{
    private string _payload_510_P;

    private void Awake()
    {
        _payload_510_P = TestSources.GetUIInput();
    }

    private void Start()
    {
        string prefix = "Emit";
        string suffix = "Payload";
        Invoke(prefix + suffix, 0.0f);
    }

    private void EmitPayload()
    {
        TestSinks.DangerousLoad(_payload_510_P);
    }
}
