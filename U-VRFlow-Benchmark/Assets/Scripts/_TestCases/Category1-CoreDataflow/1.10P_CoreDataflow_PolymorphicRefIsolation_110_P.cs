using UnityEngine;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category10-Precision/10.1P
/// EXPECTED: TRUE POSITIVE
/// 1.10 Polymorphic ref isolation [Positive]
/// A virtual sanitizer overwrites an unrelated ref argument; the payload remains tainted.
public abstract class CoreDataflow_PrecisionBufferSanitizer_110_P
{
    public abstract void ClearBuffer(ref string data);
}

public sealed class CoreDataflow_PrecisionConstantBufferSanitizer_110_P : CoreDataflow_PrecisionBufferSanitizer_110_P
{
    public override void ClearBuffer(ref string data)
    {
        data = "safe_default";
    }
}

public class CoreDataflow_PolymorphicRefIsolation_110_P : MonoBehaviour
{
    private readonly CoreDataflow_PrecisionBufferSanitizer_110_P _sanitizer =
        new CoreDataflow_PrecisionConstantBufferSanitizer_110_P();
    private string _payload_110_P;
    private string _unrelated_110_P;

    private void Awake()
    {
        _payload_110_P = TestSources.GetUIInput();
        _sanitizer.ClearBuffer(ref _unrelated_110_P);
    }

    private void Update()
    {
        TestSinks.DangerousLoad(_payload_110_P);
    }
}
