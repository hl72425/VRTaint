/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category9-NonUnity/9.1P
/// EXPECTED: TRUE POSITIVE
/// Simple data holder for cross?method field flow test (Positive).
/// Stores tainted data in instance field, then provides it to a Sink via another method.
public class ObjectIdentityHeap_DataStorage_27_P
{
    private string _payload_27_P;

    public void Store(string input)
    {
        _payload_27_P = input;
    }

    public void Execute()
    {
        if (!string.IsNullOrEmpty(_payload_27_P))
            TestSinks.DangerousLoad(_payload_27_P);
    }
}
