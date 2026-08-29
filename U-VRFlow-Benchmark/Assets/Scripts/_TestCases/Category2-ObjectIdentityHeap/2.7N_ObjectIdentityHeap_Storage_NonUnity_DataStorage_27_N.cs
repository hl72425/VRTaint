/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category9-NonUnity/9.1N
/// EXPECTED: TRUE NEGATIVE
/// Simple data holder for cross‑method field flow test (Negative).
/// Applies barrier (ToUpper) before storing, cutting taint.
public class ObjectIdentityHeap_DataStorage_27_N
{
    private string _payload_27_N;

    public void Store(string input)
    {
        _payload_27_N = input;
    }

    public void Execute()
    {
        if (!string.IsNullOrEmpty(_payload_27_N))
            TestSinks.DangerousFileWrite("/tmp/out.txt", _payload_27_N);
    }
}
