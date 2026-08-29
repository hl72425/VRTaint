using System.Threading.Tasks;
using UnityEngine;

/// INTEGRATED CATEGORY: Category4-AsyncTemporal
/// LEGACY CASE: Category10-Precision/10.2N
/// EXPECTED: TRUE NEGATIVE
/// 4.1 Awaited asynchronous definite clean [Negative]
/// The sink is sequenced after the awaited continuation and a constant overwrite.
public class AsyncTemporal_AsyncAwaitDefiniteClean_41_N : MonoBehaviour
{
    private string _payload_41_N;

    private async void Start()
    {
        _payload_41_N = TestSources.GetUIInput();
        await CompleteAndCleanAsync();
        TestSinks.DangerousLoad(_payload_41_N);
    }

    private async Task CompleteAndCleanAsync()
    {
        await Task.Yield();
        _payload_41_N = "safe_default";
    }
}
