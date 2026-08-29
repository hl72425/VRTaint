using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.5N
/// EXPECTED: TRUE NEGATIVE
/// 3.5 Update self-loop [Negative]
public class UnityLifecycle_UpdateSelfLoop_LogBarrier_35_N : MonoBehaviour
{
    private string _payload_35_N;

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_35_N))
        {
            _payload_35_N = _payload_35_N.ToUpper();

            TestSinks.DangerousFileWrite("/tmp/loop.txt", _payload_35_N);
        }

        if (Time.frameCount % 60 == 0)
            _payload_35_N = TestSources.GetNetworkInput();
    }
}
