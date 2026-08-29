using UnityEngine;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.5P
/// EXPECTED: TRUE POSITIVE
/// 3.5 Update self-loop [Positive]
public class UnityLifecycle_UpdateSelfLoop_35_P : MonoBehaviour
{
    private string _payload_35_P;

    void Update()
    {
        if (!string.IsNullOrEmpty(_payload_35_P))
            TestSinks.DangerousLoad(_payload_35_P);

        // next frame
        if (Time.frameCount % 60 == 0)
            _payload_35_P = TestSources.GetNetworkInput();
    }
}
