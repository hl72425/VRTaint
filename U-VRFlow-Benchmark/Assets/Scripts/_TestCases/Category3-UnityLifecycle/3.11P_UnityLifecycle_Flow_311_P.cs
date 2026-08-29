using UnityEngine;
using System.IO;

/// INTEGRATED CATEGORY: Category3-UnityLifecycle
/// LEGACY CASE: Category1-Lifecycle/1.11P
/// EXPECTED: TRUE POSITIVE
public class UnityLifecycle_StartUpdate_311_P : MonoBehaviour
{
    private string _payload_311_P;
    private bool f2 = false;
    private bool f3 = false;
    void Awake()
    {
        _payload_311_P = TestSources.GetNetworkInput();

        // 3. [The countermove point of Rule 5]
        // If we wrote f = "final_clean_data"; here, Rule 5 would fire and the
        // vulnerability would be forcibly intercepted at this method's exit.
        // But because the developer omitted the else branch, or wrote a
        // self-polluting assignment here (e.g. f = f + "id";), there is no
        // deterministic, last, non-self-referential overwrite w_over that can
        // dominate the whole exit.
        // Conclusion: Rule 5 decides interception fails (IsIntercepted = false),
        // so the tainted payload freely leaves Awake!
    }

    void Update()
    {
        // path branch 𝝿_A：
        if (f2)
        {
            _payload_311_P = "calibrated_safe_stream";
            TestSinks.DangerousLoad(_payload_311_P);
        }
        // path branch 𝝿_B：
        else if (f3)
        {

            SanitizeSystemField();
            TestSinks.DangerousLoad(_payload_311_P);
        }
        // path branch 𝝿_C (implicit else branch)：
        else
        {
            // Critical defect: the developer completely forgot to handle f in this branch!
            // Field f keeps the original malicious taint that drifted in from Awake.
        }

        // ─── 🛑 Final control-flow convergence gate ───

        // Sink consumption point 3 (Sink 3)
        TestSinks.DangerousLoad(_payload_311_P);
    }

    private void SanitizeSystemField()
    {
        _payload_311_P = "fallback_safe_stream";
    }
}
