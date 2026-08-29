using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category2-CrossClass/2.2N
/// EXPECTED: TRUE NEGATIVE
/// Writer for 2.2 Instance cross-class [Negative]
public class ObjectIdentityHeap_StartScene_InstanceWriter_22_N : MonoBehaviour
{
    void Start()
    {
        if (InstancePayload.Instance != null)
            InstancePayload.Instance.CrossClassData_N = TestSources.GetCmdArgs()[0];
        UnityEngine.SceneManagement.SceneManager.LoadScene("2 Game Scene");
    }
}
