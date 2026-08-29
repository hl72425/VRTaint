using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category2-CrossClass/2.2P
/// EXPECTED: TRUE POSITIVE
/// Writer for 2.2 Instance cross-scene [Positive]
public class ObjectIdentityHeap_StartScene_InstanceWriter_22_P : MonoBehaviour
{
    void Start()
    {
        if (InstancePayload.Instance != null)
            InstancePayload.Instance.CrossClassData_P = TestSources.GetNetworkInput();
        UnityEngine.SceneManagement.SceneManager.LoadScene("2 Game Scene");
    }
}
