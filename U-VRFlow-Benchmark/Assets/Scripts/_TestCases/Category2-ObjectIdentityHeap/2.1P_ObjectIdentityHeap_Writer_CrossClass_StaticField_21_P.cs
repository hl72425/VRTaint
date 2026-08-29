using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category2-CrossClass/2.1P
/// EXPECTED: TRUE POSITIVE
/// Writer for 2.1 Static field cross-class [Positive]
public class ObjectIdentityHeap_StartScene_StaticWriter_21_P : MonoBehaviour
{
    void Start()
    {
        StaticPayload.CrossClassData_P = TestSources.GetNetworkInput();
        UnityEngine.SceneManagement.SceneManager.LoadScene("2 Game Scene");
    }
}
