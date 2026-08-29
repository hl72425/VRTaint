using UnityEngine;

/// INTEGRATED CATEGORY: Category2-ObjectIdentityHeap
/// LEGACY CASE: Category2-CrossClass/2.1N
/// EXPECTED: TRUE NEGATIVE
/// Writer for 2.1 Static field cross-class [Negative]
/// Stores tainted data into static field.
public class ObjectIdentityHeap_StartScene_StaticWriter_21_N : MonoBehaviour
{
    void Start()
    {
        StaticPayload.CrossClassData_N = TestSources.GetUIInput();
        UnityEngine.SceneManagement.SceneManager.LoadScene("2 Game Scene");
    }
}
