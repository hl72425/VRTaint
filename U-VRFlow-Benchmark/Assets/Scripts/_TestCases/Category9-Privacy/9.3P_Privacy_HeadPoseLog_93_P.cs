using UnityEngine;

/// INTEGRATED CATEGORY: Category9-Privacy
/// LEGACY CASE: Category17-Privacy/17.3P
/// EXPECTED: TRUE POSITIVE
/// 9.3 XR head pose disclosure [Positive]
public class Privacy_HeadPoseLog_93_P : MonoBehaviour
{
    public Transform headTransform;
    void Update() { Debug.Log(headTransform.position); }
}
