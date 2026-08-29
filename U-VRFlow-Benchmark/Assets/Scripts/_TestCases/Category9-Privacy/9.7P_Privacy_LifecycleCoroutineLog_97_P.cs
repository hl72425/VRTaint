using System.Collections;
using UnityEngine;

/// INTEGRATED CATEGORY: Category9-Privacy
/// LEGACY CASE: Category17-Privacy/17.7P
/// EXPECTED: TRUE POSITIVE
/// 9.7 Lifecycle coroutine privacy disclosure [Positive]
public class Privacy_LifecycleCoroutineLog_97_P : MonoBehaviour
{
    private string _deviceId_97_P;
    void Awake() { _deviceId_97_P = SystemInfo.deviceUniqueIdentifier; }
    void Start() { StartCoroutine(Upload()); }
    private IEnumerator Upload() { yield return null; Debug.Log(_deviceId_97_P); }
}
