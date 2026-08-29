using UnityEngine;

/// INTEGRATED CATEGORY: Category9-Privacy
/// LEGACY CASE: Category17-Privacy/17.1P
/// EXPECTED: TRUE POSITIVE
/// 9.1 Device identifier disclosure [Positive]
public class Privacy_DeviceIdentifierLog_91_P : MonoBehaviour
{
    void Start() { Debug.Log(SystemInfo.deviceUniqueIdentifier); }
}
