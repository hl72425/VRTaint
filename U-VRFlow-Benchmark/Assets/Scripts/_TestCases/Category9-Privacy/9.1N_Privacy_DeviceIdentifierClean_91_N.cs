using UnityEngine;

/// INTEGRATED CATEGORY: Category9-Privacy
/// LEGACY CASE: Category17-Privacy/17.1N
/// EXPECTED: TRUE NEGATIVE
/// 9.1 Cleaned device identifier [Negative]
public class Privacy_DeviceIdentifierClean_91_N : MonoBehaviour
{
    void Start() { string value = SystemInfo.deviceUniqueIdentifier; value = "safe_default"; Debug.Log(value); }
}
