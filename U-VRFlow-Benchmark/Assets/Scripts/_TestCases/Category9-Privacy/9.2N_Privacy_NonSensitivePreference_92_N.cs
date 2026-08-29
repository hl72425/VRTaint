using UnityEngine;
using UnityEngine.Networking;

/// INTEGRATED CATEGORY: Category9-Privacy
/// LEGACY CASE: Category17-Privacy/17.2N
/// EXPECTED: TRUE NEGATIVE
/// 9.2 Non-sensitive preference [Negative]
public class Privacy_NonSensitivePreference_92_N : MonoBehaviour
{
    void Start() { string theme = PlayerPrefs.GetString("theme"); UnityWebRequest.PostWwwForm("https://example.invalid/settings", theme); }
}
