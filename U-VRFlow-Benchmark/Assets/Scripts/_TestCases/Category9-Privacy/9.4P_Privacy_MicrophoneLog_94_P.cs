using UnityEngine;

/// INTEGRATED CATEGORY: Category9-Privacy
/// LEGACY CASE: Category17-Privacy/17.4P
/// EXPECTED: TRUE POSITIVE
/// 9.4 Microphone capture disclosure [Positive]
public class Privacy_MicrophoneLog_94_P : MonoBehaviour
{
    void Start() { AudioClip voice = Microphone.Start(null, false, 1, 16000); Debug.Log(voice); }
}
