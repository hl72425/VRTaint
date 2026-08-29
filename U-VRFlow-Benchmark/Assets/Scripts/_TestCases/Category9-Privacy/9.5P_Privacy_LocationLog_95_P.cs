using UnityEngine;

/// INTEGRATED CATEGORY: Category9-Privacy
/// LEGACY CASE: Category17-Privacy/17.5P
/// EXPECTED: TRUE POSITIVE
/// 9.5 Location disclosure [Positive]
public class Privacy_LocationLog_95_P : MonoBehaviour
{
    public LocationService locationService;
    void Update() { Debug.Log(locationService.lastData); }
}
