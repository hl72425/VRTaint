using UnityEngine;
using UnityEngine.Networking;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category5-Property/5.3P
/// EXPECTED: TRUE POSITIVE
/// 1.4 Network downloadHandler.text as Source [Positive]
/// Simulates reading downloadHandler.text after a web request, storing it in field,
/// then using it in another lifecycle method.
public class CoreDataflow_Property_NetworkDownload_14_P : MonoBehaviour
{
    private string _payload_14_P;
    private UnityWebRequest _request;

    void Start()
    {
        _request = UnityWebRequest.Get("http://example.com");
        _request.SendWebRequest();
    }

    void Update()
    {
        if (_request != null && _request.isDone)
        {
            _payload_14_P = _request.downloadHandler.text; // Source
            if (!string.IsNullOrEmpty(_payload_14_P))
                TestSinks.DangerousLoad(_payload_14_P);
            _request = null;
        }
    }
}
