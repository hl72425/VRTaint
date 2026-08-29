using UnityEngine;
using UnityEngine.Networking;

/// INTEGRATED CATEGORY: Category1-CoreDataflow
/// LEGACY CASE: Category5-Property/5.3N
/// EXPECTED: TRUE NEGATIVE
/// 1.4 Network downloadHandler.text as Source [Negative]
/// Downloaded data is sanitized via ToUpper (Barrier) before Sink.
public class CoreDataflow_Property_NetworkDownload_14_N : MonoBehaviour
{
    private string _payload_14_N;
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
            _payload_14_N = _request.downloadHandler.text.ToUpper(); // Barrier
            if (!string.IsNullOrEmpty(_payload_14_N))
                TestSinks.DangerousFileWrite("/tmp/net.txt", _payload_14_N);
            _request = null;
        }
    }
}
