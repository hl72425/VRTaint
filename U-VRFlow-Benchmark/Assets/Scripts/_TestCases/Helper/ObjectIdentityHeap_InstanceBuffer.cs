using UnityEngine;

/// Instance field storage. Each component instance owns a distinct payload.
public class ObjectIdentityHeap_InstanceBuffer : MonoBehaviour
{
    private string _payload;

    public void Store(string value)
    {
        _payload = value;
    }

    public void Upload()
    {
        TestSinks.DangerousLoad(_payload);
    }
}
