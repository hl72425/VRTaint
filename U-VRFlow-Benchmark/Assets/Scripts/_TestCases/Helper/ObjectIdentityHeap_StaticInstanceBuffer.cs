using UnityEngine;

/// Static storage is shared by all component instances of this type.
public class ObjectIdentityHeap_StaticInstanceBuffer : MonoBehaviour
{
    private static string _payload;

    public void Store(string value)
    {
        _payload = value;
    }

    public void Upload()
    {
        TestSinks.DangerousLoad(_payload);
    }
}
