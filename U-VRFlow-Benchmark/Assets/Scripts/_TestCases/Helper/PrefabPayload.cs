using UnityEngine;

/// Payload carrier script attached to prefab.
public class PrefabPayload : MonoBehaviour
{
    public string payload;

    void Start()
    {
        if (!string.IsNullOrEmpty(payload))
            TestSinks.DangerousLoad(payload);
    }
}
