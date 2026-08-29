using UnityEngine;

/// Helper component that receives data and triggers a dangerous Sink.
public class TargetReceiver : MonoBehaviour
{
    public string payload;
    public void HandleData_1(string value)
    {
        TestSinks.DangerousLoad(value);
    }

    public void HandleData_2(string value)
    {
        TestSinks.DangerousLoad(value);
    }

    public void HandleData_3()
    {
        TestSinks.DangerousLoad(payload);
    }
}
