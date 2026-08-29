using UnityEngine;

// Static field container for tests
public static class StaticPayload
{
    public static string CrossClassData_P;
    public static string CrossClassData_N;
}

// Instance field for cross‑scene tests
public class InstancePayload : MonoBehaviour
{
    public static InstancePayload Instance { get; private set; }
    public string CrossClassData_P;
    public string CrossClassData_N;

    void Awake()
    {
        if (Instance == null)
        {
            Instance = this;
            DontDestroyOnLoad(gameObject);
        }
        else
        {
            Destroy(gameObject);
        }
    }
}
