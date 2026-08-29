using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public static class TestSinks
{
    public static void DangerousLoad(string path)
    {
        Resources.Load(path);
    }

    public static void DangerousFileWrite(string path, string content)
    {
        System.IO.File.WriteAllText(path, content);
    }
}
