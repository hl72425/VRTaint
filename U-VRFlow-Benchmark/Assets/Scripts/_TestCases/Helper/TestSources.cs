using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public static class TestSources
{
    public static string GetUIInput() => "<script>alert(1)</script>";
    public static string GetNetworkInput() => "http://evil.com/payload";
    public static string GetFileContent() => System.IO.File.ReadAllText("/etc/passwd");
    public static string[] GetCmdArgs() => System.Environment.GetCommandLineArgs();
}
