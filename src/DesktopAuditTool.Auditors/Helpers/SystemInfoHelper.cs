using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace DesktopAuditTool.Auditors.Helpers;

public static class SystemInfoHelper
{
    public static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
    public static bool IsLinux => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
    public static bool IsMacOS => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

    public static bool IsAdministrator()
    {
        if (!IsWindows) return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public static List<Dictionary<string, string>> QueryWmi(string query, string wmiNamespace = "root\\cimv2")
    {
        var results = new List<Dictionary<string, string>>();
        if (!IsWindows) return results;

        try
        {
            using var searcher = new ManagementObjectSearcher(wmiNamespace, query);
            foreach (var item in searcher.Get())
            {
                var row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var prop in item.Properties)
                {
                    row[prop.Name] = prop.Value?.ToString() ?? string.Empty;
                }
                results.Add(row);
            }
        }
        catch
        {
            // Fallback gracefully if WMI provider is missing or permissions restricted
        }
        return results;
    }

    public static object? GetRegistryValue(RegistryHive hive, string subKey, string valueName)
    {
        if (!IsWindows) return null;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(subKey);
            return key?.GetValue(valueName);
        }
        catch
        {
            return null;
        }
    }

    public static List<int> GetActiveListeningPorts()
    {
        var ports = new List<int>();
        try
        {
            var ipProps = IPGlobalProperties.GetIPGlobalProperties();
            var listeners = ipProps.GetActiveTcpListeners();
            foreach (var ep in listeners)
            {
                ports.Add(ep.Port);
            }
        }
        catch
        {
            // Fallback
        }
        return ports.Distinct().Order().ToList();
    }

    public static string RunShellCommand(string fileName, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return string.Empty;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);
            return output.Trim();
        }
        catch
        {
            return string.Empty;
        }
    }
}
