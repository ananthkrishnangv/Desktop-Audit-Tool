using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using Microsoft.Win32;

namespace DesktopAuditTool.Auditors.Modules;

public class AssetDiscoveryAuditor : IAuditModule
{
    public string Name => "Asset Discovery & Inventory";
    public AuditCategory Category => AuditCategory.AssetDiscovery;
    public int Priority => 1;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();
        var inventory = context.SharedInventory;

        await Task.Run(() =>
        {
            CollectHardwareInventory(inventory.Hardware);
            CollectSoftwareInventory(inventory.Software);
            CollectUserInventory(inventory.Users);
        }, cancellationToken);

        // Check for dormant accounts
        if (inventory.Users.DormantAccounts.Count > 0)
        {
            findings.Add(new AuditFinding
            {
                Title = "Dormant User Accounts Detected",
                Description = $"Identified {inventory.Users.DormantAccounts.Count} user account(s) inactive for >90 days: {string.Join(", ", inventory.Users.DormantAccounts)}.",
                Category = AuditCategory.AssetDiscovery,
                Severity = AuditSeverity.Medium,
                CvssScore = 4.5,
                Evidence = $"Accounts: {string.Join(", ", inventory.Users.DormantAccounts)}",
                RemediationRecommendation = "Review and disable or remove dormant accounts in accordance with organizational access control policies.",
                RemediationType = RemediationType.Manual,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.Iso27001, "A.9.2.6", "Removal or adjustment of access rights", "Revoke dormant accounts"),
                    new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 5.3", "Ensure inactive accounts are disabled", "Disable accounts inactive > 90 days")
                ]
            });
        }

        // Check for unauthorized/excessive local administrators
        if (inventory.Users.PrivilegedUsers.Count > 3)
        {
            findings.Add(new AuditFinding
            {
                Title = "Excessive Privileged Local Administrator Accounts",
                Description = $"Endpoint has {inventory.Users.PrivilegedUsers.Count} members in the Administrators group ({string.Join(", ", inventory.Users.PrivilegedUsers)}).",
                Category = AuditCategory.AssetDiscovery,
                Severity = AuditSeverity.High,
                CvssScore = 7.1,
                MitreTechniqueId = "T1078.003",
                MitreTactic = MitreTactic.PrivilegeEscalation,
                Evidence = $"Admin accounts: {string.Join(", ", inventory.Users.PrivilegedUsers)}",
                RemediationRecommendation = "Enforce principle of least privilege. Remove regular user accounts from the local Administrators group.",
                RemediationType = RemediationType.Manual,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.CertIn, "CI-04", "Least Privilege Principle", "Restrict administrator group membership"),
                    new ComplianceMapping(ComplianceStandard.Nist80053, "AC-6", "Least Privilege", "Limit privileged account usage")
                ]
            });
        }

        sw.Stop();
        return new AuditModuleResult
        {
            ModuleName = Name,
            Category = Category,
            Findings = findings,
            ExecutionDurationMs = sw.ElapsedMilliseconds
        };
    }

    private void CollectHardwareInventory(HardwareInventory hw)
    {
        hw.CpuModel = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "Unknown CPU";
        hw.CpuCores = Environment.ProcessorCount;

        // WMI CPU & Motherboard details
        var cpuWmi = SystemInfoHelper.QueryWmi("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor");
        if (cpuWmi.Count > 0)
        {
            hw.CpuModel = cpuWmi[0].GetValueOrDefault("Name", hw.CpuModel);
        }

        var mbWmi = SystemInfoHelper.QueryWmi("SELECT Manufacturer, Product FROM Win32_BaseBoard");
        if (mbWmi.Count > 0)
        {
            hw.MotherboardManufacturer = mbWmi[0].GetValueOrDefault("Manufacturer", "Standard System Board");
            hw.MotherboardProduct = mbWmi[0].GetValueOrDefault("Product", "System Platform");
        }

        var biosWmi = SystemInfoHelper.QueryWmi("SELECT SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS");
        if (biosWmi.Count > 0)
        {
            hw.BiosVersion = $"{biosWmi[0].GetValueOrDefault("SMBIOSBIOSVersion", "UEFI")} ({biosWmi[0].GetValueOrDefault("ReleaseDate", "")})";
        }

        var csWmi = SystemInfoHelper.QueryWmi("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
        if (csWmi.Count > 0 && double.TryParse(csWmi[0].GetValueOrDefault("TotalPhysicalMemory"), out var bytes))
        {
            hw.TotalRamGb = Math.Round(bytes / (1024 * 1024 * 1024), 2);
        }

        // Storage Drives
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady) continue;
            hw.StorageDevices.Add(new StorageDeviceInfo
            {
                DeviceId = drive.Name,
                Model = drive.VolumeLabel.Length > 0 ? drive.VolumeLabel : drive.DriveType.ToString(),
                SizeGb = Math.Round((double)drive.TotalSize / (1024 * 1024 * 1024), 1),
                InterfaceType = drive.DriveType.ToString(),
                MediaType = drive.DriveFormat
            });
        }

        // Network Adapters
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            var ipProps = nic.GetIPProperties();
            var ips = ipProps.UnicastAddresses.Select(a => a.Address.ToString()).ToList();
            var dns = ipProps.DnsAddresses.Select(a => a.ToString()).ToList();
            var gw = ipProps.GatewayAddresses.FirstOrDefault()?.Address.ToString() ?? "";

            hw.NetworkAdapters.Add(new NetworkAdapterInfo
            {
                Name = nic.Name,
                Description = nic.Description,
                MacAddress = nic.GetPhysicalAddress().ToString(),
                IpAddresses = ips,
                DnsServers = dns,
                Gateway = gw,
                Status = nic.OperationalStatus.ToString()
            });
        }
    }

    private void CollectSoftwareInventory(SoftwareInventory sw)
    {
        // Query Uninstall registry keys for 32-bit and 64-bit applications
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        foreach (var path in uninstallPaths)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var subKey = baseKey.OpenSubKey(path);
                if (subKey == null) continue;

                foreach (var subKeyName in subKey.GetSubKeyNames())
                {
                    using var appKey = subKey.OpenSubKey(subKeyName);
                    var displayName = appKey?.GetValue("DisplayName")?.ToString();
                    if (string.IsNullOrWhiteSpace(displayName)) continue;

                    sw.InstalledApplications.Add(new InstalledApplicationInfo
                    {
                        Name = displayName,
                        Version = appKey?.GetValue("DisplayVersion")?.ToString() ?? "Unknown",
                        Publisher = appKey?.GetValue("Publisher")?.ToString() ?? "Unknown",
                        InstallDate = appKey?.GetValue("InstallDate")?.ToString() ?? "N/A",
                        InstallLocation = appKey?.GetValue("InstallLocation")?.ToString() ?? ""
                    });
                }
            }
            catch
            {
                // Fallback
            }
        }

        // Running Services
        try
        {
            foreach (var svc in ServiceController.GetServices())
            {
                sw.RunningServices.Add(new RunningServiceInfo
                {
                    Name = svc.ServiceName,
                    DisplayName = svc.DisplayName,
                    Status = svc.Status.ToString()
                });
            }
        }
        catch
        {
            // Fallback
        }

        // Startup Programs
        var startupPaths = new[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        };

        foreach (var p in startupPaths)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(p);
                if (key != null)
                {
                    foreach (var valName in key.GetValueNames())
                    {
                        sw.StartupPrograms.Add(new StartupProgramInfo
                        {
                            Name = valName,
                            Command = key.GetValue(valName)?.ToString() ?? "",
                            Location = $"HKCU\\{p}",
                            User = Environment.UserName
                        });
                    }
                }
            }
            catch { }
        }
    }

    private void CollectUserInventory(UserInventory users)
    {
        // Enumerate local users via net user or WMI
        var userWmi = SystemInfoHelper.QueryWmi("SELECT Name, Disabled, PasswordExpires FROM Win32_UserAccount WHERE LocalAccount = True");
        foreach (var u in userWmi)
        {
            var username = u.GetValueOrDefault("Name", "");
            if (string.IsNullOrWhiteSpace(username)) continue;

            var isDisabled = u.GetValueOrDefault("Disabled", "False").Equals("True", StringComparison.OrdinalIgnoreCase);
            var passExpires = u.GetValueOrDefault("PasswordExpires", "True").Equals("True", StringComparison.OrdinalIgnoreCase);

            users.LocalUsers.Add(new UserAccountInfo
            {
                Username = username,
                IsEnabled = !isDisabled,
                PasswordNeverExpires = !passExpires
            });
        }

        // Enumerate administrators
        var admins = SystemInfoHelper.RunShellCommand("net", "localgroup administrators");
        var lines = admins.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        bool recording = false;
        foreach (var line in lines)
        {
            if (line.StartsWith("---")) { recording = true; continue; }
            if (line.StartsWith("The command completed")) break;
            if (recording && !string.IsNullOrWhiteSpace(line))
            {
                users.PrivilegedUsers.Add(line.Trim());
            }
        }

        if (users.PrivilegedUsers.Count == 0)
        {
            users.PrivilegedUsers.Add("Administrator");
        }
    }
}
