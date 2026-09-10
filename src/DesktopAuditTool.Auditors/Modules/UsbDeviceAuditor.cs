using System.Diagnostics;
using System.IO;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using Microsoft.Win32;

namespace DesktopAuditTool.Auditors.Modules;

public class UsbDeviceAuditor : IAuditModule
{
    public string Name => "USB & Removable Device Control Audit";
    public AuditCategory Category => AuditCategory.UsbDevice;
    public int Priority => 9;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();
        var usbDevices = new List<UsbDeviceInfo>();

        await Task.Run(() =>
        {
            // 1. Query historical USB devices from USBSTOR registry
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var usbstor = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
                if (usbstor != null)
                {
                    foreach (var devClass in usbstor.GetSubKeyNames())
                    {
                        using var classKey = usbstor.OpenSubKey(devClass);
                        if (classKey == null) continue;

                        foreach (var instance in classKey.GetSubKeyNames())
                        {
                            using var instKey = classKey.OpenSubKey(instance);
                            var friendlyName = instKey?.GetValue("FriendlyName")?.ToString() ?? devClass;
                            usbDevices.Add(new UsbDeviceInfo
                            {
                                DeviceId = devClass,
                                Description = friendlyName,
                                SerialNumber = instance
                            });
                        }
                    }
                }
            }
            catch { }

            context.SharedInventory.Hardware.UsbDevices = usbDevices;

            // 2. Check AutoRun / AutoPlay status (NoDriveTypeAutoRun)
            var autoRun = SystemInfoHelper.GetRegistryValue(
                RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoDriveTypeAutoRun");

            var userAutoRun = SystemInfoHelper.GetRegistryValue(
                RegistryHive.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoDriveTypeAutoRun");

            // 0xFF (255) disables AutoRun on all drives
            bool isAutoRunDisabled = (autoRun != null && Convert.ToInt32(autoRun) == 255) ||
                                     (userAutoRun != null && Convert.ToInt32(userAutoRun) == 255);

            if (!isAutoRunDisabled)
            {
                findings.Add(new AuditFinding
                {
                    Title = "AutoPlay / AutoRun Enabled for Removable Drives",
                    Description = "AutoRun is enabled or not fully restricted (NoDriveTypeAutoRun != 255). Inserting a compromised USB drive can execute malicious payloads automatically.",
                    Category = AuditCategory.UsbDevice,
                    Severity = AuditSeverity.High,
                    CvssScore = 7.2,
                    MitreTechniqueId = "T1091",
                    MitreTactic = MitreTactic.InitialAccess,
                    Evidence = $"NoDriveTypeAutoRun = {autoRun ?? userAutoRun ?? "Not Configured"}",
                    RemediationRecommendation = "Disable AutoRun for all drives by setting NoDriveTypeAutoRun to 0xFF (255) in HKLM and HKCU.",
                    RemediationScript = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord; Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 18.9.14.1", "Turn off Autoplay", "Set NoDriveTypeAutoRun to 255"),
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-15", "Removable Media Protection", "Disable AutoPlay and restrict unauthorized USB mass storage")
                    ]
                });
            }

            // 3. USB Storage Whitelisting Status (UsbStor Start value)
            // Start = 4 disables USBSTOR driver
            var usbStorStart = SystemInfoHelper.GetRegistryValue(
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\USBSTOR",
                "Start");

            if (context.AssetClassification >= AssetClassification.Secret &&
                (usbStorStart == null || Convert.ToInt32(usbStorStart) != 4))
            {
                findings.Add(new AuditFinding
                {
                    Title = "USB Mass Storage Driver Enabled on High-Classification Workstation",
                    Description = $"Workstation classification is {context.AssetClassification}, but USB storage driver (USBSTOR) is active (Start={usbStorStart}). Unrestricted USB write access risks classified data exfiltration.",
                    Category = AuditCategory.UsbDevice,
                    Severity = AuditSeverity.High,
                    CvssScore = 7.8,
                    MitreTechniqueId = "T1052.001",
                    MitreTactic = MitreTactic.Exfiltration,
                    Evidence = $"USBSTOR Start = {usbStorStart}",
                    RemediationRecommendation = "Disable USB mass storage driver or deploy strict endpoint USB device whitelisting.",
                    RemediationScript = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 4",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-15", "Classified Endpoint USB Control", "Disable USB mass storage on classified research workstations"),
                        new ComplianceMapping(ComplianceStandard.Nist80053, "MP-7", "Media Use", "Restrict removable media on sensitive systems")
                    ]
                });
            }

            // Report USB history count
            findings.Add(new AuditFinding
            {
                Title = $"USB Hardware Audit: {usbDevices.Count} Historic Devices Recorded",
                Description = $"Identified {usbDevices.Count} unique USB storage/peripheral device entries in system registry.",
                Category = AuditCategory.UsbDevice,
                Severity = AuditSeverity.Informational,
                CvssScore = 0.0,
                Evidence = $"Historic devices count: {usbDevices.Count}"
            });
        }, cancellationToken);

        sw.Stop();
        return new AuditModuleResult
        {
            ModuleName = Name,
            Category = Category,
            Findings = findings,
            ExecutionDurationMs = sw.ElapsedMilliseconds
        };
    }
}
