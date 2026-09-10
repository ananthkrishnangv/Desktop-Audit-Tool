using System.Diagnostics;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using Microsoft.Win32;

namespace DesktopAuditTool.Auditors.Modules;

public class NetworkSecurityAuditor : IAuditModule
{
    public string Name => "Network Security Audit";
    public AuditCategory Category => AuditCategory.NetworkSecurity;
    public int Priority => 6;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();

        await Task.Run(() =>
        {
            CheckSmbV1Protocol(findings);
            CheckRdpConfiguration(findings);
            CheckLlmnrAndNetBios(findings);
            CheckDnsRegistration(findings);
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

    private void CheckSmbV1Protocol(List<AuditFinding> findings)
    {
        var smb1 = SystemInfoHelper.GetRegistryValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1");

        // If SMB1 is 1 or not explicitly 0, it may be active
        if (smb1 != null && Convert.ToInt32(smb1) == 1)
        {
            findings.Add(new AuditFinding
            {
                Title = "SMBv1 Protocol Enabled (EternalBlue Vector)",
                Description = "SMBv1 is active. SMBv1 is obsolete, lacks encryption, and is vulnerable to catastrophic remote code execution exploits (EternalBlue / WannaCry).",
                Category = AuditCategory.NetworkSecurity,
                Severity = AuditSeverity.Critical,
                CvssScore = 9.8,
                MitreTechniqueId = "T1210",
                MitreTactic = MitreTactic.LateralMovement,
                Evidence = "HKLM\\...\\LanmanServer\\Parameters\\SMB1 = 1",
                RemediationRecommendation = "Disable SMBv1 immediately and enforce SMBv2/v3 signing.",
                RemediationScript = "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'SMB1' -Value 0",
                RemediationType = RemediationType.Automatic,
                CanAutoRemediate = true,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.CertIn, "CI-10", "Legacy Protocol Decommissioning", "Disable SMBv1 across all endpoints"),
                    new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 18.4.4", "Ensure SMBv1 protocol driver is disabled", "Set SMB1 = 0"),
                    new ComplianceMapping(ComplianceStandard.Nist80053, "SC-8", "Transmission Confidentiality and Integrity", "Disable legacy unencrypted protocols")
                ]
            });
        }
    }

    private void CheckRdpConfiguration(List<AuditFinding> findings)
    {
        var rdpDeny = SystemInfoHelper.GetRegistryValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections");

        var nlaEnabled = SystemInfoHelper.GetRegistryValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication");

        bool isRdpEnabled = rdpDeny != null && Convert.ToInt32(rdpDeny) == 0;

        if (isRdpEnabled)
        {
            if (nlaEnabled == null || Convert.ToInt32(nlaEnabled) != 1)
            {
                findings.Add(new AuditFinding
                {
                    Title = "RDP Enabled Without Network Level Authentication (NLA)",
                    Description = "Remote Desktop is enabled but Network Level Authentication (UserAuthentication) is not enforced, exposing RDP to unauthenticated pre-auth exploits (BlueKeep).",
                    Category = AuditCategory.NetworkSecurity,
                    Severity = AuditSeverity.Critical,
                    CvssScore = 9.0,
                    MitreTechniqueId = "T1021.001",
                    MitreTactic = MitreTactic.LateralMovement,
                    Evidence = "fDenyTSConnections = 0, UserAuthentication != 1",
                    RemediationRecommendation = "Enforce Network Level Authentication (NLA) for all Remote Desktop connections.",
                    RemediationScript = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 18.9.65.3.3.2", "Require user authentication for remote connections by using Network Level Authentication", "UserAuthentication = 1"),
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-11", "Remote Access Hardening", "Require NLA and MFA for RDP")
                    ]
                });
            }
            else
            {
                findings.Add(new AuditFinding
                {
                    Title = "RDP Service Active with NLA Enforced",
                    Description = "Remote Desktop service is enabled with Network Level Authentication (NLA) properly configured.",
                    Category = AuditCategory.NetworkSecurity,
                    Severity = AuditSeverity.Informational,
                    CvssScore = 0.0,
                    Evidence = "fDenyTSConnections = 0, UserAuthentication = 1"
                });
            }
        }
    }

    private void CheckLlmnrAndNetBios(List<AuditFinding> findings)
    {
        var llmnr = SystemInfoHelper.GetRegistryValue(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "EnableMulticast");

        if (llmnr == null || Convert.ToInt32(llmnr) != 0)
        {
            findings.Add(new AuditFinding
            {
                Title = "LLMNR Name Resolution Enabled (Responder Attack Risk)",
                Description = "Link-Local Multicast Name Resolution (LLMNR) is active. Attackers on the local network can spoof DNS responses and harvest NTLMv2 hashes using Responder.",
                Category = AuditCategory.NetworkSecurity,
                Severity = AuditSeverity.High,
                CvssScore = 7.5,
                MitreTechniqueId = "T1557.001",
                MitreTactic = MitreTactic.CredentialAccess,
                Evidence = "EnableMulticast != 0 (LLMNR is active)",
                RemediationRecommendation = "Disable LLMNR via Group Policy or Registry.",
                RemediationScript = "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0",
                RemediationType = RemediationType.Automatic,
                CanAutoRemediate = true,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 18.9.30.2", "Turn off multicast name resolution", "EnableMulticast = 0"),
                    new ComplianceMapping(ComplianceStandard.CertIn, "CI-12", "Name Resolution Poisoning Prevention", "Disable LLMNR and mDNS across endpoints")
                ]
            });
        }
    }

    private void CheckDnsRegistration(List<AuditFinding> findings)
    {
        // Informational finding for network posture
        var activePorts = SystemInfoHelper.GetActiveListeningPorts();
        findings.Add(new AuditFinding
        {
            Title = $"Network Exposure: {activePorts.Count} Listening TCP Ports",
            Description = $"Host currently has {activePorts.Count} active listening TCP ports: [{string.Join(", ", activePorts.Take(15))}{(activePorts.Count > 15 ? "..." : "")}].",
            Category = AuditCategory.NetworkSecurity,
            Severity = AuditSeverity.Informational,
            CvssScore = 0.0,
            Evidence = $"Active ports count: {activePorts.Count}"
        });
    }
}
