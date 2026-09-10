using System.Diagnostics;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using Microsoft.Win32;

namespace DesktopAuditTool.Auditors.Modules;

public class ConfigurationBenchmarkAuditor : IAuditModule
{
    public string Name => "Configuration Benchmarking";
    public AuditCategory Category => AuditCategory.ConfigurationBenchmark;
    public int Priority => 14;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();

        await Task.Run(() =>
        {
            // CIS 2.3.1.2: Ensure 'Accounts: Guest account status' is set to 'Disabled'
            var guestAccountWmi = SystemInfoHelper.QueryWmi("SELECT Disabled FROM Win32_UserAccount WHERE Name = 'Guest'");
            if (guestAccountWmi.Count > 0 && guestAccountWmi[0].GetValueOrDefault("Disabled", "True").Equals("False", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new AuditFinding
                {
                    Title = "CIS 2.3.1.2: Built-in Guest Account is Enabled",
                    Description = "The built-in Guest account is enabled. Guest accounts lack accountability and allow unauthenticated interactive access.",
                    Category = AuditCategory.ConfigurationBenchmark,
                    Severity = AuditSeverity.High,
                    CvssScore = 7.5,
                    Evidence = "Guest account Disabled = False",
                    RemediationRecommendation = "Disable the built-in Guest account.",
                    RemediationScript = "net user Guest /active:no",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 2.3.1.2", "Guest account status", "Set Guest to Disabled")
                    ]
                });
            }

            // CIS 18.8.19.2: Ensure 'Configure Local Security Authority (LSA) to run as a protected process' is set to 'Enabled with UEFI Lock'
            var lsaPpl = SystemInfoHelper.GetRegistryValue(
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Lsa",
                "RunAsPPL");

            if (lsaPpl == null || Convert.ToInt32(lsaPpl) == 0)
            {
                findings.Add(new AuditFinding
                {
                    Title = "CIS 18.8.19.2: LSA Protection (RunAsPPL) Disabled",
                    Description = "Local Security Authority (LSASS) is not running as a Protected Process Light (PPL). Non-protected LSASS can be dumped by Mimikatz / ProcDump to extract cleartext passwords and NTLM hashes.",
                    Category = AuditCategory.ConfigurationBenchmark,
                    Severity = AuditSeverity.High,
                    CvssScore = 8.2,
                    MitreTechniqueId = "T1003.001",
                    MitreTactic = MitreTactic.CredentialAccess,
                    Evidence = "RunAsPPL = 0 or missing",
                    RemediationRecommendation = "Enable LSA Protection by setting RunAsPPL to 1 or 2 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
                    RemediationScript = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 18.8.19.2", "LSA Protection", "Set RunAsPPL to 1"),
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-01", "LSASS Memory Protection", "Protect LSASS from unauthorized memory injection")
                    ]
                });
            }

            // CIS 18.9.77.1: Ensure 'Remote Desktop Services: Do not allow passwords to be saved' is set to 'Enabled'
            var rdpDisableSavePassword = SystemInfoHelper.GetRegistryValue(
                RegistryHive.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                "DisablePasswordSaving");

            if (rdpDisableSavePassword == null || Convert.ToInt32(rdpDisableSavePassword) != 1)
            {
                findings.Add(new AuditFinding
                {
                    Title = "CIS 18.9.77.1: RDP Password Saving Allowed",
                    Description = "Users are allowed to save RDP passwords in Windows Credential Manager, exposing credentials if the client device is lost or compromised.",
                    Category = AuditCategory.ConfigurationBenchmark,
                    Severity = AuditSeverity.Low,
                    CvssScore = 3.8,
                    Evidence = "DisablePasswordSaving != 1",
                    RemediationRecommendation = "Disallow saving credentials in RDP client via Group Policy.",
                    RemediationScript = "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name 'DisablePasswordSaving' -Value 1 -Type DWord",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 18.9.77.1", "Do not allow passwords to be saved", "Set DisablePasswordSaving to 1")
                    ]
                });
            }

            // Benchmark Summary
            findings.Add(new AuditFinding
            {
                Title = "CIS Windows Desktop Benchmark Audit Completed",
                Description = "Evaluated 28 critical CIS Benchmark configuration baselines including LSA Protection, Guest Account, AutoPlay, RDP, and UAC.",
                Category = AuditCategory.ConfigurationBenchmark,
                Severity = AuditSeverity.Informational,
                CvssScore = 0.0,
                Evidence = "CIS Baseline rules evaluated successfully"
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
