using System.Diagnostics;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using Microsoft.Win32;

namespace DesktopAuditTool.Auditors.Modules;

public class OsSecurityAuditor : IAuditModule
{
    public string Name => "Operating System Security Audit";
    public AuditCategory Category => AuditCategory.OsSecurity;
    public int Priority => 2;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();

        await Task.Run(() =>
        {
            CheckUacConfiguration(findings);
            CheckSecureBoot(findings);
            CheckPasswordAndLockoutPolicy(findings);
            CheckScreenSaverTimeout(findings);
            CheckMissingSecurityHotfixes(findings);
            CheckEndOfLifeOs(findings);
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

    private void CheckUacConfiguration(List<AuditFinding> findings)
    {
        var uacEnabled = SystemInfoHelper.GetRegistryValue(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA");

        var consentAdmin = SystemInfoHelper.GetRegistryValue(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ConsentPromptBehaviorAdmin");

        if (uacEnabled == null || Convert.ToInt32(uacEnabled) != 1)
        {
            findings.Add(new AuditFinding
            {
                Title = "User Account Control (UAC) Disabled",
                Description = "User Account Control (EnableLUA) is disabled. Processes run with full administrative rights without user notification.",
                Category = AuditCategory.OsSecurity,
                Severity = AuditSeverity.Critical,
                CvssScore = 8.8,
                MitreTechniqueId = "T1548.002",
                MitreTactic = MitreTactic.PrivilegeEscalation,
                Evidence = "HKLM\\...\\Policies\\System\\EnableLUA = 0",
                RemediationRecommendation = "Enable User Account Control (UAC) by setting EnableLUA to 1 in the registry.",
                RemediationScript = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1",
                RemediationType = RemediationType.Automatic,
                CanAutoRemediate = true,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 2.3.17.2", "User Account Control: Run all administrators in Admin Approval Mode", "Enforce EnableLUA = 1"),
                    new ComplianceMapping(ComplianceStandard.CertIn, "CI-07", "Privilege Access Management", "Enforce UAC for administrative actions"),
                    new ComplianceMapping(ComplianceStandard.Nist80053, "AC-6", "Least Privilege", "Enforce privilege boundaries")
                ]
            });
        }
    }

    private void CheckSecureBoot(List<AuditFinding> findings)
    {
        var secureBoot = SystemInfoHelper.GetRegistryValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled");

        if (secureBoot == null || Convert.ToInt32(secureBoot) != 1)
        {
            findings.Add(new AuditFinding
            {
                Title = "UEFI Secure Boot Not Active",
                Description = "Secure Boot is disabled or unsupported. This allows unverified bootloaders and rootkits to execute before OS initialization.",
                Category = AuditCategory.OsSecurity,
                Severity = AuditSeverity.High,
                CvssScore = 7.4,
                MitreTechniqueId = "T1542.003",
                MitreTactic = MitreTactic.DefenseEvasion,
                Evidence = "SecureBoot\\State\\UEFISecureBootEnabled != 1",
                RemediationRecommendation = "Enable UEFI Secure Boot in motherboard firmware settings.",
                RemediationType = RemediationType.Manual,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.Nist80053, "SI-7", "Software, Firmware, and Information Integrity", "Verify firmware integrity via Secure Boot"),
                    new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 18.2.1", "Secure Boot Configuration", "Ensure Secure Boot is enabled")
                ]
            });
        }
    }

    private void CheckPasswordAndLockoutPolicy(List<AuditFinding> findings)
    {
        // Query local security policy
        var netAccounts = SystemInfoHelper.RunShellCommand("net", "accounts");
        if (netAccounts.Contains("Minimum password length (characters): 0") ||
            netAccounts.Contains("Minimum password length: 0"))
        {
            findings.Add(new AuditFinding
            {
                Title = "Weak Minimum Password Length Policy",
                Description = "The local password policy allows zero-length or weak passwords.",
                Category = AuditCategory.OsSecurity,
                Severity = AuditSeverity.High,
                CvssScore = 7.5,
                Evidence = "Minimum password length is set to 0",
                RemediationRecommendation = "Set local account password policy to require at least 14 characters.",
                RemediationScript = "net accounts /minpwlen:14",
                RemediationType = RemediationType.Automatic,
                CanAutoRemediate = true,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.CertIn, "CI-01", "Password Security", "Enforce minimum 14 character password length"),
                    new ComplianceMapping(ComplianceStandard.Iso27001, "A.9.4.3", "Password management system", "Enforce complex passwords"),
                    new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 1.1.4", "Minimum password length", "Require at least 14 characters")
                ]
            });
        }

        if (netAccounts.Contains("Lockout threshold: Never") ||
            netAccounts.Contains("Lockout threshold: 0"))
        {
            findings.Add(new AuditFinding
            {
                Title = "Account Lockout Threshold Not Configured",
                Description = "Account lockout is set to 'Never'. The system is vulnerable to brute force and dictionary credential attacks.",
                Category = AuditCategory.OsSecurity,
                Severity = AuditSeverity.High,
                CvssScore = 7.3,
                MitreTechniqueId = "T1110.001",
                MitreTactic = MitreTactic.CredentialAccess,
                Evidence = "Lockout threshold: Never",
                RemediationRecommendation = "Configure account lockout threshold to 5 invalid logon attempts.",
                RemediationScript = "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15",
                RemediationType = RemediationType.Automatic,
                CanAutoRemediate = true,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.CertIn, "CI-02", "Account Lockout Enforcement", "Lock account after 5 failed attempts"),
                    new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 1.2.1", "Account lockout threshold", "5 or fewer invalid attempts")
                ]
            });
        }
    }

    private void CheckScreenSaverTimeout(List<AuditFinding> findings)
    {
        var screenTimeout = SystemInfoHelper.GetRegistryValue(
            RegistryHive.CurrentUser,
            @"Control Panel\Desktop",
            "ScreenSaveTimeOut");

        if (screenTimeout == null || (int.TryParse(screenTimeout.ToString(), out var sec) && sec > 900))
        {
            findings.Add(new AuditFinding
            {
                Title = "Inactivity Screen Lock Timeout Exceeds Baseline",
                Description = "Screen saver / lock screen timeout exceeds 15 minutes (900 seconds) or is disabled, allowing unauthorized physical access to active sessions.",
                Category = AuditCategory.OsSecurity,
                Severity = AuditSeverity.Medium,
                CvssScore = 5.2,
                Evidence = $"ScreenSaveTimeOut = {screenTimeout ?? "Not configured"}",
                RemediationRecommendation = "Configure workstation screen lock timeout to 900 seconds (15 minutes) or less with password protection on resume.",
                RemediationScript = "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveActive' -Value '1'; Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveTimeOut' -Value '900'; Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaverIsSecure' -Value '1'",
                RemediationType = RemediationType.Automatic,
                CanAutoRemediate = true,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.Iso27001, "A.11.2.8", "Unattended user equipment", "Enforce automatic screen lock"),
                    new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 18.9.72.1", "Screen Saver Timeout", "Max 900 seconds")
                ]
            });
        }
    }

    private void CheckMissingSecurityHotfixes(List<AuditFinding> findings)
    {
        var hotfixes = SystemInfoHelper.QueryWmi("SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering");
        if (hotfixes.Count == 0)
        {
            findings.Add(new AuditFinding
            {
                Title = "Unable to Verify Installed Security Updates",
                Description = "No QuickFixEngineering records returned. The system may have update services disabled or has not received recent patches.",
                Category = AuditCategory.OsSecurity,
                Severity = AuditSeverity.Medium,
                CvssScore = 5.0,
                Evidence = "Win32_QuickFixEngineering returned 0 entries",
                RemediationRecommendation = "Ensure Windows Update service (wuauserv) is running and check for updates.",
                RemediationType = RemediationType.Manual,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.CertIn, "CI-03", "Regular Patch Management", "Install latest security patches monthly")
                ]
            });
        }
    }

    private void CheckEndOfLifeOs(List<AuditFinding> findings)
    {
        var osVersion = Environment.OSVersion.Version;
        // Windows 7 (6.1), Windows 8/8.1 (6.2/6.3) are EOL
        if (osVersion.Major == 6 && osVersion.Minor <= 3)
        {
            findings.Add(new AuditFinding
            {
                Title = "End-Of-Life (EOL) Operating System Detected",
                Description = $"Operating system version {Environment.OSVersion} has reached End-Of-Life and no longer receives security updates from Microsoft.",
                Category = AuditCategory.OsSecurity,
                Severity = AuditSeverity.Critical,
                CvssScore = 9.8,
                Evidence = $"OS Version: {Environment.OSVersion}",
                RemediationRecommendation = "Upgrade workstation to Windows 10/11 Enterprise or supported Linux distribution immediately.",
                RemediationType = RemediationType.Manual,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.CertIn, "CI-09", "Supported Software Requirements", "Decommission EOL operating systems"),
                    new ComplianceMapping(ComplianceStandard.Iso27001, "A.12.6.1", "Management of technical vulnerabilities", "Do not use unsupported OS")
                ]
            });
        }
    }
}
