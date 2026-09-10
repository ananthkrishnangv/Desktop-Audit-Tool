using System.Diagnostics;
using System.IO;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using Microsoft.Win32;

namespace DesktopAuditTool.Auditors.Modules;

public class CredentialSecurityAuditor : IAuditModule
{
    public string Name => "Credential Security Assessment";
    public AuditCategory Category => AuditCategory.CredentialSecurity;
    public int Priority => 16;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();

        await Task.Run(() =>
        {
            // 1. Check WDigest cleartext password caching
            var wdigest = SystemInfoHelper.GetRegistryValue(
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                "UseLogonCredential");

            if (wdigest != null && Convert.ToInt32(wdigest) == 1)
            {
                findings.Add(new AuditFinding
                {
                    Title = "WDigest Plaintext Credential Caching Enabled in LSASS",
                    Description = "WDigest is configured with UseLogonCredential = 1. LSASS keeps plaintext user passwords in memory, allowing instant extraction via Mimikatz.",
                    Category = AuditCategory.CredentialSecurity,
                    Severity = AuditSeverity.Critical,
                    CvssScore = 9.8,
                    MitreTechniqueId = "T1003.001",
                    MitreTactic = MitreTactic.CredentialAccess,
                    Evidence = "WDigest\\UseLogonCredential = 1",
                    RemediationRecommendation = "Disable WDigest cleartext caching by setting UseLogonCredential to 0.",
                    RemediationScript = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 18.8.21.1", "WDigest Authentication", "Set UseLogonCredential to 0"),
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-01", "Credential Protection in Memory", "Disable plaintext password caching in LSASS")
                    ]
                });
            }

            // 2. Check Credential Guard status
            var credGuard = SystemInfoHelper.GetRegistryValue(
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "EnableVirtualizationBasedSecurity");

            if (credGuard == null || Convert.ToInt32(credGuard) != 1)
            {
                findings.Add(new AuditFinding
                {
                    Title = "Windows Defender Credential Guard Not Enforced",
                    Description = "Virtualization-based Security (VBS) and Credential Guard are disabled or not configured. LSASS isolation is not active.",
                    Category = AuditCategory.CredentialSecurity,
                    Severity = AuditSeverity.Medium,
                    CvssScore = 6.5,
                    MitreTechniqueId = "T1003.001",
                    MitreTactic = MitreTactic.CredentialAccess,
                    Evidence = "DeviceGuard\\EnableVirtualizationBasedSecurity != 1",
                    RemediationRecommendation = "Enable Virtualization Based Security and Credential Guard via Group Policy or registry.",
                    RemediationType = RemediationType.Manual,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 18.8.19.1", "Turn On Virtualization Based Security", "Enable VBS and Credential Guard")
                    ]
                });
            }

            // 3. Scan user .ssh directory for unencrypted private keys
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var sshDir = Path.Combine(userProfile, ".ssh");
            if (Directory.Exists(sshDir))
            {
                var sshFiles = Directory.GetFiles(sshDir, "*", SearchOption.TopDirectoryOnly);
                foreach (var sshFile in sshFiles)
                {
                    var name = Path.GetFileName(sshFile);
                    if (name.StartsWith("id_") && !name.EndsWith(".pub"))
                    {
                        findings.Add(new AuditFinding
                        {
                            Title = $"SSH Private Key Discovered: {name}",
                            Description = $"Discovered private SSH key '{sshFile}'. If this key is unpassphrased, an attacker can use it for unauthorized SSH lateral movement.",
                            Category = AuditCategory.CredentialSecurity,
                            Severity = AuditSeverity.High,
                            CvssScore = 7.8,
                            MitreTechniqueId = "T1552.004",
                            MitreTactic = MitreTactic.CredentialAccess,
                            Evidence = $"Path: {sshFile}",
                            RemediationRecommendation = "Ensure all SSH keys are protected with strong passphrases and strict NTFS ACL permissions.",
                            RemediationType = RemediationType.Manual,
                            ComplianceMappings = [
                                new ComplianceMapping(ComplianceStandard.CertIn, "CI-01", "Private Key Protection", "Enforce passphrase protection on private keys")
                            ]
                        });
                    }
                }
            }

            // 4. Check CachedLogonsCount (Number of previous logons to cache)
            var cachedLogons = SystemInfoHelper.GetRegistryValue(
                RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "CachedLogonsCount");

            if (cachedLogons != null && int.TryParse(cachedLogons.ToString(), out var count) && count > 4)
            {
                findings.Add(new AuditFinding
                {
                    Title = $"Excessive Cached Domain Credentials ({count} logons cached)",
                    Description = $"The system is configured to cache {count} logon credentials locally. CIS recommends 4 or fewer to minimize exposure to MSCash2 cracking.",
                    Category = AuditCategory.CredentialSecurity,
                    Severity = AuditSeverity.Low,
                    CvssScore = 3.5,
                    MitreTechniqueId = "T1003.005",
                    MitreTactic = MitreTactic.CredentialAccess,
                    Evidence = $"CachedLogonsCount = {count}",
                    RemediationRecommendation = "Reduce CachedLogonsCount to 2 or 4 in Winlogon registry.",
                    RemediationScript = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'CachedLogonsCount' -Value '2'",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 2.3.7.1", "Number of previous logons to cache", "Set to 4 or fewer")
                    ]
                });
            }
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
