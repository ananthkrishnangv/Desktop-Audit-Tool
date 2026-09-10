using System.Diagnostics;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Auditors.Modules;

public class ActiveDirectoryAuditor : IAuditModule
{
    public string Name => "Active Directory & Domain Security Audit";
    public AuditCategory Category => AuditCategory.ActiveDirectory;
    public int Priority => 7;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();

        await Task.Run(() =>
        {
            var csWmi = SystemInfoHelper.QueryWmi("SELECT Domain, PartOfDomain, DomainRole FROM Win32_ComputerSystem");
            bool isDomainJoined = false;
            string domainName = Environment.UserDomainName;

            if (csWmi.Count > 0)
            {
                isDomainJoined = csWmi[0].GetValueOrDefault("PartOfDomain", "False").Equals("True", StringComparison.OrdinalIgnoreCase);
                domainName = csWmi[0].GetValueOrDefault("Domain", domainName);
            }

            if (!isDomainJoined)
            {
                findings.Add(new AuditFinding
                {
                    Title = "Workstation Running in Standalone Workgroup Mode",
                    Description = $"The workstation is not joined to a centralized Active Directory domain (Domain: {domainName}). Centralized security policies cannot be enforced automatically.",
                    Category = AuditCategory.ActiveDirectory,
                    Severity = AuditSeverity.Low,
                    CvssScore = 3.0,
                    Evidence = $"PartOfDomain = False, Workgroup = {domainName}",
                    RemediationRecommendation = "Join workstation to the organization's Active Directory or Entra ID domain for centralized security baseline management.",
                    RemediationType = RemediationType.Manual,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-13", "Centralized Identity Management", "All research workstations must be enrolled in centralized domain")
                    ]
                });
            }
            else
            {
                findings.Add(new AuditFinding
                {
                    Title = $"Active Directory Domain Membership Verified ({domainName})",
                    Description = $"Host is joined to Active Directory domain: {domainName}.",
                    Category = AuditCategory.ActiveDirectory,
                    Severity = AuditSeverity.Informational,
                    CvssScore = 0.0,
                    Evidence = $"Domain: {domainName}"
                });
            }

            // Check for accounts with PasswordNeverExpires
            var neverExpireAccounts = context.SharedInventory.Users.LocalUsers
                .Where(u => u.PasswordNeverExpires && u.IsEnabled)
                .Select(u => u.Username)
                .ToList();

            if (neverExpireAccounts.Count > 0)
            {
                findings.Add(new AuditFinding
                {
                    Title = "Accounts with Non-Expiring Passwords Detected",
                    Description = $"Identified {neverExpireAccounts.Count} active account(s) configured with 'PasswordNeverExpires': {string.Join(", ", neverExpireAccounts)}.",
                    Category = AuditCategory.ActiveDirectory,
                    Severity = AuditSeverity.High,
                    CvssScore = 7.0,
                    MitreTechniqueId = "T1078",
                    MitreTactic = MitreTactic.Persistence,
                    Evidence = $"Accounts: {string.Join(", ", neverExpireAccounts)}",
                    RemediationRecommendation = "Enforce periodic password expiration on all user accounts.",
                    RemediationScript = string.Join("; ", neverExpireAccounts.Select(u => $"Set-LocalUser -Name '{u}' -PasswordNeverExpires $false")),
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 1.1.2", "Maximum password age", "Enforce 60-90 days expiration"),
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-01", "Credential Hygiene", "Disable non-expiring passwords")
                    ]
                });
            }

            // Check for open administrative file shares
            var netShareOutput = SystemInfoHelper.RunShellCommand("net", "share");
            if (netShareOutput.Contains("C$") || netShareOutput.Contains("ADMIN$"))
            {
                findings.Add(new AuditFinding
                {
                    Title = "Default Administrative SMB Shares Accessible",
                    Description = "Default administrative network shares (C$, ADMIN$) are active. In an unhardened environment, these allow lateral movement via SMB.",
                    Category = AuditCategory.ActiveDirectory,
                    Severity = AuditSeverity.Medium,
                    CvssScore = 5.5,
                    MitreTechniqueId = "T1021.002",
                    MitreTactic = MitreTactic.LateralMovement,
                    Evidence = "Administrative shares C$, ADMIN$ present in net share",
                    RemediationRecommendation = "Disable administrative shares (AutoShareWks) if not explicitly required by management tools.",
                    RemediationScript = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'AutoShareWks' -Value 0",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 2.3.11.1", "Network access: Restrict anonymous access to Named Pipes and Shares", "Disable administrative auto-shares")
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
