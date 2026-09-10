using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using Microsoft.Win32;

namespace DesktopAuditTool.Auditors.Modules;

public class LogAnalysisAuditor : IAuditModule
{
    public string Name => "Log Analysis & Tamper Audit";
    public AuditCategory Category => AuditCategory.LogAnalysis;
    public int Priority => 10;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();

        await Task.Run(() =>
        {
            CheckEventLogRetention(findings);
            AuditSecurityEventLogs(findings);
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

    private void CheckEventLogRetention(List<AuditFinding> findings)
    {
        // Check Security log size limit in registry
        var maxSizeVal = SystemInfoHelper.GetRegistryValue(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\EventLog\Security",
            "MaxSize");

        // CERT-In recommends minimum 1 GB (1073741824 bytes) or 180 days retention
        if (maxSizeVal != null && Convert.ToInt64(maxSizeVal) < 104857600) // Less than 100 MB
        {
            findings.Add(new AuditFinding
            {
                Title = "Security Event Log Maximum Size Insufficient",
                Description = $"Windows Security event log maximum size is configured to only {Convert.ToInt64(maxSizeVal) / (1024 * 1024)} MB. High-traffic environments will prematurely overwrite critical forensic evidence.",
                Category = AuditCategory.LogAnalysis,
                Severity = AuditSeverity.Medium,
                CvssScore = 5.0,
                Evidence = $"Security Log MaxSize = {maxSizeVal} bytes",
                RemediationRecommendation = "Increase Security Log size to at least 1 GB (1073741824 bytes) to support CERT-In 180-day retention guidelines.",
                RemediationScript = "wevtutil sl Security /ms:1073741824",
                RemediationType = RemediationType.Automatic,
                CanAutoRemediate = true,
                ComplianceMappings = [
                    new ComplianceMapping(ComplianceStandard.CertIn, "CI-16", "Log Retention Mandate", "Mandatory log retention for 180 days"),
                    new ComplianceMapping(ComplianceStandard.Nist80053, "AU-11", "Audit Record Retention", "Retain logs for organizational period")
                ]
            });
        }
    }

    private void AuditSecurityEventLogs(List<AuditFinding> findings)
    {
        if (!SystemInfoHelper.IsWindows) return;

        try
        {
            // Query for Security Log Cleared (Event ID 1102)
            var logClearQuery = "*[System[(EventID=1102 or EventID=104)]]";
            var logClearQueryDesc = new EventLogQuery("Security", PathType.LogName, logClearQuery);
            using (var reader = new EventLogReader(logClearQueryDesc))
            {
                var evt = reader.ReadEvent();
                if (evt != null)
                {
                    findings.Add(new AuditFinding
                    {
                        Title = "Security Audit Log Cleared Event Detected (Anti-Forensics)",
                        Description = $"Event ID {evt.Id} detected at {evt.TimeCreated}. The security audit log was cleared, indicating potential anti-forensics / log tampering.",
                        Category = AuditCategory.LogAnalysis,
                        Severity = AuditSeverity.Critical,
                        CvssScore = 9.0,
                        MitreTechniqueId = "T1070.001",
                        MitreTactic = MitreTactic.DefenseEvasion,
                        Evidence = $"Event ID: {evt.Id}, Time: {evt.TimeCreated}",
                        RemediationRecommendation = "Investigate the workstation immediately for unauthorized administrative access or compromise.",
                        RemediationType = RemediationType.Manual,
                        ComplianceMappings = [
                            new ComplianceMapping(ComplianceStandard.CertIn, "CI-17", "Incident Reporting", "Mandatory reporting of log tampering"),
                            new ComplianceMapping(ComplianceStandard.Iso27001, "A.12.4.2", "Protection of log information", "Prevent tampering of log facilities")
                        ]
                    });
                }
            }

            // Query for Failed Logins in last 24h (Event ID 4625)
            var failedLoginsQuery = "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";
            var failedQueryDesc = new EventLogQuery("Security", PathType.LogName, failedLoginsQuery);
            int failedCount = 0;
            using (var reader = new EventLogReader(failedQueryDesc))
            {
                while (reader.ReadEvent() != null && failedCount < 50)
                {
                    failedCount++;
                }
            }

            if (failedCount >= 10)
            {
                findings.Add(new AuditFinding
                {
                    Title = $"High Volume of Failed Authentication Events ({failedCount}+ in 24h)",
                    Description = $"Detected {failedCount} failed logon attempts (Event ID 4625) in the last 24 hours. Pattern indicates possible brute-force or credential spraying activity.",
                    Category = AuditCategory.LogAnalysis,
                    Severity = AuditSeverity.High,
                    CvssScore = 7.5,
                    MitreTechniqueId = "T1110.001",
                    MitreTactic = MitreTactic.CredentialAccess,
                    Evidence = $"{failedCount} failed logons in last 24 hours",
                    RemediationRecommendation = "Review source IP and targeted accounts in Security Event Log; enforce account lockout and investigate authentication origin.",
                    RemediationType = RemediationType.Manual,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-02", "Brute Force Protection", "Monitor and mitigate repeated authentication failures")
                    ]
                });
            }
        }
        catch
        {
            // Event log access may require elevated privileges; handled gracefully
        }
    }
}
