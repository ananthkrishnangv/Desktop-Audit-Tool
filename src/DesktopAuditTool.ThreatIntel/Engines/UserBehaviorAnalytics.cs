using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.ThreatIntel.Engines;

public class UserBehaviorAnalytics
{
    public double CalculateUserRiskScore(AuditReport report, out List<string> anomalies)
    {
        anomalies = [];
        double score = 15.0; // Baseline low risk

        // Check for dormant accounts still active
        if (report.Inventory.Users.DormantAccounts.Count > 0)
        {
            score += 20.0;
            anomalies.Add($"Identified {report.Inventory.Users.DormantAccounts.Count} dormant user accounts with active credentials.");
        }

        // Check for accounts with non-expiring passwords
        var neverExpire = report.Inventory.Users.LocalUsers.Count(u => u.PasswordNeverExpires && u.IsEnabled);
        if (neverExpire > 0)
        {
            score += 15.0;
            anomalies.Add($"{neverExpire} active accounts configured with non-expiring passwords.");
        }

        // Check for excessive local administrators
        if (report.Inventory.Users.PrivilegedUsers.Count > 3)
        {
            score += 25.0;
            anomalies.Add($"Excessive local administrative privileges ({report.Inventory.Users.PrivilegedUsers.Count} admin accounts).");
        }

        // Check for DLP findings in user profiles
        if (report.DlpFindings.Count > 0)
        {
            score += Math.Min(30.0, report.DlpFindings.Count * 10.0);
            anomalies.Add($"User profile directories contain {report.DlpFindings.Count} unencrypted sensitive PII/credential instances.");
        }

        return Math.Min(100.0, Math.Round(score, 1));
    }
}

public class EntityBehaviorAnalytics
{
    public double CalculateEntityRiskScore(AuditReport report, out List<string> anomalies)
    {
        anomalies = [];
        double score = 10.0;

        // Check active network exposure
        var openPorts = report.Findings.Count(f => f.Category == AuditCategory.Firewall && f.Severity >= AuditSeverity.High);
        if (openPorts > 0)
        {
            score += 25.0;
            anomalies.Add($"Entity has {openPorts} high-risk ports or services exposed through host firewall.");
        }

        // Check for EOL operating system or vulnerable software
        var critVulns = report.Findings.Count(f => f.Category == AuditCategory.Vulnerability && f.Severity == AuditSeverity.Critical);
        if (critVulns > 0)
        {
            score += Math.Min(40.0, critVulns * 15.0);
            anomalies.Add($"Entity hosts {critVulns} critical CVEs actively exploitable in the wild.");
        }

        // Check endpoint security health
        var endpointDisabled = report.Findings.Any(f => f.Category == AuditCategory.EndpointSecurity && f.Severity >= AuditSeverity.High);
        if (endpointDisabled)
        {
            score += 30.0;
            anomalies.Add("Real-time endpoint defense or antivirus is disabled or degraded.");
        }

        return Math.Min(100.0, Math.Round(score, 1));
    }
}
