using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.ThreatIntel.Engines;

public class ThreatHuntingAssistant
{
    public List<AuditFinding> SearchThreats(string query, AuditReport report)
    {
        var cleanQuery = query.Trim().ToLowerInvariant();

        if (cleanQuery.Contains("critical") || cleanQuery.Contains("highest"))
        {
            return report.Findings.Where(f => f.Severity == AuditSeverity.Critical).ToList();
        }
        if (cleanQuery.Contains("mitre") || cleanQuery.Contains("tactic") || cleanQuery.Contains("technique"))
        {
            return report.Findings.Where(f => !string.IsNullOrEmpty(f.MitreTechniqueId)).ToList();
        }
        if (cleanQuery.Contains("cve") || cleanQuery.Contains("vulnerab"))
        {
            return report.Findings.Where(f => f.Category == AuditCategory.Vulnerability || !string.IsNullOrEmpty(f.CveId)).ToList();
        }
        if (cleanQuery.Contains("credential") || cleanQuery.Contains("password") || cleanQuery.Contains("admin"))
        {
            return report.Findings.Where(f => f.Category == AuditCategory.CredentialSecurity || f.Title.Contains("Password", StringComparison.OrdinalIgnoreCase)).ToList();
        }
        if (cleanQuery.Contains("firewall") || cleanQuery.Contains("port"))
        {
            return report.Findings.Where(f => f.Category == AuditCategory.Firewall || f.Category == AuditCategory.NetworkSecurity).ToList();
        }

        return report.Findings.Where(f =>
            f.Title.Contains(cleanQuery, StringComparison.OrdinalIgnoreCase) ||
            f.Description.Contains(cleanQuery, StringComparison.OrdinalIgnoreCase) ||
            f.Evidence.Contains(cleanQuery, StringComparison.OrdinalIgnoreCase)
        ).ToList();
    }
}

public class RansomwareEarlyWarning
{
    public double CalculateRansomwareRiskProbability(AuditReport report, out List<string> indicators)
    {
        indicators = [];
        double probability = 5.0; // Baseline low

        // Indicator 1: SMBv1 or exposed SMB
        if (report.Findings.Any(f => f.Title.Contains("SMBv1", StringComparison.OrdinalIgnoreCase)))
        {
            probability += 30.0;
            indicators.Add("SMBv1 enabled (High risk of EternalBlue ransomware worm propagation).");
        }

        // Indicator 2: Disabled host firewall
        if (report.Findings.Any(f => f.Category == AuditCategory.Firewall && f.Severity == AuditSeverity.Critical))
        {
            probability += 25.0;
            indicators.Add("Host firewall disabled, allowing unhindered lateral ransomware spreading.");
        }

        // Indicator 3: Unprotected LSASS / WDigest
        if (report.Findings.Any(f => f.Category == AuditCategory.CredentialSecurity && f.Severity >= AuditSeverity.High))
        {
            probability += 20.0;
            indicators.Add("Unprotected credential caching enables rapid credential theft for domain-wide ransomware staging.");
        }

        // Indicator 4: AutoRun enabled
        if (report.Findings.Any(f => f.Title.Contains("AutoRun", StringComparison.OrdinalIgnoreCase)))
        {
            probability += 15.0;
            indicators.Add("Removable media AutoRun enabled (USB ransomware delivery vector).");
        }

        return Math.Min(98.0, Math.Round(probability, 1));
    }
}

public class InsiderThreatDetector
{
    public double CalculateInsiderThreatScore(AuditReport report, out List<string> indicators)
    {
        indicators = [];
        double score = 10.0;

        // Check for sensitive DLP documents on Desktop/Downloads
        if (report.DlpFindings.Count > 0)
        {
            score += Math.Min(35.0, report.DlpFindings.Count * 12.0);
            indicators.Add($"{report.DlpFindings.Count} sensitive document(s) (PAN, Aadhaar, private keys) stored in unencrypted public user directories.");
        }

        // Check for unauthorized remote desktop applications
        if (report.Findings.Any(f => f.Title.Contains("AnyDesk", StringComparison.OrdinalIgnoreCase) || f.Title.Contains("TeamViewer", StringComparison.OrdinalIgnoreCase)))
        {
            score += 30.0;
            indicators.Add("Unapproved remote control software detected, enabling unmonitored off-site data exfiltration.");
        }

        // Check for USB storage enabled on classified endpoint
        if (report.Findings.Any(f => f.Category == AuditCategory.UsbDevice && f.Severity >= AuditSeverity.High))
        {
            score += 25.0;
            indicators.Add("USB mass storage driver active on classified workstation, risking physical bulk exfiltration.");
        }

        return Math.Min(100.0, Math.Round(score, 1));
    }
}

public class ThreatCorrelationEngine
{
    public List<AttackChain> CorrelateEvents(AuditReport report)
    {
        var chains = new List<AttackChain>();

        // Attack Chain 1: Credential Access -> Lateral Movement -> Ransomware Exposure
        var hasCredRisk = report.Findings.Any(f => f.Category == AuditCategory.CredentialSecurity && f.Severity >= AuditSeverity.High);
        var hasNetRisk = report.Findings.Any(f => (f.Category == AuditCategory.NetworkSecurity || f.Category == AuditCategory.Firewall) && f.Severity >= AuditSeverity.High);
        var hasAutoRun = report.Findings.Any(f => f.Category == AuditCategory.UsbDevice && f.Severity >= AuditSeverity.High);

        if (hasCredRisk && hasNetRisk)
        {
            var chain = new AttackChain
            {
                Title = "High-Confidence Multi-Stage Attack Chain Detected: Credential Theft & Lateral Propagation",
                ConfidenceScore = 94.0,
                RootCauseAnalysis = "Vulnerable network protocols (SMBv1/RDP without NLA) combined with unhardened LSASS credential storage create an unobstructed pivot path for active adversaries.",
                ImpactAssessment = "An attacker obtaining unprivileged initial access can extract domain credentials from memory and pivot laterally to compromise adjacent research infrastructure.",
                SuggestedRemediation = "1. Enable LSA Protection (RunAsPPL).\n2. Disable SMBv1 and enforce NLA on RDP.\n3. Turn on host firewall on all profiles."
            };

            chain.Events.Add(new AttackEvent
            {
                Timestamp = DateTime.UtcNow.AddMinutes(-45),
                Description = "Initial Vector: Network exposure or unauthorized USB insertion allowed ingress.",
                MitreTechniqueId = "T1091",
                Tactic = MitreTactic.InitialAccess,
                Severity = AuditSeverity.High
            });

            chain.Events.Add(new AttackEvent
            {
                Timestamp = DateTime.UtcNow.AddMinutes(-30),
                Description = "Credential Access: Unprotected LSASS / WDigest allows plaintext credential dumping via Mimikatz.",
                MitreTechniqueId = "T1003.001",
                Tactic = MitreTactic.CredentialAccess,
                Severity = AuditSeverity.Critical
            });

            chain.Events.Add(new AttackEvent
            {
                Timestamp = DateTime.UtcNow.AddMinutes(-10),
                Description = "Lateral Movement: Unrestricted SMB / RDP enables worm-like propagation across local subnet.",
                MitreTechniqueId = "T1021.002",
                Tactic = MitreTactic.LateralMovement,
                Severity = AuditSeverity.Critical
            });

            chains.Add(chain);
        }

        return chains;
    }
}
