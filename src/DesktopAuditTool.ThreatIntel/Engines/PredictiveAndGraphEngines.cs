using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.ThreatIntel.Engines;

public class PredictiveRiskEngine
{
    public double ForecastCompromiseProbability(AuditReport report, out List<string> contributingFactors)
    {
        contributingFactors = [];
        double baseScore = 15.0;

        var critCount = report.Findings.Count(f => f.Severity == AuditSeverity.Critical);
        var highCount = report.Findings.Count(f => f.Severity == AuditSeverity.High);

        if (critCount > 0)
        {
            baseScore += Math.Min(50.0, critCount * 20.0);
            contributingFactors.Add($"{critCount} unpatched critical vulnerabilities or severe misconfigurations.");
        }
        if (highCount > 0)
        {
            baseScore += Math.Min(25.0, highCount * 7.0);
            contributingFactors.Add($"{highCount} high-severity security exposures.");
        }

        if (report.Findings.Any(f => f.Title.Contains("Firewall", StringComparison.OrdinalIgnoreCase) && f.Severity == AuditSeverity.Critical))
        {
            contributingFactors.Add("Host perimeter shielding disabled.");
        }

        if (report.DlpFindings.Count > 0)
        {
            contributingFactors.Add("Sensitive national PII or credentials exposed locally.");
        }

        return Math.Min(95.0, Math.Round(baseScore, 1));
    }
}

public class VulnerabilityPrioritizer
{
    public List<AuditFinding> PrioritizeVulnerabilities(AuditReport report)
    {
        return report.Findings
            .OrderByDescending(f => f.CvssScore + (f.Severity == AuditSeverity.Critical ? 5.0 : 0.0))
            .ThenByDescending(f => f.CanAutoRemediate ? 2.0 : 0.0)
            .ToList();
    }
}

public class ZeroDayDetector
{
    public double CalculateZeroDaySusceptibility(AuditReport report, out List<string> indicators)
    {
        indicators = [];
        double score = 10.0;

        // Missing EDR/AV RTP
        var endpointIssue = report.Findings.Any(f => f.Category == AuditCategory.EndpointSecurity && f.Severity >= AuditSeverity.High);
        if (endpointIssue)
        {
            score += 35.0;
            indicators.Add("Endpoint protection offline or real-time behavioral monitoring inactive.");
        }

        // Outdated browser or EOL OS
        var eolIssue = report.Findings.Any(f => f.Title.Contains("End-Of-Life", StringComparison.OrdinalIgnoreCase) || f.Title.Contains("EOL", StringComparison.OrdinalIgnoreCase));
        if (eolIssue)
        {
            score += 40.0;
            indicators.Add("Operating system or base libraries are no longer receiving vendor security patches.");
        }

        return Math.Min(100.0, Math.Round(score, 1));
    }
}

public class SecurityKnowledgeGraphEngine
{
    public SecurityKnowledgeGraph BuildGraph(AuditReport report)
    {
        var graph = new SecurityKnowledgeGraph();

        // 1. Host Node
        var hostId = $"node-host-{report.TargetHostname}";
        graph.Nodes.Add(new GraphNode
        {
            Id = hostId,
            Label = report.TargetHostname,
            Type = "Workstation",
            Properties = new Dictionary<string, string>
            {
                { "OS", report.OperatingSystem },
                { "Domain", report.DomainOrWorkgroup },
                { "Classification", report.GovProfile.ClassificationLevel.ToString() }
            }
        });

        // 2. Department & Project Nodes
        var deptId = $"node-dept-{report.GovProfile.DepartmentName.Replace(" ", "_")}";
        graph.Nodes.Add(new GraphNode
        {
            Id = deptId,
            Label = report.GovProfile.DepartmentName,
            Type = "Department",
            Properties = new Dictionary<string, string> { { "Organization", report.GovProfile.OrganizationType } }
        });

        var projId = $"node-proj-{report.GovProfile.ProjectName.Replace(" ", "_")}";
        graph.Nodes.Add(new GraphNode
        {
            Id = projId,
            Label = report.GovProfile.ProjectName,
            Type = "Project",
            Properties = new Dictionary<string, string>()
        });

        graph.Edges.Add(new GraphEdge { SourceId = hostId, TargetId = deptId, Relationship = "BELONGS_TO" });
        graph.Edges.Add(new GraphEdge { SourceId = hostId, TargetId = projId, Relationship = "ASSIGNED_TO_PROJECT" });

        // 3. User Nodes
        foreach (var user in report.Inventory.Users.LocalUsers.Take(5))
        {
            var uId = $"node-user-{user.Username}";
            graph.Nodes.Add(new GraphNode
            {
                Id = uId,
                Label = user.Username,
                Type = "User",
                Properties = new Dictionary<string, string>
                {
                    { "IsAdmin", user.IsAdministrator.ToString() },
                    { "PasswordNeverExpires", user.PasswordNeverExpires.ToString() }
                }
            });
            graph.Edges.Add(new GraphEdge { SourceId = uId, TargetId = hostId, Relationship = "LOGS_INTO" });
        }

        // 4. Critical Threat Nodes
        foreach (var finding in report.Findings.Where(f => f.Severity >= AuditSeverity.High).Take(8))
        {
            var threatId = $"node-threat-{finding.Id}";
            graph.Nodes.Add(new GraphNode
            {
                Id = threatId,
                Label = finding.Title,
                Type = "VulnerabilityOrThreat",
                Properties = new Dictionary<string, string>
                {
                    { "Severity", finding.Severity.ToString() },
                    { "CVSS", finding.CvssScore.ToString("F1") }
                }
            });
            graph.Edges.Add(new GraphEdge { SourceId = hostId, TargetId = threatId, Relationship = "VULNERABLE_TO" });
        }

        return graph;
    }
}

public class IncidentInvestigator
{
    public string GenerateForensicInvestigationNarrative(AuditReport report)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"# Forensic Security Incident Investigation Narrative");
        sb.AppendLine($"**Target System:** {report.TargetHostname} | **Investigation Time:** {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"**Investigator Role:** {report.ExecutedUnderRole} | **Classification:** {report.GovProfile.ClassificationLevel}\n");

        sb.AppendLine("## 1. Executive Incident Summary");
        sb.AppendLine($"Automated forensic telemetry synthesis discovered {report.CriticalFindingsCount} Critical and {report.HighFindingsCount} High severity exposure vectors.");
        if (report.CorrelatedAttackChains.Count > 0)
        {
            sb.AppendLine($"Correlation engine identified {report.CorrelatedAttackChains.Count} active multi-stage attack sequence(s) threatening the workstation.");
        }
        sb.AppendLine();

        sb.AppendLine("## 2. Root Cause Analysis");
        if (report.CriticalFindingsCount > 0)
        {
            var topCrit = report.Findings.First(f => f.Severity == AuditSeverity.Critical);
            sb.AppendLine($"The primary root cause is attributed to: **{topCrit.Title}**.");
            sb.AppendLine($"Details: {topCrit.Description}");
            sb.AppendLine($"Evidence: `{topCrit.Evidence}`");
        }
        else
        {
            sb.AppendLine("No critical vulnerabilities detected. Root posture aligns with baseline institutional standards.");
        }
        sb.AppendLine();

        sb.AppendLine("## 3. Impact Assessment & Remediation Guidance");
        sb.AppendLine("Failure to remediate the identified vulnerabilities may allow lateral privilege escalation across the institutional intranet.");
        sb.AppendLine("Recommended immediate actions:");
        sb.AppendLine("1. Apply automated one-click remediation for flagged system services.");
        sb.AppendLine("2. Enforce local password complexity and account lockout policies.");
        sb.AppendLine("3. Isolate sensitive project documentation into encrypted repositories.");

        return sb.ToString();
    }
}

public class ResearchLabAiEngine
{
    public double CalculateProjectRisk(GovResearchProfile profile, AuditReport report, out List<string> riskFactors)
    {
        riskFactors = [];
        double risk = 20.0;

        if (profile.ClassificationLevel >= AssetClassification.Confidential)
        {
            risk += 15.0;
            riskFactors.Add($"Classified research asset tier: {profile.ClassificationLevel}.");
        }

        if (report.DlpFindings.Count > 0)
        {
            risk += 25.0;
            riskFactors.Add($"Exposed research or national identity credentials ({report.DlpFindings.Count} instances).");
        }

        if (!profile.IsEOfficeCompatible)
        {
            risk += 10.0;
            riskFactors.Add("eOffice smart card signing service disabled, impacting official file processing.");
        }

        if (report.Findings.Any(f => f.Severity == AuditSeverity.Critical))
        {
            risk += 20.0;
            riskFactors.Add("Critical system vulnerability presence compromises project integrity.");
        }

        return Math.Min(100.0, Math.Round(risk, 1));
    }
}
