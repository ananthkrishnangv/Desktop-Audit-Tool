using DesktopAuditTool.Core.Enums;

namespace DesktopAuditTool.Core.Models;

public class AiSecurityScores
{
    public double SecurityHealthScore { get; set; } = 85.0; // 0-100 (higher is better)
    public double ThreatScore { get; set; } = 25.0;         // 0-100 (lower is better)
    public double ComplianceScore { get; set; } = 90.0;     // 0-100 (higher is better)
    public double AiRiskScore { get; set; } = 35.0;         // 0-100 (lower is better)
    public double InsiderThreatScore { get; set; } = 15.0;  // 0-100 (lower is better)
    public double RansomwareProbability { get; set; } = 8.0;// 0-100 percentage
}

public class AttackEvent
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Description { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string MitreTechniqueId { get; set; } = string.Empty;
    public MitreTactic Tactic { get; set; } = MitreTactic.Execution;
    public AuditSeverity Severity { get; set; } = AuditSeverity.High;
}

public class AttackChain
{
    public string ChainId { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Title { get; set; } = string.Empty;
    public double ConfidenceScore { get; set; } = 90.0;
    public List<AttackEvent> Events { get; set; } = [];
    public string RootCauseAnalysis { get; set; } = string.Empty;
    public string ImpactAssessment { get; set; } = string.Empty;
    public string SuggestedRemediation { get; set; } = string.Empty;
}

public class ProcessTreeNode
{
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public double CpuPercent { get; set; }
    public double MemoryMb { get; set; }
    public bool IsSuspicious { get; set; }
    public List<string> AnomalyReasons { get; set; } = [];
    public List<ProcessTreeNode> Children { get; set; } = [];
}

public class GraphNode
{
    public string Id { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty; // User, Workstation, Project, Vulnerability, Threat, Department
    public Dictionary<string, string> Properties { get; set; } = [];
}

public class GraphEdge
{
    public string SourceId { get; set; } = string.Empty;
    public string TargetId { get; set; } = string.Empty;
    public string Relationship { get; set; } = string.Empty; // ACCESSES, BELONGS_TO, COMPROMISED_BY, VULNERABLE_TO
}

public class SecurityKnowledgeGraph
{
    public List<GraphNode> Nodes { get; set; } = [];
    public List<GraphEdge> Edges { get; set; } = [];
}

public class GovResearchProfile
{
    public string OrganizationType { get; set; } = "CSIR / Research Lab";
    public string DepartmentName { get; set; } = "Advanced Computing & Systems";
    public string ProjectName { get; set; } = "National Strategic Initiative";
    public AssetClassification ClassificationLevel { get; set; } = AssetClassification.Restricted;
    public List<string> ScientificSoftwareInventory { get; set; } = [];
    public bool IsNicCompliant { get; set; } = true;
    public bool IsEOfficeCompatible { get; set; } = true;
    public bool HasCertInIncident { get; set; } = false;
    public string DigitalEvidenceHashChain { get; set; } = string.Empty;
}

public class CertInIncidentReport
{
    public string IncidentId { get; set; } = $"CERTIN-INC-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString("N")[..4].ToUpper()}";
    public DateTime IncidentDetectionTime { get; set; } = DateTime.UtcNow;
    public string OrganizationName { get; set; } = "CSIR / Autonomous R&D Body";
    public string AffectedSystemName { get; set; } = Environment.MachineName;
    public string AffectedIpAddress { get; set; } = "127.0.0.1";
    public string IncidentType { get; set; } = "Suspicious Behavior / Configuration Drift / Malware Attempt";
    public string DescriptionOfIncident { get; set; } = string.Empty;
    public string ImpactAssessment { get; set; } = string.Empty;
    public string ActionsTaken { get; set; } = string.Empty;
    public string ContactEmail { get; set; } = "ciso@organization.res.in";
}
