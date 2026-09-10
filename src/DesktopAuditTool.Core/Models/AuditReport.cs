using DesktopAuditTool.Core.Enums;

namespace DesktopAuditTool.Core.Models;

public class AuditReport
{
    public string AuditId { get; set; } = $"AUDIT-{DateTime.UtcNow:yyyyMMdd-HHmmss}";
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    public string TargetHostname { get; set; } = Environment.MachineName;
    public string OperatingSystem { get; set; } = Environment.OSVersion.ToString();
    public string AuditorUser { get; set; } = Environment.UserName;
    public string DomainOrWorkgroup { get; set; } = Environment.UserDomainName;
    public RbacRole ExecutedUnderRole { get; set; } = RbacRole.Administrator;
    
    // Executive summary and aggregated scores
    public string ExecutiveSummary { get; set; } = string.Empty;
    public AiSecurityScores Scores { get; set; } = new();

    // Findings
    public List<AuditFinding> Findings { get; set; } = [];
    public int CriticalFindingsCount => Findings.Count(f => f.Severity == AuditSeverity.Critical);
    public int HighFindingsCount => Findings.Count(f => f.Severity == AuditSeverity.High);
    public int MediumFindingsCount => Findings.Count(f => f.Severity == AuditSeverity.Medium);
    public int LowFindingsCount => Findings.Count(f => f.Severity == AuditSeverity.Low);
    public int InformationalFindingsCount => Findings.Count(f => f.Severity == AuditSeverity.Informational);

    // Deep Sub-system data
    public AssetInventory Inventory { get; set; } = new();
    public List<ComplianceScorecard> ComplianceScorecards { get; set; } = [];
    public List<DlpFinding> DlpFindings { get; set; } = [];
    public List<FimRecord> FimRecords { get; set; } = [];
    public List<AttackChain> CorrelatedAttackChains { get; set; } = [];
    public SecurityKnowledgeGraph KnowledgeGraph { get; set; } = new();
    public GovResearchProfile GovProfile { get; set; } = new();
    public CertInIncidentReport? CertInReport { get; set; }

    // Execution stats
    public Dictionary<string, double> ModuleExecutionTimesMs { get; set; } = [];
    public double TotalScanDurationSeconds { get; set; }
}
