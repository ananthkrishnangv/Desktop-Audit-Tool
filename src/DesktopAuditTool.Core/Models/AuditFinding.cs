using DesktopAuditTool.Core.Enums;

namespace DesktopAuditTool.Core.Models;

public record ComplianceMapping(
    ComplianceStandard Standard,
    string ControlId,
    string ControlName,
    string RequirementSummary
);

public class AuditFinding
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..10];
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public AuditCategory Category { get; set; }
    public AuditSeverity Severity { get; set; } = AuditSeverity.Medium;
    public double CvssScore { get; set; } = 0.0;
    public string? CveId { get; set; }
    public string? MitreTechniqueId { get; set; }
    public MitreTactic? MitreTactic { get; set; }
    public List<ComplianceMapping> ComplianceMappings { get; set; } = [];
    public string AffectedAsset { get; set; } = Environment.MachineName;
    public string Evidence { get; set; } = string.Empty;
    public string RemediationRecommendation { get; set; } = string.Empty;
    public string? RemediationScript { get; set; }
    public RemediationType RemediationType { get; set; } = RemediationType.Manual;
    public bool CanAutoRemediate { get; set; } = false;
    public bool IsRemediated { get; set; } = false;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
