using DesktopAuditTool.Core.Enums;

namespace DesktopAuditTool.Core.Models;

public class ComplianceControlResult
{
    public string ControlId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool Passed { get; set; }
    public string Evidence { get; set; } = string.Empty;
    public string RemediationGuidance { get; set; } = string.Empty;
    public AuditSeverity SeverityOnFailure { get; set; } = AuditSeverity.Medium;
}

public class ComplianceScorecard
{
    public ComplianceStandard Standard { get; set; }
    public string StandardTitle { get; set; } = string.Empty;
    public int TotalControls { get; set; }
    public int PassedControls { get; set; }
    public int FailedControls { get; set; }
    public double CompliancePercentage => TotalControls > 0 ? Math.Round((double)PassedControls / TotalControls * 100, 1) : 100.0;
    public List<ComplianceControlResult> Controls { get; set; } = [];
}
