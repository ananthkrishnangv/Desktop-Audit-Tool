using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Core.Interfaces;

public class AuditContext
{
    public RbacRole UserRole { get; set; } = RbacRole.Administrator;
    public AssetClassification AssetClassification { get; set; } = AssetClassification.Restricted;
    public string ProjectName { get; set; } = "Research Strategic Computing";
    public string Department { get; set; } = "Cyber & High Performance Systems";
    public bool DeepDlpScan { get; set; } = true;
    public bool QuickScanOnly { get; set; } = false;
    public AssetInventory SharedInventory { get; set; } = new();
}

public class AuditModuleResult
{
    public string ModuleName { get; set; } = string.Empty;
    public AuditCategory Category { get; set; }
    public List<AuditFinding> Findings { get; set; } = [];
    public Dictionary<string, object> ExtraData { get; set; } = [];
    public double ExecutionDurationMs { get; set; }
}

public interface IAuditModule
{
    string Name { get; }
    AuditCategory Category { get; }
    int Priority { get; } // 1 to 22
    Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default);
}

public interface IAiThreatEngine
{
    Task<AiSecurityScores> CalculateAiScoresAsync(AuditReport report, CancellationToken cancellationToken = default);
    Task<List<AttackChain>> CorrelateAttackChainsAsync(AuditReport report, CancellationToken cancellationToken = default);
    Task<SecurityKnowledgeGraph> BuildKnowledgeGraphAsync(AuditReport report, CancellationToken cancellationToken = default);
    Task<string> QueryAiCopilotAsync(string userPrompt, AuditReport currentReport, CancellationToken cancellationToken = default);
    Task<string> GenerateExecutiveSummaryAsync(AuditReport report, CancellationToken cancellationToken = default);
}

public interface IRemediationEngine
{
    Task<bool> ApplyOneClickRemediationAsync(string findingId, AuditReport report, CancellationToken cancellationToken = default);
    string GenerateGuidedScript(AuditFinding finding, bool isPowerShell = true);
    string GenerateRollbackScript(AuditFinding finding);
}

public interface IReportGenerator
{
    string FormatExtension { get; }
    Task<byte[]> GenerateReportBytesAsync(AuditReport report, CancellationToken cancellationToken = default);
    Task ExportToFileAsync(AuditReport report, string outputPath, CancellationToken cancellationToken = default);
}
