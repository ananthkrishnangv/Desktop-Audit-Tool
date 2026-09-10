using DesktopAuditTool.Core.Enums;

namespace DesktopAuditTool.Core.Models;

public enum DlpPatternType
{
    PanNumber,
    AadhaarNumber,
    PassportNumber,
    BankAccount,
    IfscCode,
    ApiKeyOrSecret,
    PrivateKey,
    PlaintextPassword,
    SensitiveProjectDocument
}

public class DlpFinding
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public DlpPatternType PatternType { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public int LineNumber { get; set; }
    public string MaskedSnippet { get; set; } = string.Empty;
    public string RuleTriggered { get; set; } = string.Empty;
    public AuditSeverity Severity { get; set; } = AuditSeverity.High;
    public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;
}

public enum FimStatus
{
    VerifiedClean,
    Modified,
    Missing,
    NewUnrecognized,
    PermissionChanged
}

public class FimRecord
{
    public string FilePath { get; set; } = string.Empty;
    public string ExpectedSha256 { get; set; } = string.Empty;
    public string CurrentSha256 { get; set; } = string.Empty;
    public FimStatus Status { get; set; } = FimStatus.VerifiedClean;
    public DateTime LastModified { get; set; }
    public long SizeBytes { get; set; }
    public string Description { get; set; } = string.Empty;
}
