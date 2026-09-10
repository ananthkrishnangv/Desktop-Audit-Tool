namespace DesktopAuditTool.Core.Enums;

public enum AuditSeverity
{
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum AuditCategory
{
    AssetDiscovery,
    OsSecurity,
    Vulnerability,
    EndpointSecurity,
    Firewall,
    NetworkSecurity,
    ActiveDirectory,
    ApplicationSecurity,
    UsbDevice,
    LogAnalysis,
    MalwareThreat,
    FileIntegrity,
    Compliance,
    ConfigurationBenchmark,
    DataProtection,
    CredentialSecurity,
    PerformanceResource,
    EnterpriseManagement,
    GovernmentResearch,
    AiThreatIntel
}

public enum ComplianceStandard
{
    Iso27001,
    Nist80053,
    CisBenchmark,
    CertIn,
    MeitY,
    Stqc
}

public enum RbacRole
{
    Auditor,
    SocAnalyst,
    Administrator,
    DepartmentHead,
    ComplianceOfficer
}

public enum MitreTactic
{
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact
}

public enum AssetClassification
{
    Unclassified,
    Restricted,
    Confidential,
    Secret,
    TopSecret
}

public enum RemediationType
{
    Automatic,
    GuidedPowerShell,
    GuidedBash,
    Manual
}
