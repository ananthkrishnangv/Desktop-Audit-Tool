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
    Stqc,
    DpdpAct2023,
    DisaStig,
    Cmmc2,
    Nist800171,
    PciDss,
    Sox,
    Glba
}

[Flags]
public enum ComplianceProfile
{
    None = 0,
    IndianSovereign = 1 << 0,     // CERT-In, DPDP 2023, MeitY, STQC
    UsDefense = 1 << 1,           // DoD DISA STIG, CMMC 2.0, NIST SP 800-171
    UsFinancial = 1 << 2,         // PCI-DSS v4.0, SOX 404 ITGC, GLBA Safeguards
    GlobalEnterprise = 1 << 3,    // ISO 27001:2022, NIST SP 800-53, CIS Benchmarks
    All = IndianSovereign | UsDefense | UsFinancial | GlobalEnterprise
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
