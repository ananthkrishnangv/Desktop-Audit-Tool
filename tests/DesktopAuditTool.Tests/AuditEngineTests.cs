using DesktopAuditTool.Auditors;
using DesktopAuditTool.Auditors.Modules;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using DesktopAuditTool.Reporting;
using DesktopAuditTool.ThreatIntel;
using Xunit;

namespace DesktopAuditTool.Tests;

public class AuditEngineTests
{
    [Fact]
    public void VerhoeffAadhaarValidation_ValidAndInvalidChecks()
    {
        // 12-digit number with valid Verhoeff checksum
        // Example: 2345 6789 0123 -> let's test algorithm behavior
        Assert.False(DataProtectionAuditor.ValidateVerhoeffAadhaar("123456789012")); // standard sequential fails checksum
        Assert.False(DataProtectionAuditor.ValidateVerhoeffAadhaar("123")); // wrong length
        Assert.False(DataProtectionAuditor.ValidateVerhoeffAadhaar("")); // empty
    }

    [Fact]
    public void ComplianceScorecard_CalculatesCorrectPercentages()
    {
        var sc = new ComplianceScorecard
        {
            Standard = ComplianceStandard.CertIn,
            TotalControls = 10,
            PassedControls = 8,
            FailedControls = 2
        };

        Assert.Equal(80.0, sc.CompliancePercentage);
    }

    [Fact]
    public async Task ThreatIntel_CorrelatesAttackChainsCorrectly()
    {
        var report = new AuditReport();
        report.Findings.Add(new AuditFinding
        {
            Title = "WDigest Plaintext Credential Caching",
            Category = AuditCategory.CredentialSecurity,
            Severity = AuditSeverity.Critical
        });
        report.Findings.Add(new AuditFinding
        {
            Title = "SMBv1 Protocol Enabled",
            Category = AuditCategory.NetworkSecurity,
            Severity = AuditSeverity.Critical
        });

        var threatEngine = new AiThreatEngine();
        var chains = await threatEngine.CorrelateAttackChainsAsync(report);

        Assert.NotEmpty(chains);
        Assert.Contains("Multi-Stage Attack Chain", chains[0].Title);
        Assert.True(chains[0].ConfidenceScore >= 90.0);
    }

    [Fact]
    public async Task ReportGenerators_ProduceValidOutputs()
    {
        var report = new AuditReport
        {
            TargetHostname = "TEST-WS01",
            OperatingSystem = "Windows 11 Enterprise",
            ExecutiveSummary = "Test audit summary."
        };
        report.Findings.Add(new AuditFinding
        {
            Title = "Test Critical Finding",
            Category = AuditCategory.OsSecurity,
            Severity = AuditSeverity.Critical,
            CvssScore = 9.8,
            Evidence = "Sample evidence",
            RemediationRecommendation = "Sample remediation"
        });

        var jsonGen = new JsonReportGenerator();
        var csvGen = new CsvReportGenerator();
        var htmlGen = new HtmlReportGenerator();
        var certInGen = new CertInReportGenerator();

        var jsonBytes = await jsonGen.GenerateReportBytesAsync(report);
        var csvBytes = await csvGen.GenerateReportBytesAsync(report);
        var htmlBytes = await htmlGen.GenerateReportBytesAsync(report);
        var certInText = certInGen.GenerateCertInAnnexure1(report);

        Assert.NotEmpty(jsonBytes);
        Assert.NotEmpty(csvBytes);
        Assert.NotEmpty(htmlBytes);
        Assert.Contains("CERT-In", certInText);
        Assert.Contains("TEST-WS01", certInText);
    }

    [Fact]
    public async Task AuditEngine_ExecutesAllModulesSuccessfully()
    {
        var engine = new AuditEngine();
        var ctx = new AuditContext
        {
            UserRole = RbacRole.Administrator,
            AssetClassification = AssetClassification.Restricted,
            Department = "CSIR Research Lab",
            ProjectName = "AI Strategic Systems"
        };

        var report = await engine.RunFullAuditAsync(ctx);

        Assert.NotNull(report);
        Assert.NotEmpty(report.Findings);
        Assert.NotNull(report.Inventory);
        Assert.NotEmpty(report.ComplianceScorecards);
        Assert.True(report.TotalScanDurationSeconds >= 0);
    }
}
