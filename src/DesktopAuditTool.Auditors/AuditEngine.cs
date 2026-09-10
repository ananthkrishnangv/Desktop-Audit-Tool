using System.Diagnostics;
using DesktopAuditTool.Auditors.Modules;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Auditors;

public class AuditEngine
{
    private readonly List<IAuditModule> _modules;

    public AuditEngine()
    {
        _modules =
        [
            new AssetDiscoveryAuditor(),
            new OsSecurityAuditor(),
            new VulnerabilityAuditor(),
            new EndpointSecurityAuditor(),
            new FirewallAuditor(),
            new NetworkSecurityAuditor(),
            new ActiveDirectoryAuditor(),
            new ApplicationSecurityAuditor(),
            new UsbDeviceAuditor(),
            new LogAnalysisAuditor(),
            new MalwareThreatAuditor(),
            new FileIntegrityAuditor(),
            new ComplianceAuditor(),
            new ConfigurationBenchmarkAuditor(),
            new DataProtectionAuditor(),
            new CredentialSecurityAuditor(),
            new PerformanceResourceAuditor(),
            new EnterpriseManagementAuditor(),
            new AutomatedRemediationAuditor(),
            new GovernmentResearchAuditor(),
            new AiFeaturesAuditor()
        ];
    }

    public async Task<AuditReport> RunFullAuditAsync(AuditContext context, Action<string, int>? progressCallback = null, CancellationToken cancellationToken = default)
    {
        var totalSw = Stopwatch.StartNew();
        var report = new AuditReport
        {
            AuditorUser = Environment.UserName,
            ExecutedUnderRole = context.UserRole,
            TargetHostname = Environment.MachineName,
            OperatingSystem = Environment.OSVersion.ToString(),
            DomainOrWorkgroup = Environment.UserDomainName
        };

        var orderedModules = _modules.OrderBy(m => m.Priority).ToList();
        int current = 0;

        foreach (var module in orderedModules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            current++;
            var pct = (int)((double)current / orderedModules.Count * 100);
            progressCallback?.Invoke($"Executing [{current}/{orderedModules.Count}]: {module.Name}...", pct);

            try
            {
                var result = await module.AuditAsync(context, cancellationToken);
                report.Findings.AddRange(result.Findings);
                report.ModuleExecutionTimesMs[module.Name] = result.ExecutionDurationMs;

                // Extract extra data into report
                if (result.ExtraData.TryGetValue("Scorecards", out var sc) && sc is List<ComplianceScorecard> scorecards)
                {
                    report.ComplianceScorecards = scorecards;
                }
                if (result.ExtraData.TryGetValue("DlpFindings", out var dlp) && dlp is List<DlpFinding> dlpList)
                {
                    report.DlpFindings = dlpList;
                }
                if (result.ExtraData.TryGetValue("FimRecords", out var fim) && fim is List<FimRecord> fimList)
                {
                    report.FimRecords = fimList;
                }
                if (result.ExtraData.TryGetValue("GovProfile", out var gov) && gov is GovResearchProfile govProf)
                {
                    report.GovProfile = govProf;
                }
            }
            catch (Exception ex)
            {
                report.Findings.Add(new AuditFinding
                {
                    Title = $"Module Execution Warning: {module.Name}",
                    Description = $"Audit module encountered exception: {ex.Message}",
                    Category = module.Category,
                    Severity = AuditSeverity.Low,
                    Evidence = ex.ToString()
                });
            }
        }

        report.Inventory = context.SharedInventory;
        totalSw.Stop();
        report.TotalScanDurationSeconds = Math.Round(totalSw.Elapsed.TotalSeconds, 2);

        // Generate preliminary Executive Summary
        report.ExecutiveSummary = $"Desktop Security Audit completed on {report.TargetHostname} in {report.TotalScanDurationSeconds}s. Discovered {report.Findings.Count} total findings ({report.CriticalFindingsCount} Critical, {report.HighFindingsCount} High, {report.MediumFindingsCount} Medium, {report.LowFindingsCount} Low).";

        progressCallback?.Invoke("Audit execution completed successfully.", 100);
        return report;
    }
}
