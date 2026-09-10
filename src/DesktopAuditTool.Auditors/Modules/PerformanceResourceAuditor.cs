using System.Diagnostics;
using System.IO;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Auditors.Modules;

public class PerformanceResourceAuditor : IAuditModule
{
    public string Name => "Performance & Resource Audit";
    public AuditCategory Category => AuditCategory.PerformanceResource;
    public int Priority => 17;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();

        await Task.Run(() =>
        {
            // 1. Check system drive free disk space
            var sysDrive = DriveInfo.GetDrives().FirstOrDefault(d => d.IsReady && d.RootDirectory.FullName.StartsWith("C", StringComparison.OrdinalIgnoreCase));
            if (sysDrive != null)
            {
                var freeGb = Math.Round((double)sysDrive.AvailableFreeSpace / (1024 * 1024 * 1024), 1);
                var totalGb = Math.Round((double)sysDrive.TotalSize / (1024 * 1024 * 1024), 1);
                var percentFree = Math.Round((double)sysDrive.AvailableFreeSpace / sysDrive.TotalSize * 100, 1);

                if (freeGb < 15.0 || percentFree < 10.0)
                {
                    findings.Add(new AuditFinding
                    {
                        Title = $"Low Disk Space on System Drive C: ({freeGb} GB Free)",
                        Description = $"System drive C: has only {freeGb} GB ({percentFree}%) available. Insufficient disk space impairs Windows Update patching and crash dump generation.",
                        Category = AuditCategory.PerformanceResource,
                        Severity = AuditSeverity.High,
                        CvssScore = 7.0,
                        Evidence = $"Free: {freeGb} GB / Total: {totalGb} GB ({percentFree}%)",
                        RemediationRecommendation = "Clean temporary files and ensure at least 20 GB free on system drive C:.",
                        RemediationType = RemediationType.Manual,
                        ComplianceMappings = [
                            new ComplianceMapping(ComplianceStandard.Nist80053, "SI-2", "Flaw Remediation", "Maintain adequate system resources for updates")
                        ]
                    });
                }
                else
                {
                    findings.Add(new AuditFinding
                    {
                        Title = $"System Disk Health Normal ({freeGb} GB Free)",
                        Description = $"Drive C: has {freeGb} GB ({percentFree}%) healthy storage capacity.",
                        Category = AuditCategory.PerformanceResource,
                        Severity = AuditSeverity.Informational,
                        CvssScore = 0.0,
                        Evidence = $"Free: {freeGb} GB"
                    });
                }
            }

            // 2. Security agent resource overhead & conflict detection
            var processes = Process.GetProcesses();
            var securityAgents = new[] { "MsMpEng", "CSFalconService", "SentinelAgent", "mfetp", "cbdefense", "SophosED" };
            var runningAgents = new List<string>();

            foreach (var p in processes)
            {
                if (securityAgents.Any(a => p.ProcessName.Contains(a, StringComparison.OrdinalIgnoreCase)))
                {
                    runningAgents.Add(p.ProcessName);
                }
            }

            if (runningAgents.Distinct().Count() > 2)
            {
                findings.Add(new AuditFinding
                {
                    Title = $"Multiple Concurrent Antivirus/EDR Engines Detected ({runningAgents.Distinct().Count()})",
                    Description = $"Detected multiple active real-time security agents: {string.Join(", ", runningAgents.Distinct())}. Running multiple active AV engines causes file locking conflicts and high CPU degradation.",
                    Category = AuditCategory.PerformanceResource,
                    Severity = AuditSeverity.Medium,
                    CvssScore = 5.5,
                    Evidence = $"Active security processes: {string.Join(", ", runningAgents.Distinct())}",
                    RemediationRecommendation = "Configure Microsoft Defender to passive/EDR mode if third-party EDR (e.g. CrowdStrike/SentinelOne) is primary.",
                    RemediationType = RemediationType.Manual
                });
            }
        }, cancellationToken);

        sw.Stop();
        return new AuditModuleResult
        {
            ModuleName = Name,
            Category = Category,
            Findings = findings,
            ExecutionDurationMs = sw.ElapsedMilliseconds
        };
    }
}
