using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.ThreatIntel.Engines;

public class ThreatDetectionEngine
{
    private static readonly HashSet<string> LolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "certutil.exe", "mshta.exe", "wmic.exe", "bitsadmin.exe", "cscript.exe",
        "wscript.exe", "regsvr32.exe", "rundll32.exe", "installutil.exe"
    };

    public List<AttackEvent> DetectSuspiciousBehaviors(AuditReport report)
    {
        var events = new List<AttackEvent>();

        // Check for LOLBin abuse or process anomalies
        foreach (var proc in report.Inventory.Software.StartupPrograms)
        {
            if (LolBins.Any(bin => proc.Command.Contains(bin, StringComparison.OrdinalIgnoreCase)))
            {
                events.Add(new AttackEvent
                {
                    Description = $"Living-Off-The-Land Binary (LOLBin) execution detected in startup: '{proc.Command}'",
                    Source = "Process & Startup Monitor",
                    MitreTechniqueId = "T1218",
                    Tactic = MitreTactic.DefenseEvasion,
                    Severity = AuditSeverity.High
                });
            }
        }

        // Check for password/privilege escalation findings
        var privFindings = report.Findings.Where(f => f.MitreTactic == MitreTactic.PrivilegeEscalation || f.MitreTactic == MitreTactic.CredentialAccess);
        foreach (var pf in privFindings)
        {
            events.Add(new AttackEvent
            {
                Description = $"Potential credential or privilege escalation exposure: {pf.Title}",
                Source = "Audit Engine",
                MitreTechniqueId = pf.MitreTechniqueId ?? "T1078",
                Tactic = pf.MitreTactic ?? MitreTactic.CredentialAccess,
                Severity = pf.Severity
            });
        }

        return events;
    }
}
