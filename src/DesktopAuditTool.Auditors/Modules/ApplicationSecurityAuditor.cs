using System.Diagnostics;
using System.IO;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Auditors.Modules;

public class ApplicationSecurityAuditor : IAuditModule
{
    public string Name => "Application Security Audit";
    public AuditCategory Category => AuditCategory.ApplicationSecurity;
    public int Priority => 8;

    private readonly Dictionary<string, (string Category, AuditSeverity Severity, string Reason)> _blacklistedApplications = new(StringComparer.OrdinalIgnoreCase)
    {
        { "TeamViewer", ("Unapproved Remote Access Tool", AuditSeverity.High, "Third-party remote desktop tool allows unmonitored external inbound connections.") },
        { "AnyDesk", ("Unapproved Remote Access Tool", AuditSeverity.High, "Unauthorized remote management utility frequently targeted in social engineering attacks.") },
        { "Ammyy", ("Dangerous Remote Access Tool", AuditSeverity.Critical, "Known malicious or insecure remote access software.") },
        { "uTorrent", ("P2P File Sharing Software", AuditSeverity.High, "Torrent clients violate institutional policy and risk malware transmission and copyright liability.") },
        { "BitTorrent", ("P2P File Sharing Software", AuditSeverity.High, "Peer-to-peer file sharing creates unauthorized outbound ports and high data exfiltration risk.") },
        { "Wireshark", ("Packet Sniffer Utility", AuditSeverity.Medium, "Network sniffer should only be deployed on designated diagnostic workstations.") },
        { "Mimikatz", ("Offensive Hacking Tool", AuditSeverity.Critical, "Credential dumping utility detected.") },
        { "Nmap", ("Network Port Scanner", AuditSeverity.Medium, "Network port discovery tool should be authorized only for designated SOC/IT staff.") },
        { "CCleaner", ("System Cleaner Utility", AuditSeverity.Low, "Third-party cleaner tool historically compromised; institutional cleanup tools preferred.") },
        { "XMRig", ("Cryptocurrency Miner", AuditSeverity.Critical, "Unauthorized crypto miner consumes CPU and indicates system compromise.") }
    };

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();
        var installedApps = context.SharedInventory.Software.InstalledApplications;

        await Task.Run(() =>
        {
            // Check installed applications against blacklist
            foreach (var app in installedApps)
            {
                foreach (var kvp in _blacklistedApplications)
                {
                    if (app.Name.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        var (cat, sev, reason) = kvp.Value;
                        findings.Add(new AuditFinding
                        {
                            Title = $"Unauthorized Software: {app.Name} ({cat})",
                            Description = $"{reason} (Detected: '{app.Name}' v{app.Version}).",
                            Category = AuditCategory.ApplicationSecurity,
                            Severity = sev,
                            CvssScore = sev == AuditSeverity.Critical ? 9.0 : sev == AuditSeverity.High ? 7.5 : 5.0,
                            MitreTechniqueId = "T1219",
                            MitreTactic = MitreTactic.CommandAndControl,
                            Evidence = $"Application: {app.Name}, Version: {app.Version}, Publisher: {app.Publisher}",
                            RemediationRecommendation = $"Uninstall {app.Name} from workstation or seek formal IT security exception approval.",
                            RemediationType = RemediationType.Manual,
                            ComplianceMappings = [
                                new ComplianceMapping(ComplianceStandard.CertIn, "CI-14", "Whitelisted Software Policy", "Prohibit unapproved remote desktop and P2P software"),
                                new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 2.1", "Inventory and Control of Software Assets", "Ensure only authorized software is installed")
                            ]
                        });
                    }
                }
            }

            // Browser saved credentials / SQLite check in AppData
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var chromeLoginData = Path.Combine(localAppData, @"Google\Chrome\User Data\Default\Login Data");
            var edgeLoginData = Path.Combine(localAppData, @"Microsoft\Edge\User Data\Default\Login Data");

            if (File.Exists(chromeLoginData) || File.Exists(edgeLoginData))
            {
                findings.Add(new AuditFinding
                {
                    Title = "Browser Built-In Credential Storage in Use",
                    Description = "Chromium-based browser Login Data database exists. Built-in browser password stores are accessible to info-stealer malware.",
                    Category = AuditCategory.ApplicationSecurity,
                    Severity = AuditSeverity.Medium,
                    CvssScore = 6.0,
                    MitreTechniqueId = "T1555.003",
                    MitreTactic = MitreTactic.CredentialAccess,
                    Evidence = $"Browser Login Data detected at: {(File.Exists(chromeLoginData) ? "Chrome " : "")}{(File.Exists(edgeLoginData) ? "Edge" : "")}",
                    RemediationRecommendation = "Enforce enterprise password manager (e.g., KeePassXC / Bitwarden) and disable browser password autofill/save via GPO.",
                    RemediationType = RemediationType.Manual,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-01", "Password Security", "Prohibit unencrypted browser password saving"),
                        new ComplianceMapping(ComplianceStandard.Nist80053, "IA-5", "Authenticator Management", "Protect stored authenticators")
                    ]
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
