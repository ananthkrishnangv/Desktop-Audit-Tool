using System.Diagnostics;
using DesktopAuditTool.Auditors;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using DesktopAuditTool.Reporting;
using DesktopAuditTool.ThreatIntel;

namespace DesktopAuditTool.App;

public static class Program
{
    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        PrintBanner();

        var isCli = args.Contains("--cli") || args.Contains("--audit") || args.Contains("--all") || args.Contains("--headless");
        var exportDir = GetArgumentValue(args, "--export") ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "reports");

        if (args.Contains("--help") || args.Contains("-h"))
        {
            PrintHelp();
            return;
        }

        if (isCli)
        {
            await RunCliAuditAsync(exportDir, args);
        }
        else
        {
            await RunDesktopGuiAsync();
        }
    }

    private static void PrintBanner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║       ENTERPRISE DESKTOP SECURITY AUDIT & AI THREAT INTELLIGENCE PLATFORM             ║
║            Tailored for Government Labs, PSUs, CSIR, DRDO, ISRO & IITs               ║
║                     Built on .NET 10 (Standalone Native Desktop)                     ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝");
        Console.ResetColor();
    }

    private static void PrintHelp()
    {
        Console.WriteLine(@"
Usage:
  DesktopAuditTool.App.exe [options]

Options:
  --gui                   Launch interactive Standalone Desktop GUI (Default)
  --audit, --cli, --all   Run headless command-line audit across all 22 modules
  --export <directory>    Directory path to export PDF, Excel, HTML, CSV, JSON, CERT-In
  --classification <tier> Asset classification (Unclassified, Restricted, Confidential, Secret, TopSecret)
  --dept <name>           Department name (e.g. 'Cyber Systems')
  --project <name>        Project title (e.g. 'Strategic Computing')
  -h, --help              Show this help menu
");
    }

    private static async Task RunCliAuditAsync(string exportDir, string[] args)
    {
        Console.WriteLine($"[*] Target Host: {Environment.MachineName} ({Environment.OSVersion})");
        Console.WriteLine($"[*] Auditor: {Environment.UserName} | Domain: {Environment.UserDomainName}");
        Console.WriteLine($"[*] Initiating full 22-Module Enterprise Security Audit...\n");

        var auditEngine = new AuditEngine();
        var threatEngine = new AiThreatEngine();
        var reportManager = new ReportManager();

        var ctx = new AuditContext
        {
            UserRole = RbacRole.Administrator,
            AssetClassification = AssetClassification.Restricted,
            Department = GetArgumentValue(args, "--dept") ?? "CSIR Strategic Systems",
            ProjectName = GetArgumentValue(args, "--project") ?? "High Performance Computing Security"
        };

        var report = await auditEngine.RunFullAuditAsync(ctx, (msg, pct) =>
        {
            Console.WriteLine($"  [{pct,3}%] {msg}");
        });

        Console.WriteLine("\n[*] Synthesizing AI Threat Intelligence & Behavioral Analytics...");
        report.Scores = await threatEngine.CalculateAiScoresAsync(report);
        report.CorrelatedAttackChains = await threatEngine.CorrelateAttackChainsAsync(report);

        // Display Scorecard
        Console.WriteLine("\n" + new string('=', 78));
        Console.WriteLine("                  EXECUTIVE AUDIT & THREAT INTELLIGENCE SCORECARD");
        Console.WriteLine(new string('=', 78));
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  * Security Health Score:     {report.Scores.SecurityHealthScore,5:F1} / 100  (Overall Security Posture)");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  * Threat Score:              {report.Scores.ThreatScore,5:F1} / 100  (Active Threat Exposure)");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  * Compliance Score:          {report.Scores.ComplianceScore,5:F1} %      (CERT-In, ISO 27001, CIS)");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"  * AI Risk Compromise Index:  {report.Scores.AiRiskScore,5:F1} %      (Forecast Probability)");
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine($"  * Insider Threat Score:      {report.Scores.InsiderThreatScore,5:F1} %      (Data Leak Exposure)");
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine($"  * Ransomware Exposure:       {report.Scores.RansomwareProbability,5:F1} %      (Propagation Vulnerability)");
        Console.ResetColor();
        Console.WriteLine(new string('-', 78));

        Console.WriteLine($"\n[*] Findings Summary: {report.Findings.Count} Total ({report.CriticalFindingsCount} Critical, {report.HighFindingsCount} High, {report.MediumFindingsCount} Medium, {report.LowFindingsCount} Low)");

        foreach (var f in report.Findings.Where(f => f.Severity >= AuditSeverity.High).Take(8))
        {
            var color = f.Severity == AuditSeverity.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;
            Console.ForegroundColor = color;
            Console.WriteLine($"  [{f.Severity}] {f.Title}");
            Console.ResetColor();
            Console.WriteLine($"     Category: {f.Category} | CVSS: {f.CvssScore:F1}");
            Console.WriteLine($"     Evidence: {f.Evidence}");
            Console.WriteLine($"     Remediation: {f.RemediationRecommendation}\n");
        }

        // Export reports
        Console.WriteLine($"[*] Exporting multi-format enterprise audit reports to: {exportDir}");
        var files = await reportManager.ExportAllFormatsAsync(report, exportDir);
        foreach (var file in files)
        {
            Console.WriteLine($"  [✓] {Path.GetFileName(file)}");
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n[✓] Audit execution and report export complete.");
        Console.ResetColor();
    }

    private static async Task RunDesktopGuiAsync()
    {
        const int port = 58200;
        var url = $"http://127.0.0.1:{port}/";
        Console.WriteLine($"[*] Starting Enterprise Desktop Audit Server on {url}...");

        var server = new DesktopServer(port);
        var cts = new CancellationTokenSource();

        var serverTask = server.StartAsync(cts.Token);

        // Open local desktop browser window
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch
        {
            Console.WriteLine($"[!] Open your browser and navigate to: {url}");
        }

        Console.WriteLine($"[+] Desktop GUI is live at {url}");
        Console.WriteLine($"[+] Press Ctrl+C or Enter to shutdown server.\n");

        Console.ReadLine();
        cts.Cancel();
        await Task.WhenAny(serverTask, Task.Delay(500));
    }

    private static string? GetArgumentValue(string[] args, string flag)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(flag, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }
        return null;
    }
}
