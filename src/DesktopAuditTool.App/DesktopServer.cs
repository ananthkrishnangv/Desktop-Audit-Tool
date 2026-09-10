using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DesktopAuditTool.App.Ui;
using DesktopAuditTool.Auditors;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using DesktopAuditTool.Remediation;
using DesktopAuditTool.Reporting;
using DesktopAuditTool.ThreatIntel;

namespace DesktopAuditTool.App;

public class DesktopServer
{
    private readonly HttpListener _listener = new();
    private readonly AuditEngine _auditEngine = new();
    private readonly AiThreatEngine _threatEngine = new();
    private readonly RemediationEngine _remediationEngine = new();
    private readonly ReportManager _reportManager = new();
    private AuditReport? _latestReport;
    private readonly int _port;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    public DesktopServer(int port = 58200)
    {
        _port = port;
        _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _listener.Start();
        Console.WriteLine($"[+] Desktop Audit Server active at: http://127.0.0.1:{_port}/");

        // Run baseline initial audit
        var ctx = new AuditContext
        {
            UserRole = RbacRole.Administrator,
            AssetClassification = AssetClassification.Restricted,
            Department = "Advanced Systems & Strategic R&D",
            ProjectName = "National Autonomous Computing"
        };
        _latestReport = await _auditEngine.RunFullAuditAsync(ctx, null, cancellationToken);
        _latestReport.Scores = await _threatEngine.CalculateAiScoresAsync(_latestReport, cancellationToken);
        _latestReport.CorrelatedAttackChains = await _threatEngine.CorrelateAttackChainsAsync(_latestReport, cancellationToken);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var context = await _listener.GetContextAsync();
                _ = Task.Run(() => HandleRequestAsync(context), cancellationToken);
            }
            catch when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Listener error: {ex.Message}");
            }
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext context)
    {
        var req = context.Request;
        var res = context.Response;

        // Enable CORS
        res.AddHeader("Access-Control-Allow-Origin", "*");
        res.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.AddHeader("Access-Control-Allow-Headers", "Content-Type");

        if (req.HttpMethod == "OPTIONS")
        {
            res.StatusCode = 200;
            res.Close();
            return;
        }

        var path = req.Url?.AbsolutePath ?? "/";

        try
        {
            if (path == "/" || path == "/index.html")
            {
                var html = DashboardUiContent.GetHtml();
                var bytes = Encoding.UTF8.GetBytes(html);
                res.ContentType = "text/html; charset=utf-8";
                res.ContentLength64 = bytes.Length;
                await res.OutputStream.WriteAsync(bytes);
            }
            else if (path == "/api/audit/latest" && req.HttpMethod == "GET")
            {
                var json = JsonSerializer.Serialize(_latestReport ?? new AuditReport(), JsonOpts);
                var bytes = Encoding.UTF8.GetBytes(json);
                res.ContentType = "application/json";
                res.ContentLength64 = bytes.Length;
                await res.OutputStream.WriteAsync(bytes);
            }
            else if (path == "/api/audit/run" && req.HttpMethod == "POST")
            {
                var ctx = new AuditContext
                {
                    UserRole = RbacRole.Administrator,
                    AssetClassification = AssetClassification.Restricted
                };
                _latestReport = await _auditEngine.RunFullAuditAsync(ctx);
                _latestReport.Scores = await _threatEngine.CalculateAiScoresAsync(_latestReport);
                _latestReport.CorrelatedAttackChains = await _threatEngine.CorrelateAttackChainsAsync(_latestReport);

                var json = JsonSerializer.Serialize(_latestReport, JsonOpts);
                var bytes = Encoding.UTF8.GetBytes(json);
                res.ContentType = "application/json";
                res.ContentLength64 = bytes.Length;
                await res.OutputStream.WriteAsync(bytes);
            }
            else if (path == "/api/ai/ask" && req.HttpMethod == "POST")
            {
                using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
                var body = await reader.ReadToEndAsync();
                var prompt = "summary";
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("prompt", out var p)) prompt = p.GetString() ?? prompt;
                }
                catch { }

                var reply = await _threatEngine.QueryAiCopilotAsync(prompt, _latestReport ?? new AuditReport());
                var respObj = new { reply };
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(respObj));
                res.ContentType = "application/json";
                res.ContentLength64 = bytes.Length;
                await res.OutputStream.WriteAsync(bytes);
            }
            else if (path == "/api/remediate/one-click" && req.HttpMethod == "POST")
            {
                var findingId = req.QueryString["id"] ?? "";
                bool success = false;
                if (_latestReport != null && !string.IsNullOrEmpty(findingId))
                {
                    success = await _remediationEngine.ApplyOneClickRemediationAsync(findingId, _latestReport);
                }
                var respObj = new { success, message = success ? "Remediation applied successfully." : "Remediation failed or manual fix required." };
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(respObj));
                res.ContentType = "application/json";
                res.ContentLength64 = bytes.Length;
                await res.OutputStream.WriteAsync(bytes);
            }
            else if (path == "/api/remediate/all" && req.HttpMethod == "POST")
            {
                int count = 0;
                if (_latestReport != null)
                {
                    count = await _remediationEngine.ApplyAllOneClickRemediationsAsync(_latestReport);
                }
                var respObj = new { count, message = $"Applied {count} automated one-click remediation(s)." };
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(respObj));
                res.ContentType = "application/json";
                res.ContentLength64 = bytes.Length;
                await res.OutputStream.WriteAsync(bytes);
            }
            else if (path.StartsWith("/api/export/"))
            {
                var format = path.Replace("/api/export/", "").ToLowerInvariant();
                var report = _latestReport ?? new AuditReport();

                if (format == "html")
                {
                    var html = _reportManager.HtmlGenerator.GenerateHtmlContent(report);
                    var bytes = Encoding.UTF8.GetBytes(html);
                    res.ContentType = "text/html";
                    res.ContentLength64 = bytes.Length;
                    await res.OutputStream.WriteAsync(bytes);
                }
                else if (format == "pdf")
                {
                    var html = _reportManager.HtmlGenerator.GenerateHtmlContent(report);
                    var bytes = Encoding.UTF8.GetBytes(html);
                    res.ContentType = "text/html"; // Browser print-ready HTML
                    res.AddHeader("Content-Disposition", $"inline; filename=\"AuditReport_{report.TargetHostname}.html\"");
                    res.ContentLength64 = bytes.Length;
                    await res.OutputStream.WriteAsync(bytes);
                }
                else if (format == "xlsx")
                {
                    var xlsxGen = new ExcelReportGenerator();
                    var bytes = await xlsxGen.GenerateReportBytesAsync(report);
                    res.ContentType = "application/vnd.ms-excel";
                    res.AddHeader("Content-Disposition", $"attachment; filename=\"AuditReport_{report.TargetHostname}.xls\"");
                    res.ContentLength64 = bytes.Length;
                    await res.OutputStream.WriteAsync(bytes);
                }
                else if (format == "csv")
                {
                    var csvGen = new CsvReportGenerator();
                    var bytes = await csvGen.GenerateReportBytesAsync(report);
                    res.ContentType = "text/csv";
                    res.AddHeader("Content-Disposition", $"attachment; filename=\"AuditReport_{report.TargetHostname}.csv\"");
                    res.ContentLength64 = bytes.Length;
                    await res.OutputStream.WriteAsync(bytes);
                }
                else if (format == "json")
                {
                    var jsonGen = new JsonReportGenerator();
                    var bytes = await jsonGen.GenerateReportBytesAsync(report);
                    res.ContentType = "application/json";
                    res.AddHeader("Content-Disposition", $"attachment; filename=\"AuditReport_{report.TargetHostname}.json\"");
                    res.ContentLength64 = bytes.Length;
                    await res.OutputStream.WriteAsync(bytes);
                }
                else if (format == "certin")
                {
                    var text = _reportManager.CertInGenerator.GenerateCertInAnnexure1(report);
                    var bytes = Encoding.UTF8.GetBytes(text);
                    res.ContentType = "text/plain";
                    res.AddHeader("Content-Disposition", $"attachment; filename=\"CERT-In_Annexure-I_{report.TargetHostname}.txt\"");
                    res.ContentLength64 = bytes.Length;
                    await res.OutputStream.WriteAsync(bytes);
                }
                else
                {
                    res.StatusCode = 404;
                }
            }
            else
            {
                res.StatusCode = 404;
            }
        }
        catch (Exception ex)
        {
            res.StatusCode = 500;
            var errBytes = Encoding.UTF8.GetBytes(ex.ToString());
            await res.OutputStream.WriteAsync(errBytes);
        }
        finally
        {
            res.Close();
        }
    }
}
