using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Reporting;

public class JsonReportGenerator : IReportGenerator
{
    public string FormatExtension => "json";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    public Task<byte[]> GenerateReportBytesAsync(AuditReport report, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(report, JsonOpts);
        return Task.FromResult(Encoding.UTF8.GetBytes(json));
    }

    public async Task ExportToFileAsync(AuditReport report, string outputPath, CancellationToken cancellationToken = default)
    {
        var bytes = await GenerateReportBytesAsync(report, cancellationToken);
        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
        await File.WriteAllBytesAsync(outputPath, bytes, cancellationToken);
    }
}

public class CsvReportGenerator : IReportGenerator
{
    public string FormatExtension => "csv";

    public Task<byte[]> GenerateReportBytesAsync(AuditReport report, CancellationToken cancellationToken = default)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ID,Severity,Category,CVSS,CVE,MITRE_ID,Title,Description,AffectedAsset,CanAutoRemediate,Evidence,Remediation");

        foreach (var f in report.Findings)
        {
            var line = $"{Escape(f.Id)},{f.Severity},{f.Category},{f.CvssScore:F1},{Escape(f.CveId ?? "")},{Escape(f.MitreTechniqueId ?? "")},{Escape(f.Title)},{Escape(f.Description)},{Escape(f.AffectedAsset)},{f.CanAutoRemediate},{Escape(f.Evidence)},{Escape(f.RemediationRecommendation)}";
            sb.AppendLine(line);
        }

        return Task.FromResult(Encoding.UTF8.GetBytes(sb.ToString()));
    }

    public async Task ExportToFileAsync(AuditReport report, string outputPath, CancellationToken cancellationToken = default)
    {
        var bytes = await GenerateReportBytesAsync(report, cancellationToken);
        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
        await File.WriteAllBytesAsync(outputPath, bytes, cancellationToken);
    }

    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";
        var escaped = value.Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ");
        return $"\"{escaped}\"";
    }
}
