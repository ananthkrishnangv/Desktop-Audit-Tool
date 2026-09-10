using System.Net;
using System.Text;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Reporting;

public class ExcelReportGenerator : IReportGenerator
{
    public string FormatExtension => "xlsx";

    public Task<byte[]> GenerateReportBytesAsync(AuditReport report, CancellationToken cancellationToken = default)
    {
        // Generate multi-worksheet XML Spreadsheet format compatible directly with Excel
        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\"?>");
        sb.AppendLine("<?mso-application progid=\"Excel.Sheet\"?>");
        sb.AppendLine("<Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\"");
        sb.AppendLine(" xmlns:o=\"urn:schemas-microsoft-com:office:office\"");
        sb.AppendLine(" xmlns:x=\"urn:schemas-microsoft-com:office:excel\"");
        sb.AppendLine(" xmlns:ss=\"urn:schemas-microsoft-com:office:spreadsheet\">");

        // Styles
        sb.AppendLine("  <Styles>");
        sb.AppendLine("    <Style ss:ID=\"Default\" ss:Name=\"Normal\"><Font ss:FontName=\"Segoe UI\" ss:Size=\"10\"/></Style>");
        sb.AppendLine("    <Style ss:ID=\"Header\"><Font ss:FontName=\"Segoe UI\" ss:Size=\"11\" ss:Bold=\"1\" ss:Color=\"#FFFFFF\"/><Interior ss:Color=\"#0F172A\" ss:Pattern=\"Solid\"/></Style>");
        sb.AppendLine("    <Style ss:ID=\"Crit\"><Font ss:FontName=\"Segoe UI\" ss:Bold=\"1\" ss:Color=\"#DC2626\"/></Style>");
        sb.AppendLine("    <Style ss:ID=\"High\"><Font ss:FontName=\"Segoe UI\" ss:Bold=\"1\" ss:Color=\"#EA580C\"/></Style>");
        sb.AppendLine("  </Styles>");

        // Sheet 1: Summary
        sb.AppendLine("  <Worksheet ss:Name=\"Executive Summary\">");
        sb.AppendLine("    <Table ss:DefaultColumnWidth=\"180\">");
        sb.AppendLine("      <Row ss:StyleID=\"Header\"><Cell><Data ss:Type=\"String\">Metric</Data></Cell><Cell><Data ss:Type=\"String\">Value</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">Target Hostname</Data></Cell><Cell><Data ss:Type=\"String\">{EscapeXml(report.TargetHostname)}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">Operating System</Data></Cell><Cell><Data ss:Type=\"String\">{EscapeXml(report.OperatingSystem)}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">Security Health Score</Data></Cell><Cell><Data ss:Type=\"Number\">{report.Scores.SecurityHealthScore:F1}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">Threat Score</Data></Cell><Cell><Data ss:Type=\"Number\">{report.Scores.ThreatScore:F1}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">Compliance Score</Data></Cell><Cell><Data ss:Type=\"Number\">{report.Scores.ComplianceScore:F1}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">AI Risk Forecast</Data></Cell><Cell><Data ss:Type=\"Number\">{report.Scores.AiRiskScore:F1}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">Insider Threat Score</Data></Cell><Cell><Data ss:Type=\"Number\">{report.Scores.InsiderThreatScore:F1}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">Ransomware Probability</Data></Cell><Cell><Data ss:Type=\"Number\">{report.Scores.RansomwareProbability:F1}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">Total Findings</Data></Cell><Cell><Data ss:Type=\"Number\">{report.Findings.Count}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">Critical Severity</Data></Cell><Cell><Data ss:Type=\"Number\">{report.CriticalFindingsCount}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">High Severity</Data></Cell><Cell><Data ss:Type=\"Number\">{report.HighFindingsCount}</Data></Cell></Row>");
        sb.AppendLine($"      <Row><Cell><Data ss:Type=\"String\">Evidence Hash Chain</Data></Cell><Cell><Data ss:Type=\"String\">{EscapeXml(report.GovProfile.DigitalEvidenceHashChain)}</Data></Cell></Row>");
        sb.AppendLine("    </Table>");
        sb.AppendLine("  </Worksheet>");

        // Sheet 2: Findings
        sb.AppendLine("  <Worksheet ss:Name=\"Audit Findings\">");
        sb.AppendLine("    <Table ss:DefaultColumnWidth=\"140\">");
        sb.AppendLine("      <Row ss:StyleID=\"Header\">");
        sb.AppendLine("        <Cell><Data ss:Type=\"String\">ID</Data></Cell>");
        sb.AppendLine("        <Cell><Data ss:Type=\"String\">Severity</Data></Cell>");
        sb.AppendLine("        <Cell><Data ss:Type=\"String\">CVSS</Data></Cell>");
        sb.AppendLine("        <Cell><Data ss:Type=\"String\">Category</Data></Cell>");
        sb.AppendLine("        <Cell><Data ss:Type=\"String\">Title</Data></Cell>");
        sb.AppendLine("        <Cell><Data ss:Type=\"String\">Description</Data></Cell>");
        sb.AppendLine("        <Cell><Data ss:Type=\"String\">Evidence</Data></Cell>");
        sb.AppendLine("        <Cell><Data ss:Type=\"String\">Remediation</Data></Cell>");
        sb.AppendLine("      </Row>");

        foreach (var f in report.Findings.OrderByDescending(f => f.Severity))
        {
            var style = f.Severity == AuditSeverity.Critical ? " ss:StyleID=\"Crit\"" : f.Severity == AuditSeverity.High ? " ss:StyleID=\"High\"" : "";
            sb.AppendLine("      <Row>");
            sb.AppendLine($"        <Cell><Data ss:Type=\"String\">{EscapeXml(f.Id)}</Data></Cell>");
            sb.AppendLine($"        <Cell{style}><Data ss:Type=\"String\">{f.Severity}</Data></Cell>");
            sb.AppendLine($"        <Cell><Data ss:Type=\"Number\">{f.CvssScore:F1}</Data></Cell>");
            sb.AppendLine($"        <Cell><Data ss:Type=\"String\">{f.Category}</Data></Cell>");
            sb.AppendLine($"        <Cell><Data ss:Type=\"String\">{EscapeXml(f.Title)}</Data></Cell>");
            sb.AppendLine($"        <Cell><Data ss:Type=\"String\">{EscapeXml(f.Description)}</Data></Cell>");
            sb.AppendLine($"        <Cell><Data ss:Type=\"String\">{EscapeXml(f.Evidence)}</Data></Cell>");
            sb.AppendLine($"        <Cell><Data ss:Type=\"String\">{EscapeXml(f.RemediationRecommendation)}</Data></Cell>");
            sb.AppendLine("      </Row>");
        }

        sb.AppendLine("    </Table>");
        sb.AppendLine("  </Worksheet>");

        // Sheet 3: DLP Findings
        if (report.DlpFindings.Count > 0)
        {
            sb.AppendLine("  <Worksheet ss:Name=\"Sensitive Data DLP\">");
            sb.AppendLine("    <Table ss:DefaultColumnWidth=\"160\">");
            sb.AppendLine("      <Row ss:StyleID=\"Header\">");
            sb.AppendLine("        <Cell><Data ss:Type=\"String\">Type</Data></Cell>");
            sb.AppendLine("        <Cell><Data ss:Type=\"String\">File Path</Data></Cell>");
            sb.AppendLine("        <Cell><Data ss:Type=\"String\">Line</Data></Cell>");
            sb.AppendLine("        <Cell><Data ss:Type=\"String\">Rule</Data></Cell>");
            sb.AppendLine("        <Cell><Data ss:Type=\"String\">Masked Match</Data></Cell>");
            sb.AppendLine("      </Row>");
            foreach (var d in report.DlpFindings)
            {
                sb.AppendLine("      <Row>");
                sb.AppendLine($"        <Cell><Data ss:Type=\"String\">{d.PatternType}</Data></Cell>");
                sb.AppendLine($"        <Cell><Data ss:Type=\"String\">{EscapeXml(d.FilePath)}</Data></Cell>");
                sb.AppendLine($"        <Cell><Data ss:Type=\"Number\">{d.LineNumber}</Data></Cell>");
                sb.AppendLine($"        <Cell><Data ss:Type=\"String\">{EscapeXml(d.RuleTriggered)}</Data></Cell>");
                sb.AppendLine($"        <Cell><Data ss:Type=\"String\">{EscapeXml(d.MaskedSnippet)}</Data></Cell>");
                sb.AppendLine("      </Row>");
            }
            sb.AppendLine("    </Table>");
            sb.AppendLine("  </Worksheet>");
        }

        sb.AppendLine("</Workbook>");
        return Task.FromResult(Encoding.UTF8.GetBytes(sb.ToString()));
    }

    public async Task ExportToFileAsync(AuditReport report, string outputPath, CancellationToken cancellationToken = default)
    {
        var bytes = await GenerateReportBytesAsync(report, cancellationToken);
        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
        await File.WriteAllBytesAsync(outputPath, bytes, cancellationToken);
    }

    private static string EscapeXml(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return WebUtility.HtmlEncode(value);
    }
}

public class CertInReportGenerator
{
    public string GenerateCertInAnnexure1(AuditReport report)
    {
        var sb = new StringBuilder();
        var incId = $"CERTIN-INC-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString("N")[..4].ToUpper()}";

        sb.AppendLine("================================================================================");
        sb.AppendLine("INDIAN COMPUTER EMERGENCY RESPONSE TEAM (CERT-In)");
        sb.AppendLine("CYBER SECURITY INCIDENT REPORTING FORM (ANNEXURE-I)");
        sb.AppendLine("Reported pursuant to Section 70B(6) of IT Act, 2000 & CERT-In Directions 2022");
        sb.AppendLine("================================================================================\n");

        sb.AppendLine($"1. Incident Reference ID:        {incId}");
        sb.AppendLine($"2. Date & Time of Detection:     {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"3. Reporting Organization:       {report.GovProfile.OrganizationType} ({report.GovProfile.DepartmentName})");
        sb.AppendLine($"4. Project / Asset Title:        {report.GovProfile.ProjectName}");
        sb.AppendLine($"5. Asset Classification:         {report.GovProfile.ClassificationLevel}");
        sb.AppendLine($"6. Affected Workstation / Host:  {report.TargetHostname} ({report.OperatingSystem})");
        sb.AppendLine($"7. Security Health Score:        {report.Scores.SecurityHealthScore:F1}/100");
        sb.AppendLine($"8. Incident Classification:      Configuration Drift / Vulnerability Exposure / Anti-Forensics");
        sb.AppendLine($"9. Critical Findings Count:      {report.CriticalFindingsCount}\n");

        sb.AppendLine("10. Summary Description of Discovered Threat Vectors:");
        foreach (var f in report.Findings.Where(f => f.Severity >= AuditSeverity.High).Take(5))
        {
            sb.AppendLine($"   * [{f.Severity}] {f.Title}");
            sb.AppendLine($"     Evidence: {f.Evidence}");
            sb.AppendLine($"     Remediation: {f.RemediationRecommendation}\n");
        }

        sb.AppendLine("11. Actions Taken & Containment Status:");
        sb.AppendLine("   * Automated endpoint audit executed.");
        sb.AppendLine("   * Remediation scripts compiled for network hardening and LSASS protection.");
        sb.AppendLine($"   * Digital evidence sealed with SHA256 chain of custody: {report.GovProfile.DigitalEvidenceHashChain}\n");

        sb.AppendLine("12. Contact Information:");
        sb.AppendLine("   * Designated CISO / Auditor:   ciso@organization.res.in");
        sb.AppendLine("   * Contact Phone:               +91-11-2436-XXXX (Institutional SOC Desk)");
        sb.AppendLine("================================================================================");

        return sb.ToString();
    }
}
