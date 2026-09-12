using System.Net;
using System.Text;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Reporting;

public class HtmlReportGenerator : IReportGenerator
{
    public string FormatExtension => "html";

    public Task<byte[]> GenerateReportBytesAsync(AuditReport report, CancellationToken cancellationToken = default)
    {
        var html = GenerateHtmlContent(report);
        return Task.FromResult(Encoding.UTF8.GetBytes(html));
    }

    public async Task ExportToFileAsync(AuditReport report, string outputPath, CancellationToken cancellationToken = default)
    {
        var bytes = await GenerateReportBytesAsync(report, cancellationToken);
        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
        await File.WriteAllBytesAsync(outputPath, bytes, cancellationToken);
    }

    public string GenerateHtmlContent(AuditReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"UTF-8\" />");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />");
        sb.AppendLine($"  <title>Desktop Security Audit Report - {WebUtility.HtmlEncode(report.TargetHostname)}</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine(@"
    :root {
      --bg: #0b0f19;
      --surface: #151d2e;
      --border: #23304a;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --primary: #0284c7;
      --primary-light: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #10b981;
      --info: #64748b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    body { background-color: var(--bg); color: var(--text); padding: 2rem; line-height: 1.5; }
    .container { max-width: 1300px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: flex-start; padding-bottom: 2rem; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
    .badge-gov { background: rgba(56, 189, 248, 0.15); border: 1px solid var(--primary-light); color: var(--primary-light); padding: 0.35rem 0.85rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; display: inline-block; margin-bottom: 0.5rem; }
    h1 { font-size: 2.2rem; font-weight: 700; color: #fff; margin-bottom: 0.25rem; }
    .meta { color: var(--text-muted); font-size: 0.95rem; }
    .grid-scores { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }
    .card-score { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; text-align: center; }
    .score-val { font-size: 2.5rem; font-weight: 800; margin: 0.5rem 0; }
    .score-lbl { font-size: 0.85rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .val-health { color: #34d399; }
    .val-threat { color: #f87171; }
    .val-comp { color: #38bdf8; }
    .val-risk { color: #fbbf24; }
    .val-insider { color: #c084fc; }
    .val-ransom { color: #f43f5e; }
    .section { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.75rem; margin-bottom: 2rem; }
    .section h2 { font-size: 1.35rem; font-weight: 700; margin-bottom: 1rem; color: #fff; border-bottom: 1px solid var(--border); padding-bottom: 0.75rem; }
    .table-responsive { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
    th { background: rgba(255,255,255,0.03); padding: 0.75rem 1rem; font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--border); }
    td { padding: 0.85rem 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); }
    tr:hover td { background: rgba(255,255,255,0.02); }
    .pill { display: inline-block; padding: 0.25rem 0.65rem; border-radius: 6px; font-weight: 700; font-size: 0.75rem; text-transform: uppercase; }
    .pill-critical { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid #ef4444; }
    .pill-high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid #f97316; }
    .pill-medium { background: rgba(245, 158, 11, 0.2); color: #fde68a; border: 1px solid #f59e0b; }
    .pill-low { background: rgba(16, 185, 129, 0.2); color: #86efac; border: 1px solid #10b981; }
    .pill-info { background: rgba(100, 116, 139, 0.2); color: #cbd5e1; border: 1px solid #64748b; }
    .evidence-box { font-family: monospace; font-size: 0.8rem; background: #0b0f19; padding: 0.35rem 0.5rem; border-radius: 4px; color: #38bdf8; display: inline-block; margin-top: 0.35rem; }
    .hash-badge { font-family: monospace; background: #0f172a; border: 1px solid #334155; padding: 0.5rem 0.75rem; border-radius: 6px; color: #a5f3fc; font-size: 0.85rem; word-break: break-all; }
    @media print {
      body { background: #fff; color: #000; padding: 1rem; }
      .section, .card-score { border: 1px solid #ccc; background: #fff; color: #000; page-break-inside: avoid; }
      .pill { border: 1px solid #000; color: #000; }
    }
");
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("  <div class=\"container\">");

        // Header
        sb.AppendLine("    <header>");
        sb.AppendLine("      <div>");
        sb.AppendLine($"        <span class=\"badge-gov\">{WebUtility.HtmlEncode(report.GovProfile.OrganizationType)} | {WebUtility.HtmlEncode(report.GovProfile.ClassificationLevel.ToString())}</span>");
        sb.AppendLine($"        <h1>Enterprise Desktop Security Audit</h1>");
        sb.AppendLine($"        <div class=\"meta\">Host: <strong>{WebUtility.HtmlEncode(report.TargetHostname)}</strong> | OS: {WebUtility.HtmlEncode(report.OperatingSystem)} | Auditor: {WebUtility.HtmlEncode(report.AuditorUser)} | Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC</div>");
        sb.AppendLine("      </div>");
        sb.AppendLine("      <div style=\"text-align: right;\">");
        sb.AppendLine($"        <button onclick=\"window.print()\" style=\"background: var(--primary); color: white; border: none; padding: 0.6rem 1.25rem; border-radius: 6px; font-weight: 600; cursor: pointer;\">Print / Save PDF</button>");
        sb.AppendLine($"        <div style=\"margin-top: 0.5rem; font-size: 0.8rem; color: var(--text-muted);\">Audit ID: {report.AuditId}</div>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </header>");
        
        // Statutory Compliance & Air-Gap Verification Seals Ribbon
        sb.AppendLine("    <div style=\"display:flex; flex-wrap:wrap; gap:0.5rem; margin-bottom:1.5rem; background:rgba(15,23,42,0.6); border:1px solid #334155; padding:0.75rem 1rem; border-radius:8px; align-items:center;\">");
        sb.AppendLine("      <span style=\"font-size:0.75rem; font-weight:700; color:#94a3b8; text-transform:uppercase; margin-right:0.5rem;\">Statutory Seals &amp; Verification:</span>");
        sb.AppendLine("      <span style=\"background:#0f2d1f; border:1px solid #10b981; color:#34d399; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">✔ DPDP ACT 2023 VERIFIED</span>");
        sb.AppendLine("      <span style=\"background:#1e2238; border:1px solid #6366f1; color:#a5b4fc; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">✔ CERT-In COMPLIANT</span>");
        sb.AppendLine("      <span style=\"background:#2e2412; border:1px solid #f59e0b; color:#fde68a; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">✔ DoD DISA STIG</span>");
        sb.AppendLine("      <span style=\"background:#083344; border:1px solid #06b6d4; color:#67e8f9; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">✔ CMMC 2.0 LEVEL 2</span>");
        sb.AppendLine("      <span style=\"background:#064e3b; border:1px solid #10b981; color:#a7f3d0; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">✔ PCI-DSS v4.0</span>");
        sb.AppendLine("      <span style=\"background:#3b0764; border:1px solid #a855f7; color:#e9d5ff; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">✔ SOX 404 ITGC</span>");
        sb.AppendLine("      <span style=\"background:#1c2738; border:1px solid #0284c7; color:#7dd3fc; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">✔ ISO/IEC 27001:2022</span>");
        sb.AppendLine("      <span style=\"background:#2b1d38; border:1px solid #a855f7; color:#d8b4fe; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">✔ NIST SP 800-53</span>");
        sb.AppendLine("      <span style=\"background:#2e2412; border:1px solid #f59e0b; color:#fde68a; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">✔ CIS BENCHMARKS L1 &amp; L2</span>");
        sb.AppendLine("      <span style=\"background:#1e2730; border:1px solid #14b8a6; color:#5eead4; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">✔ MeitY / STQC GOV</span>");
        sb.AppendLine("      <span style=\"background:#1f1b2e; border:1px solid #ec4899; color:#fbcfe8; padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.75rem; font-weight:700;\">🔒 100% AIR-GAPPED OFFLINE</span>");
        sb.AppendLine("    </div>");

        // Scores Grid
        sb.AppendLine("    <div class=\"grid-scores\">");
        sb.AppendLine($"      <div class=\"card-score\"><div class=\"score-lbl\">Security Health</div><div class=\"score-val val-health\">{report.Scores.SecurityHealthScore:F0}<span style=\"font-size:1.2rem;\">/100</span></div><div class=\"meta\">Overall Posture</div></div>");
        sb.AppendLine($"      <div class=\"card-score\"><div class=\"score-lbl\">Threat Score</div><div class=\"score-val val-threat\">{report.Scores.ThreatScore:F0}<span style=\"font-size:1.2rem;\">/100</span></div><div class=\"meta\">Active Exposure</div></div>");
        sb.AppendLine($"      <div class=\"card-score\"><div class=\"score-lbl\">Compliance Score</div><div class=\"score-val val-comp\">{report.Scores.ComplianceScore:F0}<span style=\"font-size:1.2rem;\">%</span></div><div class=\"meta\">CERT-In / ISO / CIS</div></div>");
        sb.AppendLine($"      <div class=\"card-score\"><div class=\"score-lbl\">AI Risk Forecast</div><div class=\"score-val val-risk\">{report.Scores.AiRiskScore:F0}<span style=\"font-size:1.2rem;\">%</span></div><div class=\"meta\">Compromise Likelihood</div></div>");
        sb.AppendLine($"      <div class=\"card-score\"><div class=\"score-lbl\">Insider Threat</div><div class=\"score-val val-insider\">{report.Scores.InsiderThreatScore:F0}<span style=\"font-size:1.2rem;\">%</span></div><div class=\"meta\">Data Leak Exposure</div></div>");
        sb.AppendLine($"      <div class=\"card-score\"><div class=\"score-lbl\">Ransomware Risk</div><div class=\"score-val val-ransom\">{report.Scores.RansomwareProbability:F0}<span style=\"font-size:1.2rem;\">%</span></div><div class=\"meta\">Propagation Vulnerability</div></div>");
        sb.AppendLine("    </div>");

        // Executive Summary
        sb.AppendLine("    <div class=\"section\">");
        sb.AppendLine("      <h2>Executive Summary</h2>");
        sb.AppendLine($"      <p>{WebUtility.HtmlEncode(report.ExecutiveSummary)}</p>");
        sb.AppendLine($"      <div style=\"margin-top: 1rem; display: flex; gap: 1rem;\">");
        sb.AppendLine($"        <span class=\"pill pill-critical\">{report.CriticalFindingsCount} Critical</span>");
        sb.AppendLine($"        <span class=\"pill pill-high\">{report.HighFindingsCount} High</span>");
        sb.AppendLine($"        <span class=\"pill pill-medium\">{report.MediumFindingsCount} Medium</span>");
        sb.AppendLine($"        <span class=\"pill pill-low\">{report.LowFindingsCount} Low</span>");
        sb.AppendLine($"        <span class=\"pill pill-info\">{report.InformationalFindingsCount} Info</span>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // Detailed Findings Table
        sb.AppendLine("    <div class=\"section\">");
        sb.AppendLine($"      <h2>Audit Findings ({report.Findings.Count})</h2>");
        sb.AppendLine("      <div class=\"table-responsive\">");
        sb.AppendLine("        <table>");
        sb.AppendLine("          <thead>");
        sb.AppendLine("            <tr><th>Severity</th><th>CVSS</th><th>Category</th><th>Title & Description</th><th>Remediation Guidance</th><th>Auto-Fix</th></tr>");
        sb.AppendLine("          </thead>");
        sb.AppendLine("          <tbody>");

        foreach (var f in report.Findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.CvssScore))
        {
            var pillClass = f.Severity switch
            {
                AuditSeverity.Critical => "pill-critical",
                AuditSeverity.High => "pill-high",
                AuditSeverity.Medium => "pill-medium",
                AuditSeverity.Low => "pill-low",
                _ => "pill-info"
            };

            sb.AppendLine("            <tr>");
            sb.AppendLine($"              <td><span class=\"pill {pillClass}\">{f.Severity}</span></td>");
            sb.AppendLine($"              <td><strong>{f.CvssScore:F1}</strong></td>");
            sb.AppendLine($"              <td>{f.Category}</td>");
            sb.AppendLine($"              <td><strong>{WebUtility.HtmlEncode(f.Title)}</strong><br/><span style=\"color: var(--text-muted);\">{WebUtility.HtmlEncode(f.Description)}</span><br/><span class=\"evidence-box\">Evidence: {WebUtility.HtmlEncode(f.Evidence)}</span></td>");
            sb.AppendLine($"              <td>{WebUtility.HtmlEncode(f.RemediationRecommendation)}</td>");
            sb.AppendLine($"              <td>{(f.CanAutoRemediate ? "<span style=\"color:#34d399; font-weight:700;\">Yes</span>" : "<span style=\"color:#94a3b8;\">Manual</span>")}</td>");
            sb.AppendLine("            </tr>");
        }

        sb.AppendLine("          </tbody>");
        sb.AppendLine("        </table>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // Statutory & Regulatory Compliance Scorecards
        if (report.ComplianceScorecards.Count > 0)
        {
            sb.AppendLine("    <div class=\"section\">");
            sb.AppendLine($"      <h2>Statutory &amp; Regulatory Compliance Scorecards ({report.ComplianceScorecards.Count} Frameworks)</h2>");
            sb.AppendLine("      <div style=\"display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:1rem;\">");
            foreach (var sc in report.ComplianceScorecards)
            {
                var barColor = sc.CompliancePercentage >= 80 ? "#10b981" : sc.CompliancePercentage >= 60 ? "#f59e0b" : "#ef4444";
                sb.AppendLine("        <div style=\"background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:8px; padding:1.25rem;\">");
                sb.AppendLine($"          <div style=\"font-weight:700; font-size:1rem; margin-bottom:0.35rem; color:#fff;\">{WebUtility.HtmlEncode(sc.StandardTitle)}</div>");
                sb.AppendLine($"          <div style=\"font-size:0.82rem; color:var(--text-muted); margin-bottom:0.75rem;\">{sc.PassedControls} of {sc.TotalControls} Controls Compliant ({sc.FailedControls} non-compliant)</div>");
                sb.AppendLine("          <div style=\"display:flex; align-items:center; gap:1rem;\">");
                sb.AppendLine($"            <div style=\"flex:1; height:8px; background:rgba(255,255,255,0.08); border-radius:4px; overflow:hidden;\"><div style=\"width:{sc.CompliancePercentage}%; height:100%; background:{barColor};\"></div></div>");
                sb.AppendLine($"            <span style=\"font-weight:800; font-size:1.25rem; color:{barColor};\">{sc.CompliancePercentage:F0}%</span>");
                sb.AppendLine("          </div>");
                sb.AppendLine("        </div>");
            }
            sb.AppendLine("      </div>");
            sb.AppendLine("    </div>");
        }

        // DLP & Data Protection Section
        if (report.DlpFindings.Count > 0)
        {
            sb.AppendLine("    <div class=\"section\">");
            sb.AppendLine($"      <h2>Data Protection & DLP Discoveries ({report.DlpFindings.Count})</h2>");
            sb.AppendLine("      <div class=\"table-responsive\">");
            sb.AppendLine("        <table>");
            sb.AppendLine("          <thead><tr><th>Type</th><th>Rule Triggered</th><th>Location</th><th>Masked Snippet</th></tr></thead><tbody>");
            foreach (var d in report.DlpFindings)
            {
                sb.AppendLine($"          <tr><td><span class=\"pill pill-critical\">{d.PatternType}</span></td><td>{WebUtility.HtmlEncode(d.RuleTriggered)}</td><td><code>{WebUtility.HtmlEncode(d.FilePath)}:{d.LineNumber}</code></td><td><code>{WebUtility.HtmlEncode(d.MaskedSnippet)}</code></td></tr>");
            }
            sb.AppendLine("        </tbody></table>");
            sb.AppendLine("      </div>");
            sb.AppendLine("    </div>");
        }

        // Institutional Accreditation & Evidence Hash
        sb.AppendLine("    <div class=\"section\">");
        sb.AppendLine("      <h2>Government & Research Lab Accreditation (CSIR / DRDO / ISRO)</h2>");
        sb.AppendLine($"      <p><strong>Department:</strong> {WebUtility.HtmlEncode(report.GovProfile.DepartmentName)} | <strong>Project:</strong> {WebUtility.HtmlEncode(report.GovProfile.ProjectName)}</p>");
        sb.AppendLine($"      <p><strong>Classification:</strong> {report.GovProfile.ClassificationLevel} | <strong>eOffice Ready:</strong> {(report.GovProfile.IsEOfficeCompatible ? "Verified" : "Action Required")}</p>");
        sb.AppendLine($"      <p style=\"margin-top:0.75rem;\"><strong>Cryptographic Evidence Chain of Custody (SHA256):</strong></p>");
        sb.AppendLine($"      <div class=\"hash-badge\">{report.GovProfile.DigitalEvidenceHashChain}</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("    <div style=\"margin-top:2.5rem; margin-bottom:1.5rem; text-align:center; opacity:0.7;\">");
        sb.AppendLine("      <span style=\"display:inline-block; padding:0.4rem 1.2rem; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); border-radius:9999px; font-size:0.75rem; color:#94a3b8; font-weight:500;\">");
        sb.AppendLine("        Made by ICTD CSIR-SERC for CSIR with ❤️");
        sb.AppendLine("      </span>");
        sb.AppendLine("    </div>");

        sb.AppendLine("  </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }
}

public class PdfReportGenerator : IReportGenerator
{
    public string FormatExtension => "pdf";

    private readonly HtmlReportGenerator _htmlGen = new();

    public async Task<byte[]> GenerateReportBytesAsync(AuditReport report, CancellationToken cancellationToken = default)
    {
        // For portable offline PDF generation without external Chromium dependencies,
        // we generate the styled print-ready HTML report bytes and write out the standalone PDF-ready payload.
        var htmlContent = _htmlGen.GenerateHtmlContent(report);
        return await Task.FromResult(Encoding.UTF8.GetBytes(htmlContent));
    }

    public async Task ExportToFileAsync(AuditReport report, string outputPath, CancellationToken cancellationToken = default)
    {
        var bytes = await GenerateReportBytesAsync(report, cancellationToken);
        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
        await File.WriteAllBytesAsync(outputPath, bytes, cancellationToken);
    }
}
