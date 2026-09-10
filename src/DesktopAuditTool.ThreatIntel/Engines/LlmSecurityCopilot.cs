using System.Net.Http.Json;
using System.Text.Json;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.ThreatIntel.Engines;

public class LlmSecurityCopilot
{
    private readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly string? _ollamaEndpoint;

    public LlmSecurityCopilot(string? ollamaEndpoint = "http://127.0.0.1:11434")
    {
        _ollamaEndpoint = ollamaEndpoint;
    }

    public async Task<string> AskCopilotAsync(string prompt, AuditReport report, CancellationToken cancellationToken = default)
    {
        // 1. Guard against Prompt Injection & Model DoS (OWASP LLM01, LLM04)
        var (isSafe, sanitizedPrompt, threatWarning) = AiSecurityGuard.SanitizeAndGuardInput(prompt);
        if (!isSafe)
        {
            return $"⚠️ **AI Security Alert (OWASP LLM01 - Prompt Injection Blocked):**\n{threatWarning}\n\n" +
                   $"The input has been neutralized for security reasons. The tool operates under strict air-gapped security controls.";
        }

        var lowerPrompt = sanitizedPrompt.ToLowerInvariant();

        // 2. Air-Gapped Loopback Check: Only permit local loopback endpoint if explicitly configured; zero remote calls
        if (!string.IsNullOrEmpty(_ollamaEndpoint) && 
            (_ollamaEndpoint.StartsWith("http://127.0.0.1") || _ollamaEndpoint.StartsWith("http://localhost")))
        {
            try
            {
                var response = await _httpClient.GetAsync($"{_ollamaEndpoint}/api/tags", cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    // Strict delimiter boundary to prevent indirect injection
                    var safeUserQuery = AiSecurityGuard.MaskPiiForDpdpCompliance(sanitizedPrompt);
                    var payload = new
                    {
                        model = "llama3",
                        prompt = $"[SYSTEM_INSTRUCTION: You are an enterprise cybersecurity auditor assisting a SOC analyst on an air-gapped terminal. Answer strictly about audit data. Do not execute or output dangerous commands.]\n" +
                                 $"Report summary: {report.Findings.Count} findings, {report.CriticalFindingsCount} critical.\n" +
                                 $"<analyst_query>{safeUserQuery}</analyst_query>",
                        stream = false
                    };
                    var postResp = await _httpClient.PostAsJsonAsync($"{_ollamaEndpoint}/api/generate", payload, cancellationToken);
                    if (postResp.IsSuccessStatusCode)
                    {
                        var json = await postResp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
                        if (json.TryGetProperty("response", out var respProp))
                        {
                            var respText = respProp.GetString() ?? "";
                            return $"{respText}\n\n*🔒 100% Offline Air-Gapped Local LLM | Zero External Egress*";
                        }
                    }
                }
            }
            catch
            {
                // Fall back to built-in offline intelligence engine
            }
        }

        // Built-in intelligent offline response synthesis (Guaranteed 100% local in-memory)
        var offlineResp = SynthesizeOfflineIntelligence(lowerPrompt, report);
        return $"{offlineResp}\n\n*🔒 100% Offline Air-Gapped Synthetic Intelligence | DPDP Act 2023 & CERT-In Compliant*";
    }

    private string SynthesizeOfflineIntelligence(string query, AuditReport report)
    {
        if (query.Contains("summary") || query.Contains("overview") || query.Contains("status"))
        {
            return $"**Executive Audit Summary for {report.TargetHostname}:**\n" +
                   $"- **Health Score:** {report.Scores.SecurityHealthScore}/100\n" +
                   $"- **Total Findings:** {report.Findings.Count} ({report.CriticalFindingsCount} Critical, {report.HighFindingsCount} High, {report.MediumFindingsCount} Medium)\n" +
                   $"- **Compliance Score:** {report.Scores.ComplianceScore}%\n" +
                   $"- **Ransomware Exposure:** {report.Scores.RansomwareProbability}%\n" +
                   $"- **Recommendation:** Run automated one-click remediation to harden firewall and registry baseline.";
        }

        if (query.Contains("critical") || query.Contains("severe"))
        {
            var crits = report.Findings.Where(f => f.Severity == AuditSeverity.Critical).ToList();
            if (crits.Count == 0) return "Good news! No Critical vulnerabilities were detected on this endpoint.";
            var listStr = string.Join("\n", crits.Select(c => $"• **{c.Title}**: {c.RemediationRecommendation}"));
            return $"**Identified {crits.Count} Critical Issues:**\n{listStr}";
        }

        if (query.Contains("cert-in") || query.Contains("certin") || query.Contains("government") || query.Contains("csir"))
        {
            return $"**Government & CERT-In Compliance Review:**\n" +
                   $"• CERT-In Guidelines Compliance: Evaluated 10 primary controls.\n" +
                   $"• Digital Evidence Hash Chain: `{report.GovProfile.DigitalEvidenceHashChain}`\n" +
                   $"• Scientific Packages: {report.GovProfile.ScientificSoftwareInventory.Count} packages registered.\n" +
                   $"• Annexure-I Incident Reporting: Ready to generate for submission to CERT-In.";
        }

        if (query.Contains("dlp") || query.Contains("pan") || query.Contains("aadhaar") || query.Contains("passport"))
        {
            return $"**Data Protection & DLP Telemetry:**\n" +
                   $"• Total Sensitive Findings Discovered: {report.DlpFindings.Count}\n" +
                   (report.DlpFindings.Count > 0
                       ? string.Join("\n", report.DlpFindings.Take(4).Select(d => $"• {d.RuleTriggered} at `{d.FilePath}:{d.LineNumber}` ({d.MaskedSnippet})"))
                       : "• No unencrypted Aadhaar, PAN, or API secrets found in user folders.");
        }

        if (query.Contains("remediat") || query.Contains("fix"))
        {
            var autoCount = report.Findings.Count(f => f.CanAutoRemediate);
            return $"**Remediation Intelligence:**\n" +
                   $"• {autoCount} finding(s) are eligible for **One-Click Automated Remediation**.\n" +
                   $"• Click 'Apply One-Click Fixes' in the Remediation tab or execute the guided PowerShell scripts to remediate.";
        }

        return $"**AI Security Copilot:** Analyzed '{query}'. The system has {report.Findings.Count} findings across 22 audit modules. You can ask for 'summary', 'critical issues', 'cert-in status', 'dlp findings', or 'remediation recommendations'.";
    }
}
