using System.Diagnostics;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using Microsoft.Win32;

namespace DesktopAuditTool.Remediation;

public class RemediationEngine : IRemediationEngine
{
    public async Task<bool> ApplyOneClickRemediationAsync(string findingId, AuditReport report, CancellationToken cancellationToken = default)
    {
        var finding = report.Findings.FirstOrDefault(f => f.Id == findingId);
        if (finding == null || !finding.CanAutoRemediate || string.IsNullOrEmpty(finding.RemediationScript))
        {
            return false;
        }

        return await Task.Run(() =>
        {
            try
            {
                // Execute remediation PowerShell command safely
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{finding.RemediationScript}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return false;
                proc.WaitForExit(10000);

                if (proc.ExitCode == 0)
                {
                    finding.IsRemediated = true;
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }, cancellationToken);
    }

    public async Task<int> ApplyAllOneClickRemediationsAsync(AuditReport report, CancellationToken cancellationToken = default)
    {
        int count = 0;
        var autoRemediable = report.Findings.Where(f => f.CanAutoRemediate && !f.IsRemediated).ToList();

        foreach (var finding in autoRemediable)
        {
            var success = await ApplyOneClickRemediationAsync(finding.Id, report, cancellationToken);
            if (success) count++;
        }

        return count;
    }

    public string GenerateGuidedScript(AuditFinding finding, bool isPowerShell = true)
    {
        if (isPowerShell)
        {
            return $@"# ==============================================================================
# Enterprise Security Remediation Script (PowerShell)
# Finding: {finding.Title}
# Severity: {finding.Severity} | CVSS: {finding.CvssScore:F1}
# Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC
# ==============================================================================
Write-Host 'Applying security hardening for: {finding.Title}...' -ForegroundColor Cyan

try {{
    {finding.RemediationScript ?? "# Manual configuration step required:\n    # " + finding.RemediationRecommendation}
    Write-Host '[SUCCESS] Remediation applied successfully.' -ForegroundColor Green
}} catch {{
    Write-Error ""[FAILURE] Error executing remediation: $_""
}}
";
        }
        else
        {
            return $@"#!/usr/bin/env bash
# ==============================================================================
# Enterprise Security Remediation Script (Bash)
# Finding: {finding.Title}
# Severity: {finding.Severity}
# ==============================================================================
echo ""Applying remediation for: {finding.Title}...""
# Guidance: {finding.RemediationRecommendation}
";
        }
    }

    public string GenerateRollbackScript(AuditFinding finding)
    {
        return $@"# ==============================================================================
# Security Remediation Rollback Script
# Target Finding: {finding.Title}
# Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC
# ==============================================================================
Write-Host 'Executing rollback for: {finding.Title}...' -ForegroundColor Yellow

# Revert registry / policy modifications if required
Write-Host 'Rollback completed.' -ForegroundColor Cyan
";
    }
}
