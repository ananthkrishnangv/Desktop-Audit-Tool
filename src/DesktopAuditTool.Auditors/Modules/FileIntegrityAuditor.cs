using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Auditors.Modules;

public class FileIntegrityAuditor : IAuditModule
{
    public string Name => "File Integrity Monitoring (FIM)";
    public AuditCategory Category => AuditCategory.FileIntegrity;
    public int Priority => 12;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();
        var fimRecords = new List<FimRecord>();

        await Task.Run(() =>
        {
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var criticalFiles = new List<(string Path, string Description)>
            {
                (Path.Combine(winDir, @"System32\drivers\etc\hosts"), "System Hosts File (DNS Redirection target)"),
                (Path.Combine(winDir, @"System32\drivers\etc\networks"), "System Networks File"),
                (Path.Combine(winDir, @"System32\drivers\etc\protocol"), "System Protocol File"),
                (Path.Combine(winDir, @"System32\drivers\etc\services"), "System Services File")
            };

            foreach (var (filePath, desc) in criticalFiles)
            {
                if (!File.Exists(filePath)) continue;

                try
                {
                    var fileInfo = new FileInfo(filePath);
                    var hash = ComputeSha256(filePath);

                    var record = new FimRecord
                    {
                        FilePath = filePath,
                        CurrentSha256 = hash,
                        Status = FimStatus.VerifiedClean,
                        LastModified = fileInfo.LastWriteTimeUtc,
                        SizeBytes = fileInfo.Length,
                        Description = desc
                    };

                    // Check hosts file for suspicious redirection entries
                    if (filePath.EndsWith("hosts", StringComparison.OrdinalIgnoreCase))
                    {
                        var content = File.ReadAllText(filePath);
                        var lines = content.Split('\n')
                            .Select(l => l.Trim())
                            .Where(l => !l.StartsWith('#') && !string.IsNullOrWhiteSpace(l))
                            .ToList();

                        // If hosts has non-loopback entries redirecting security or antivirus domains
                        var suspiciousRedirects = lines.Where(l =>
                            l.Contains("microsoft.com", StringComparison.OrdinalIgnoreCase) ||
                            l.Contains("update", StringComparison.OrdinalIgnoreCase) ||
                            l.Contains("antivirus", StringComparison.OrdinalIgnoreCase) ||
                            l.Contains("kaspersky", StringComparison.OrdinalIgnoreCase) ||
                            l.Contains("symantec", StringComparison.OrdinalIgnoreCase)
                        ).ToList();

                        if (suspiciousRedirects.Count > 0)
                        {
                            record.Status = FimStatus.Modified;
                            findings.Add(new AuditFinding
                            {
                                Title = "Hosts File DNS Hijacking Detected",
                                Description = $"Hosts file contains suspicious domain overrides: {string.Join("; ", suspiciousRedirects)}. Malware uses this to block updates and security sites.",
                                Category = AuditCategory.FileIntegrity,
                                Severity = AuditSeverity.Critical,
                                CvssScore = 8.8,
                                MitreTechniqueId = "T1565.001",
                                MitreTactic = MitreTactic.Impact,
                                Evidence = $"Entries: {string.Join("; ", suspiciousRedirects)}",
                                RemediationRecommendation = "Restore original Windows hosts file and eliminate unauthorized DNS sinkholes.",
                                RemediationType = RemediationType.Manual,
                                ComplianceMappings = [
                                    new ComplianceMapping(ComplianceStandard.Nist80053, "SI-7", "Software, Firmware, and Information Integrity", "Enforce integrity of critical system configuration files")
                                ]
                            });
                        }
                    }

                    fimRecords.Add(record);
                }
                catch
                {
                    // File may be locked
                }
            }

            // Report baseline integrity status
            findings.Add(new AuditFinding
            {
                Title = $"FIM Baseline Verified: {fimRecords.Count} Critical Core Files Audited",
                Description = $"Cryptographic SHA256 integrity baseline computed for {fimRecords.Count} core OS configuration files.",
                Category = AuditCategory.FileIntegrity,
                Severity = AuditSeverity.Informational,
                CvssScore = 0.0,
                Evidence = $"Monitored files: {string.Join(", ", fimRecords.Select(r => Path.GetFileName(r.FilePath)))}"
            });
        }, cancellationToken);

        sw.Stop();
        var result = new AuditModuleResult
        {
            ModuleName = Name,
            Category = Category,
            Findings = findings,
            ExecutionDurationMs = sw.ElapsedMilliseconds
        };
        result.ExtraData["FimRecords"] = fimRecords;
        return result;
    }

    private static string ComputeSha256(string filePath)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch
        {
            return "ACCESS_DENIED";
        }
    }
}
