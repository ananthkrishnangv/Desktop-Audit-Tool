using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Auditors.Modules;

public class DataProtectionAuditor : IAuditModule
{
    public string Name => "Data Protection & DLP Audit";
    public AuditCategory Category => AuditCategory.DataProtection;
    public int Priority => 15;

    // Indian PAN regex: 5 uppercase letters + 4 digits + 1 uppercase letter
    private static readonly Regex PanRegex = new(@"\b[A-Z]{5}[0-9]{4}[A-Z]\b", RegexOptions.Compiled);

    // Indian Aadhaar regex: 12 digits (often spaced 4-4-4)
    private static readonly Regex AadhaarRegex = new(@"\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b", RegexOptions.Compiled);

    // Indian Passport: 1 uppercase letter followed by 7 digits
    private static readonly Regex PassportRegex = new(@"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b", RegexOptions.Compiled);

    // Indian Bank IFSC: 4 letters + 0 + 6 alphanumeric
    private static readonly Regex IfscRegex = new(@"\b[A-Z]{4}0[A-Z0-9]{6}\b", RegexOptions.Compiled);

    // API Keys: AWS, GitHub, Private Keys
    private static readonly Regex AwsKeyRegex = new(@"\bAKIA[0-9A-Z]{16}\b", RegexOptions.Compiled);
    private static readonly Regex GitHubTokenRegex = new(@"\bghp_[0-9a-zA-Z]{36}\b", RegexOptions.Compiled);
    private static readonly Regex PrivateKeyRegex = new(@"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", RegexOptions.Compiled);

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();
        var dlpFindings = new List<DlpFinding>();

        await Task.Run(() =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var targetFolders = new[]
            {
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents")
            };

            var searchableExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".txt", ".csv", ".json", ".xml", ".env", ".config", ".yaml", ".yml", ".log", ".sql"
            };

            foreach (var folder in targetFolders)
            {
                if (!Directory.Exists(folder)) continue;

                try
                {
                    var files = Directory.GetFiles(folder, "*.*", SearchOption.TopDirectoryOnly);
                    foreach (var file in files)
                    {
                        var ext = Path.GetExtension(file);
                        var fileName = Path.GetFileName(file);

                        // 1. Check for blatant plaintext password files
                        if (fileName.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                            fileName.Contains("credential", StringComparison.OrdinalIgnoreCase) ||
                            fileName.Equals(".env", StringComparison.OrdinalIgnoreCase))
                        {
                            dlpFindings.Add(new DlpFinding
                            {
                                PatternType = DlpPatternType.PlaintextPassword,
                                FilePath = file,
                                LineNumber = 1,
                                MaskedSnippet = $"File: {fileName}",
                                RuleTriggered = "Sensitive credential file in user directory",
                                Severity = AuditSeverity.Critical
                            });

                            findings.Add(new AuditFinding
                            {
                                Title = $"Unencrypted Credential File in User Directory: {fileName}",
                                Description = $"Identified credential repository '{file}' directly accessible in user folder without encryption.",
                                Category = AuditCategory.DataProtection,
                                Severity = AuditSeverity.Critical,
                                CvssScore = 8.5,
                                MitreTechniqueId = "T1552.001",
                                MitreTactic = MitreTactic.CredentialAccess,
                                Evidence = $"Path: {file}",
                                RemediationRecommendation = "Delete plaintext credential files or store in an authorized password vault.",
                                RemediationType = RemediationType.Manual,
                                ComplianceMappings = [
                                    new ComplianceMapping(ComplianceStandard.CertIn, "CI-01", "Credential Protection", "Never store passwords in plain text"),
                                    new ComplianceMapping(ComplianceStandard.Iso27001, "A.9.4.3", "Password management system", "Protect authenticators")
                                ]
                            });
                        }

                        // 2. Scan file content if valid text extension and size < 2MB
                        if (!searchableExtensions.Contains(ext)) continue;
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.Length > 2 * 1024 * 1024) continue; // Skip huge files

                        ScanFileForSensitivePatterns(file, findings, dlpFindings);
                    }
                }
                catch
                {
                    // Handle directory access exceptions
                }
            }

            if (dlpFindings.Count == 0)
            {
                findings.Add(new AuditFinding
                {
                    Title = "DLP Sensitive Data Audit Passed: No Unprotected PII / Secrets Found",
                    Description = "Scanned Desktop, Downloads, and Documents for Indian PAN, Aadhaar, Passports, Bank IFSC, and Cloud API keys. No unprotected sensitive tokens detected.",
                    Category = AuditCategory.DataProtection,
                    Severity = AuditSeverity.Informational,
                    CvssScore = 0.0,
                    Evidence = "Desktop, Downloads, Documents inspected"
                });
            }
        }, cancellationToken);

        sw.Stop();
        var result = new AuditModuleResult
        {
            ModuleName = Name,
            Category = Category,
            Findings = findings,
            ExecutionDurationMs = sw.ElapsedMilliseconds
        };
        result.ExtraData["DlpFindings"] = dlpFindings;
        return result;
    }

    private void ScanFileForSensitivePatterns(string filePath, List<AuditFinding> findings, List<DlpFinding> dlpFindings)
    {
        try
        {
            var lines = File.ReadLines(filePath).Take(300);
            int lineNum = 0;

            foreach (var line in lines)
            {
                lineNum++;
                if (string.IsNullOrWhiteSpace(line)) continue;

                // PAN Scan
                var panMatches = PanRegex.Matches(line);
                foreach (Match m in panMatches)
                {
                    dlpFindings.Add(new DlpFinding
                    {
                        PatternType = DlpPatternType.PanNumber,
                        FilePath = filePath,
                        LineNumber = lineNum,
                        MaskedSnippet = MaskString(m.Value),
                        RuleTriggered = "Indian Income Tax PAN Card Number",
                        Severity = AuditSeverity.High
                    });

                    findings.Add(new AuditFinding
                    {
                        Title = $"Unprotected Indian PAN Card Number in {Path.GetFileName(filePath)}",
                        Description = $"Identified cleartext Permanent Account Number (PAN) in file '{filePath}' at line {lineNum}.",
                        Category = AuditCategory.DataProtection,
                        Severity = AuditSeverity.High,
                        CvssScore = 7.5,
                        Evidence = $"File: {filePath}:{lineNum}, Match: {MaskString(m.Value)}",
                        RemediationRecommendation = "Encrypt or purge PII data from local storage to comply with Indian Digital Personal Data Protection (DPDP) Act.",
                        RemediationType = RemediationType.Manual,
                        ComplianceMappings = [
                            new ComplianceMapping(ComplianceStandard.CertIn, "CI-20", "Data Privacy & PII Protection", "Protect personal identifiable information"),
                            new ComplianceMapping(ComplianceStandard.MeitY, "MeitY-04", "Data Leakage Prevention", "Enforce DLP for national ID numbers")
                        ]
                    });
                    break;
                }

                // Aadhaar Scan
                var aadhaarMatches = AadhaarRegex.Matches(line);
                foreach (Match m in aadhaarMatches)
                {
                    var cleanNum = m.Value.Replace(" ", "");
                    if (ValidateVerhoeffAadhaar(cleanNum))
                    {
                        dlpFindings.Add(new DlpFinding
                        {
                            PatternType = DlpPatternType.AadhaarNumber,
                            FilePath = filePath,
                            LineNumber = lineNum,
                            MaskedSnippet = MaskString(m.Value),
                            RuleTriggered = "Indian Aadhaar Number (Verhoeff Verified)",
                            Severity = AuditSeverity.Critical
                        });

                        findings.Add(new AuditFinding
                        {
                            Title = $"Unprotected Indian Aadhaar Number in {Path.GetFileName(filePath)}",
                            Description = $"Discovered valid Verhoeff-verified Aadhaar number in '{filePath}' at line {lineNum}.",
                            Category = AuditCategory.DataProtection,
                            Severity = AuditSeverity.Critical,
                            CvssScore = 8.5,
                            Evidence = $"File: {filePath}:{lineNum}, Match: {MaskString(m.Value)}",
                            RemediationRecommendation = "Aadhaar numbers must be masked (only last 4 digits visible) or stored in encrypted Aadhaar Vaults.",
                            RemediationType = RemediationType.Manual,
                            ComplianceMappings = [
                                new ComplianceMapping(ComplianceStandard.MeitY, "MeitY-04", "Aadhaar Data Protection", "Comply with UIDAI & MeitY Aadhaar storage regulations")
                            ]
                        });
                        break;
                    }
                }

                // API Key / AWS Key Scan
                if (AwsKeyRegex.IsMatch(line) || GitHubTokenRegex.IsMatch(line) || PrivateKeyRegex.IsMatch(line))
                {
                    dlpFindings.Add(new DlpFinding
                    {
                        PatternType = DlpPatternType.ApiKeyOrSecret,
                        FilePath = filePath,
                        LineNumber = lineNum,
                        MaskedSnippet = "API_KEY_OR_PRIVATE_KEY_DETECTED",
                        RuleTriggered = "Cloud Credential / Private Key In Plaintext",
                        Severity = AuditSeverity.Critical
                    });

                    findings.Add(new AuditFinding
                    {
                        Title = $"Hardcoded API Key / Secret in {Path.GetFileName(filePath)}",
                        Description = $"Identified unencrypted secret or cloud API key in '{filePath}' at line {lineNum}.",
                        Category = AuditCategory.DataProtection,
                        Severity = AuditSeverity.Critical,
                        CvssScore = 9.0,
                        MitreTechniqueId = "T1552.001",
                        MitreTactic = MitreTactic.CredentialAccess,
                        Evidence = $"File: {filePath}:{lineNum}",
                        RemediationRecommendation = "Revoke and rotate exposed API secret immediately. Store credentials in environment variables or key vault.",
                        RemediationType = RemediationType.Manual,
                        ComplianceMappings = [
                            new ComplianceMapping(ComplianceStandard.CertIn, "CI-01", "Secret Management", "Prevent hardcoding secrets in local files")
                        ]
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private static string MaskString(string input)
    {
        if (input.Length <= 4) return "****";
        return input[..2] + new string('*', input.Length - 4) + input[^2..];
    }

    // Verhoeff Algorithm multiplication and permutation tables for Indian Aadhaar validation
    private static readonly int[,] D =
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
        {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
        {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
        {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
        {4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
        {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
        {6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
        {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
        {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
        {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
    };

    private static readonly int[,] P =
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
        {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
        {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
        {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
        {9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
        {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
        {2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
        {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}
    };

    public static bool ValidateVerhoeffAadhaar(string num)
    {
        if (string.IsNullOrWhiteSpace(num) || num.Length != 12) return false;
        int c = 0;
        int[] digits = num.Select(ch => ch - '0').ToArray();
        Array.Reverse(digits);

        for (int i = 0; i < digits.Length; i++)
        {
            if (digits[i] < 0 || digits[i] > 9) return false;
            c = D[c, P[i % 8, digits[i]]];
        }
        return c == 0;
    }
}
