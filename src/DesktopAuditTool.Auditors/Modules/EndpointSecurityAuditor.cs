using System.Diagnostics;
using System.ServiceProcess;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using Microsoft.Win32;

namespace DesktopAuditTool.Auditors.Modules;

public class EndpointSecurityAuditor : IAuditModule
{
    public string Name => "Endpoint Security Verification";
    public AuditCategory Category => AuditCategory.EndpointSecurity;
    public int Priority => 4;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();

        await Task.Run(() =>
        {
            var avDetected = false;
            var realTimeProtectionActive = false;
            var edrNames = new List<string>();

            // 1. Check Windows SecurityCenter2 AV status
            var sc2Wmi = SystemInfoHelper.QueryWmi("SELECT displayName, productState FROM AntiVirusProduct", "root\\SecurityCenter2");
            foreach (var av in sc2Wmi)
            {
                avDetected = true;
                var displayName = av.GetValueOrDefault("displayName", "Unknown AV");
                edrNames.Add(displayName);

                // productState is a hex/decimal bitmask
                if (int.TryParse(av.GetValueOrDefault("productState", "0"), out var state))
                {
                    // Bit 16 (0x10) usually indicates real-time protection enabled
                    var rtpOn = (state & 0x00001000) != 0 || (state & 0x00000010) != 0 || (state & 0x100000) != 0;
                    if (rtpOn) realTimeProtectionActive = true;
                }
            }

            // 2. Check Windows Defender via ROOT\Microsoft\Windows\Defender
            var defWmi = SystemInfoHelper.QueryWmi("SELECT AntispywareEnabled, RealTimeProtectionEnabled, SignatureVersion, AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus", "root\\Microsoft\\Windows\\Defender");
            if (defWmi.Count > 0)
            {
                avDetected = true;
                edrNames.Add("Microsoft Defender Antivirus");
                var rtp = defWmi[0].GetValueOrDefault("RealTimeProtectionEnabled", "False");
                if (rtp.Equals("True", StringComparison.OrdinalIgnoreCase))
                {
                    realTimeProtectionActive = true;
                }
            }

            // 3. Check Enterprise EDR / XDR services
            var enterpriseEdrServices = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "CSFalconService", "CrowdStrike Falcon Sensor" },
                { "SentinelAgent", "SentinelOne Endpoint Protection" },
                { "masvc", "Trellix (McAfee) Agent" },
                { "mfetp", "Trellix Endpoint Security" },
                { "cbdefense", "Carbon Black Cloud Sensor" },
                { "Sophos Endpoint Defense Service", "Sophos Endpoint Protection" },
                { "FortiShield", "FortiClient Endpoint Security" }
            };

            try
            {
                var services = ServiceController.GetServices();
                foreach (var svc in services)
                {
                    if (enterpriseEdrServices.TryGetValue(svc.ServiceName, out var edrName))
                    {
                        avDetected = true;
                        if (svc.Status == ServiceControllerStatus.Running)
                        {
                            realTimeProtectionActive = true;
                            edrNames.Add($"{edrName} (Running)");
                        }
                        else
                        {
                            edrNames.Add($"{edrName} (Stopped)");
                        }
                    }
                }
            }
            catch { }

            // Evaluate findings
            if (!avDetected)
            {
                findings.Add(new AuditFinding
                {
                    Title = "No Active Antivirus / EDR Solution Detected",
                    Description = "No supported endpoint protection (Defender, CrowdStrike, SentinelOne, Trellix, Carbon Black) was discovered active on this host.",
                    Category = AuditCategory.EndpointSecurity,
                    Severity = AuditSeverity.Critical,
                    CvssScore = 9.5,
                    MitreTechniqueId = "T1562.001",
                    MitreTactic = MitreTactic.DefenseEvasion,
                    Evidence = "AntiVirusProduct in SecurityCenter2 is empty and EDR services not found.",
                    RemediationRecommendation = "Deploy an enterprise approved EDR/AV solution immediately or re-enable Microsoft Defender.",
                    RemediationScript = "Set-MpPreference -DisableRealtimeMonitoring $false",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-05", "Antivirus & EDR Deployment", "Install and keep updated enterprise antivirus"),
                        new ComplianceMapping(ComplianceStandard.Iso27001, "A.12.2.1", "Controls against malware", "Detection, prevention, and recovery controls against malware"),
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 2.3.1.1", "Antivirus protection", "Real-time protection enabled")
                    ]
                });
            }
            else if (!realTimeProtectionActive)
            {
                findings.Add(new AuditFinding
                {
                    Title = "Antivirus Real-Time Protection Disabled",
                    Description = $"Antivirus product is installed ({string.Join(", ", edrNames.Distinct())}), but Real-Time Protection is inactive.",
                    Category = AuditCategory.EndpointSecurity,
                    Severity = AuditSeverity.High,
                    CvssScore = 8.5,
                    MitreTechniqueId = "T1562.001",
                    MitreTactic = MitreTactic.DefenseEvasion,
                    Evidence = "RealTimeProtectionEnabled is False",
                    RemediationRecommendation = "Enable Real-Time Protection in your antivirus settings.",
                    RemediationScript = "Set-MpPreference -DisableRealtimeMonitoring $false",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-05", "Real-Time Protection", "Ensure continuous real-time file scanning")
                    ]
                });
            }
            else
            {
                findings.Add(new AuditFinding
                {
                    Title = "Endpoint Protection Verified Active",
                    Description = $"Active EDR/AV detected: {string.Join(", ", edrNames.Distinct())} with Real-Time Protection verified.",
                    Category = AuditCategory.EndpointSecurity,
                    Severity = AuditSeverity.Informational,
                    CvssScore = 0.0,
                    Evidence = $"Active security engines: {string.Join(", ", edrNames.Distinct())}"
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
