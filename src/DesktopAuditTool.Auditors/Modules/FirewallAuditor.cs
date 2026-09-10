using System.Diagnostics;
using DesktopAuditTool.Auditors.Helpers;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using Microsoft.Win32;

namespace DesktopAuditTool.Auditors.Modules;

public class FirewallAuditor : IAuditModule
{
    public string Name => "Firewall Security Audit";
    public AuditCategory Category => AuditCategory.Firewall;
    public int Priority => 5;

    public async Task<AuditModuleResult> AuditAsync(AuditContext context, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<AuditFinding>();

        await Task.Run(() =>
        {
            // Query firewall status via netsh or registry
            var netshOutput = SystemInfoHelper.RunShellCommand("netsh", "advfirewall show allprofiles state");
            var domainOff = netshOutput.Contains("Domain Profile Settings") && netshOutput.Contains("State                                 OFF");
            var privateOff = netshOutput.Contains("Private Profile Settings") && netshOutput.Contains("State                                 OFF");
            var publicOff = netshOutput.Contains("Public Profile Settings") && netshOutput.Contains("State                                 OFF");

            // Also check registry fallback
            var domainVal = SystemInfoHelper.GetRegistryValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall");
            var privateVal = SystemInfoHelper.GetRegistryValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall");
            var publicVal = SystemInfoHelper.GetRegistryValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall");

            bool isAnyFirewallOff = domainOff || privateOff || publicOff ||
                                   (domainVal != null && Convert.ToInt32(domainVal) == 0) ||
                                   (privateVal != null && Convert.ToInt32(privateVal) == 0) ||
                                   (publicVal != null && Convert.ToInt32(publicVal) == 0);

            if (isAnyFirewallOff)
            {
                var disabledProfiles = new List<string>();
                if (domainOff || (domainVal != null && Convert.ToInt32(domainVal) == 0)) disabledProfiles.Add("Domain");
                if (privateOff || (privateVal != null && Convert.ToInt32(privateVal) == 0)) disabledProfiles.Add("Private");
                if (publicOff || (publicVal != null && Convert.ToInt32(publicVal) == 0)) disabledProfiles.Add("Public");

                findings.Add(new AuditFinding
                {
                    Title = "Host Firewall Disabled on Active Profiles",
                    Description = $"Host firewall is turned off for profile(s): {string.Join(", ", disabledProfiles)}. Inbound traffic is unshielded.",
                    Category = AuditCategory.Firewall,
                    Severity = AuditSeverity.Critical,
                    CvssScore = 9.0,
                    MitreTechniqueId = "T1562.004",
                    MitreTactic = MitreTactic.DefenseEvasion,
                    Evidence = $"Disabled Profiles: {string.Join(", ", disabledProfiles)}",
                    RemediationRecommendation = "Turn on Windows Defender Firewall for all network profiles (Domain, Private, Public).",
                    RemediationScript = "netsh advfirewall set allprofiles state on",
                    RemediationType = RemediationType.Automatic,
                    CanAutoRemediate = true,
                    ComplianceMappings = [
                        new ComplianceMapping(ComplianceStandard.CertIn, "CI-06", "Host-based Firewall Enforcement", "Enable firewall on all network profiles"),
                        new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 9.1.1", "Ensure Windows Firewall is on for Domain, Private, Public", "All profiles state ON"),
                        new ComplianceMapping(ComplianceStandard.Nist80053, "SC-7", "Boundary Protection", "Enforce host boundary isolation")
                    ]
                });
            }
            else
            {
                findings.Add(new AuditFinding
                {
                    Title = "Host Firewall Active on All Profiles",
                    Description = "Windows Defender Firewall is verified active across Domain, Private, and Public network profiles.",
                    Category = AuditCategory.Firewall,
                    Severity = AuditSeverity.Informational,
                    CvssScore = 0.0,
                    Evidence = "Domain: ON, Private: ON, Public: ON"
                });
            }

            // Check for high-risk inbound open ports (e.g. 21, 23, 135, 139, 445, 3389)
            var activePorts = SystemInfoHelper.GetActiveListeningPorts();
            var riskyPorts = new Dictionary<int, string>
            {
                { 21, "FTP (Unencrypted File Transfer)" },
                { 23, "Telnet (Unencrypted Remote Shell)" },
                { 135, "RPC Endpoint Mapper (Lateral Movement target)" },
                { 139, "NetBIOS Session Service" },
                { 445, "SMB Direct (Ransomware / Worm propagation risk)" }
            };

            foreach (var kvp in riskyPorts)
            {
                if (activePorts.Contains(kvp.Key))
                {
                    findings.Add(new AuditFinding
                    {
                        Title = $"High-Risk Port {kvp.Key} Listening ({kvp.Value})",
                        Description = $"Host is actively listening on port {kvp.Key} ({kvp.Value}). Exposed services increase lateral movement attack surface.",
                        Category = AuditCategory.Firewall,
                        Severity = kvp.Key == 23 || kvp.Key == 21 ? AuditSeverity.High : AuditSeverity.Medium,
                        CvssScore = kvp.Key == 23 ? 7.5 : 6.0,
                        MitreTechniqueId = "T1046",
                        MitreTactic = MitreTactic.Discovery,
                        Evidence = $"TCP Port {kvp.Key} is in LISTENING state",
                        RemediationRecommendation = $"Block port {kvp.Key} in firewall or disable the underlying service if not required.",
                        RemediationScript = $"New-NetFirewallRule -DisplayName 'Block-Port-{kvp.Key}' -Direction Inbound -LocalPort {kvp.Key} -Protocol TCP -Action Block",
                        RemediationType = RemediationType.Automatic,
                        CanAutoRemediate = true,
                        ComplianceMappings = [
                            new ComplianceMapping(ComplianceStandard.CisBenchmark, "CIS 9.2", "Firewall Rules", $"Restrict inbound access to port {kvp.Key}"),
                            new ComplianceMapping(ComplianceStandard.CertIn, "CI-08", "Network Exposure", "Close unused and legacy protocol ports")
                        ]
                    });
                }
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
