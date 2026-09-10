using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using DesktopAuditTool.ThreatIntel.Engines;

namespace DesktopAuditTool.ThreatIntel;

public class AiThreatEngine : IAiThreatEngine
{
    private readonly ThreatDetectionEngine _threatDetection = new();
    private readonly UserBehaviorAnalytics _uba = new();
    private readonly EntityBehaviorAnalytics _ueba = new();
    private readonly AnomalyDetectionEngine _anomaly = new();
    private readonly ProcessIntelligenceEngine _processIntel = new();
    private readonly LogAnalyticsAi _logAi = new();
    private readonly ThreatHuntingAssistant _hunting = new();
    private readonly RansomwareEarlyWarning _ransomware = new();
    private readonly InsiderThreatDetector _insider = new();
    private readonly ThreatCorrelationEngine _correlation = new();
    private readonly PredictiveRiskEngine _predictive = new();
    private readonly ZeroDayDetector _zeroDay = new();
    private readonly VulnerabilityPrioritizer _prioritizer = new();
    private readonly SecurityKnowledgeGraphEngine _knowledgeGraph = new();
    private readonly IncidentInvestigator _investigator = new();
    private readonly LlmSecurityCopilot _copilot = new();
    private readonly ResearchLabAiEngine _researchAi = new();

    public async Task<AiSecurityScores> CalculateAiScoresAsync(AuditReport report, CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            var scores = new AiSecurityScores();

            // 1. Calculate Threat Score (0-100, lower is better)
            var critCount = report.Findings.Count(f => f.Severity == AuditSeverity.Critical);
            var highCount = report.Findings.Count(f => f.Severity == AuditSeverity.High);
            var medCount = report.Findings.Count(f => f.Severity == AuditSeverity.Medium);

            var threatScore = (critCount * 25.0) + (highCount * 12.0) + (medCount * 4.0);
            scores.ThreatScore = Math.Min(100.0, Math.Round(threatScore, 1));

            // 2. Calculate Security Health Score (0-100, higher is better)
            scores.SecurityHealthScore = Math.Max(10.0, Math.Round(100.0 - scores.ThreatScore, 1));

            // 3. Compliance Score
            if (report.ComplianceScorecards.Count > 0)
            {
                scores.ComplianceScore = Math.Round(report.ComplianceScorecards.Average(s => s.CompliancePercentage), 1);
            }
            else
            {
                scores.ComplianceScore = 90.0;
            }

            // 4. AI Risk Score (via predictive risk formula)
            scores.AiRiskScore = _predictive.ForecastCompromiseProbability(report, out _);

            // 5. Insider Threat Score
            scores.InsiderThreatScore = _insider.CalculateInsiderThreatScore(report, out _);

            // 6. Ransomware Probability Score
            scores.RansomwareProbability = _ransomware.CalculateRansomwareRiskProbability(report, out _);

            return scores;
        }, cancellationToken);
    }

    public async Task<List<AttackChain>> CorrelateAttackChainsAsync(AuditReport report, CancellationToken cancellationToken = default)
    {
        return await Task.Run(() => _correlation.CorrelateEvents(report), cancellationToken);
    }

    public async Task<SecurityKnowledgeGraph> BuildKnowledgeGraphAsync(AuditReport report, CancellationToken cancellationToken = default)
    {
        return await Task.Run(() => _knowledgeGraph.BuildGraph(report), cancellationToken);
    }

    public async Task<string> QueryAiCopilotAsync(string userPrompt, AuditReport currentReport, CancellationToken cancellationToken = default)
    {
        return await _copilot.AskCopilotAsync(userPrompt, currentReport, cancellationToken);
    }

    public async Task<string> GenerateExecutiveSummaryAsync(AuditReport report, CancellationToken cancellationToken = default)
    {
        return await Task.Run(() => _investigator.GenerateForensicInvestigationNarrative(report), cancellationToken);
    }

    public ProcessIntelligenceEngine ProcessIntelligence => _processIntel;
    public ThreatHuntingAssistant ThreatHunting => _hunting;
    public VulnerabilityPrioritizer VulnerabilityPrioritizer => _prioritizer;
    public ResearchLabAiEngine ResearchLabAi => _researchAi;
}
