using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using DesktopAuditTool.Auditors;
using DesktopAuditTool.Core.Enums;
using DesktopAuditTool.Core.Interfaces;
using DesktopAuditTool.Core.Models;
using DesktopAuditTool.Remediation;
using DesktopAuditTool.Reporting;
using DesktopAuditTool.ThreatIntel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace DesktopAuditTool_WinUI;

public sealed partial class MainPage : Page
{
    private readonly AuditEngine _auditEngine = new();
    private readonly AiThreatEngine _threatEngine = new();
    private readonly RemediationEngine _remediationEngine = new();
    private readonly ReportManager _reportManager = new();

    private AuditReport? _currentReport;
    private List<AuditFinding> _allFindings = [];

    public MainPage()
    {
        InitializeComponent();
        Loaded += MainPage_Loaded;
    }

    private async void MainPage_Loaded(object sender, RoutedEventArgs e)
    {
        TxtSystemIdentity.Text = $"Host: {Environment.MachineName} | OS: {Environment.OSVersion.VersionString} | User: {Environment.UserName}";
        await ExecuteAuditAsync();
    }

    private async void BtnRunAudit_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteAuditAsync();
    }

    private async Task ExecuteAuditAsync()
    {
        BtnRunAudit.IsEnabled = false;
        AuditProgressRing.IsActive = true;
        StatusInfoBar.IsOpen = true;
        StatusInfoBar.Severity = InfoBarSeverity.Informational;
        StatusInfoBar.Title = "Auditing In Progress";
        StatusInfoBar.Message = "Running full 22-module security audit and AI threat analytics...";

        try
        {
            var ctx = new AuditContext
            {
                UserRole = RbacRole.Administrator,
                AssetClassification = AssetClassification.Restricted,
                Department = "Autonomous Systems & Strategic R&D",
                ProjectName = "High Performance Computing Baseline"
            };

            var report = await _auditEngine.RunFullAuditAsync(ctx);
            report.Scores = await _threatEngine.CalculateAiScoresAsync(report);
            report.CorrelatedAttackChains = await _threatEngine.CorrelateAttackChainsAsync(report);

            _currentReport = report;
            _allFindings = report.Findings;

            PopulateUi(report);

            StatusInfoBar.Severity = InfoBarSeverity.Success;
            StatusInfoBar.Title = "Audit Completed";
            StatusInfoBar.Message = $"Identified {report.Findings.Count} findings ({report.CriticalFindingsCount} Critical, {report.HighFindingsCount} High) in {report.TotalScanDurationSeconds:F1}s.";
        }
        catch (Exception ex)
        {
            StatusInfoBar.Severity = InfoBarSeverity.Error;
            StatusInfoBar.Title = "Audit Error";
            StatusInfoBar.Message = ex.Message;
        }
        finally
        {
            AuditProgressRing.IsActive = false;
            BtnRunAudit.IsEnabled = true;
        }
    }

    private void PopulateUi(AuditReport report)
    {
        // 1. Score Cards
        TxtScoreHealth.Text = $"{report.Scores.SecurityHealthScore:F0} / 100";
        TxtScoreThreat.Text = $"{report.Scores.ThreatScore:F0} / 100";
        TxtScoreCompliance.Text = $"{report.Scores.ComplianceScore:F0} %";
        TxtScoreAiRisk.Text = $"{report.Scores.AiRiskScore:F0} %";
        TxtScoreInsider.Text = $"{report.Scores.InsiderThreatScore:F0} %";
        TxtScoreRansomware.Text = $"{report.Scores.RansomwareProbability:F0} %";

        // 2. Executive Summary & Badges
        TxtExecutiveSummary.Text = report.ExecutiveSummary;
        BadgeCriticalCount.Text = $"{report.CriticalFindingsCount} Critical";
        BadgeHighCount.Text = $"{report.HighFindingsCount} High";
        BadgeMediumCount.Text = $"{report.MediumFindingsCount} Medium";
        BadgeLowCount.Text = $"{report.LowFindingsCount} Low";

        // 3. Top Findings (Dashboard)
        var top = report.Findings.Where(f => f.Severity >= AuditSeverity.High).Take(6).ToList();
        ListDashboardTopFindings.ItemsSource = top.Count > 0 ? top : report.Findings.Take(5).ToList();

        // 4. All Findings
        ApplyFindingsFilter();

        // 5. 22 Modules list
        ListModules.ItemsSource = report.ModuleExecutionTimesMs.ToList();

        // 6. Compliance scorecards
        ApplyComplianceFilter();

        // 7. DLP list
        ListDlp.ItemsSource = report.DlpFindings;

        // 8. Attack chains
        ListAttackChains.ItemsSource = report.CorrelatedAttackChains;

        // 9. Remediation list
        ListRemediation.ItemsSource = report.Findings.Where(f => f.CanAutoRemediate).ToList();
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is NavigationViewItem item && item.Tag is string tag)
        {
            ViewDashboard.Visibility = tag == "dashboard" ? Visibility.Visible : Visibility.Collapsed;
            ViewFindings.Visibility = tag == "findings" ? Visibility.Visible : Visibility.Collapsed;
            ViewModules.Visibility = tag == "modules" ? Visibility.Visible : Visibility.Collapsed;
            ViewCompliance.Visibility = tag == "compliance" ? Visibility.Visible : Visibility.Collapsed;
            ViewDlp.Visibility = tag == "dlp" ? Visibility.Visible : Visibility.Collapsed;
            ViewThreats.Visibility = tag == "threats" ? Visibility.Visible : Visibility.Collapsed;
            ViewRemediation.Visibility = tag == "remediation" ? Visibility.Visible : Visibility.Collapsed;
            ViewCopilot.Visibility = tag == "copilot" ? Visibility.Visible : Visibility.Collapsed;
            ViewExports.Visibility = tag == "exports" ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private void TxtSearchFindings_TextChanged(object sender, TextChangedEventArgs e)
    {
        ApplyFindingsFilter();
    }

    private void CmbSeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ApplyFindingsFilter();
    }

    private void ApplyFindingsFilter()
    {
        if (_allFindings == null) return;
        var search = TxtSearchFindings?.Text?.Trim().ToLowerInvariant() ?? "";
        var filterIndex = CmbSeverityFilter?.SelectedIndex ?? 0;

        var filtered = _allFindings.Where(f =>
        {
            var matchesSearch = string.IsNullOrEmpty(search) ||
                                f.Title.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                                f.Description.Contains(search, StringComparison.OrdinalIgnoreCase);

            var matchesSeverity = filterIndex switch
            {
                1 => f.Severity == AuditSeverity.Critical,
                2 => f.Severity == AuditSeverity.High,
                3 => f.Severity == AuditSeverity.Medium,
                4 => f.Severity == AuditSeverity.Low,
                _ => true
            };

            return matchesSearch && matchesSeverity;
        }).ToList();

        if (ListAllFindings != null)
        {
            ListAllFindings.ItemsSource = filtered;
        }
    }

    private void CmbComplianceProfile_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ApplyComplianceFilter();
    }

    private void ApplyComplianceFilter()
    {
        if (_currentReport == null || ListCompliance == null) return;

        var selectedIndex = CmbComplianceProfile?.SelectedIndex ?? 0;
        var scorecards = _currentReport.ComplianceScorecards;

        ListCompliance.ItemsSource = selectedIndex switch
        {
            1 => scorecards.Where(s => s.Profile == ComplianceProfile.IndianSovereign).ToList(),
            2 => scorecards.Where(s => s.Profile == ComplianceProfile.UsDefense).ToList(),
            3 => scorecards.Where(s => s.Profile == ComplianceProfile.UsFinancial).ToList(),
            4 => scorecards.Where(s => s.Profile == ComplianceProfile.GlobalEnterprise).ToList(),
            _ => scorecards
        };
    }

    private async void BtnFixSingle_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string findingId && _currentReport != null)
        {
            btn.IsEnabled = false;
            var success = await _remediationEngine.ApplyOneClickRemediationAsync(findingId, _currentReport);
            StatusInfoBar.IsOpen = true;
            StatusInfoBar.Severity = success ? InfoBarSeverity.Success : InfoBarSeverity.Warning;
            StatusInfoBar.Title = success ? "Remediation Applied" : "Remediation Notice";
            StatusInfoBar.Message = success ? "Security hardening command executed successfully." : "Automated remediation requires manual intervention.";
            await ExecuteAuditAsync();
        }
    }

    private async void BtnRemediateAll_Click(object sender, RoutedEventArgs e)
    {
        if (_currentReport == null) return;
        StatusInfoBar.IsOpen = true;
        StatusInfoBar.Severity = InfoBarSeverity.Informational;
        StatusInfoBar.Title = "Remediating";
        StatusInfoBar.Message = "Applying all one-click remediations...";

        var count = await _remediationEngine.ApplyAllOneClickRemediationsAsync(_currentReport);
        StatusInfoBar.Severity = InfoBarSeverity.Success;
        StatusInfoBar.Title = "Remediation Complete";
        StatusInfoBar.Message = $"Applied {count} automated remediation hardening actions.";
        await ExecuteAuditAsync();
    }

    private async void BtnAskCopilot_Click(object sender, RoutedEventArgs e)
    {
        await SendCopilotQueryAsync();
    }

    private async void TxtCopilotInput_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Enter)
        {
            await SendCopilotQueryAsync();
        }
    }

    private async Task SendCopilotQueryAsync()
    {
        var prompt = TxtCopilotInput.Text.Trim();
        if (string.IsNullOrEmpty(prompt) || _currentReport == null) return;

        TxtCopilotInput.Text = "";
        TxtCopilotChatHistory.Text += $"\n\nUser: {prompt}\n...";
        CopilotScroll.ChangeView(null, CopilotScroll.ScrollableHeight, null);

        var reply = await _threatEngine.QueryAiCopilotAsync(prompt, _currentReport);
        TxtCopilotChatHistory.Text = TxtCopilotChatHistory.Text.TrimEnd('.', '\n', ' ') + $"\n\nCopilot:\n{reply}";
        CopilotScroll.ChangeView(null, CopilotScroll.ScrollableHeight, null);
    }

    private async void BtnExportHtml_Click(object sender, RoutedEventArgs e)
    {
        await ExportReportAsync("html");
    }

    private async void BtnExportPdf_Click(object sender, RoutedEventArgs e)
    {
        await ExportReportAsync("pdf.html");
    }

    private async void BtnExportExcel_Click(object sender, RoutedEventArgs e)
    {
        await ExportReportAsync("xls");
    }

    private async void BtnExportCsv_Click(object sender, RoutedEventArgs e)
    {
        await ExportReportAsync("csv");
    }

    private async void BtnExportJson_Click(object sender, RoutedEventArgs e)
    {
        await ExportReportAsync("json");
    }

    private async void BtnExportCertIn_Click(object sender, RoutedEventArgs e)
    {
        await ExportReportAsync("txt");
    }

    private async Task ExportReportAsync(string ext)
    {
        if (_currentReport == null) return;
        var dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "reports");
        var exported = await _reportManager.ExportAllFormatsAsync(_currentReport, dir);
        StatusInfoBar.IsOpen = true;
        StatusInfoBar.Severity = InfoBarSeverity.Success;
        StatusInfoBar.Title = "Reports Exported";
        StatusInfoBar.Message = $"Successfully exported all official reports to: {dir}";
    }

    private void BtnToggleFullScreen_Click(object sender, RoutedEventArgs e)
    {
        App.MainWindowInstance?.ToggleFullScreen();
    }
}
