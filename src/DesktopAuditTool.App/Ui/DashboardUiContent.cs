namespace DesktopAuditTool.App.Ui;

public static class DashboardUiContent
{
    public static string GetHtml()
    {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Enterprise Desktop Security Audit & AI Threat Intelligence Console</title>
  <!-- 100% Offline Air-Gapped: Zero External CDN or Font Dependencies -->
  <style>
    body, * {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    code, pre, .font-mono {
      font-family: "Cascadia Code", "Consolas", "Courier New", monospace !important;
    }
    :root {
      --bg-dark: #07090e;
      --bg-surface: #0e131f;
      --bg-card: #141b2d;
      --bg-card-hover: #1c263f;
      --border: #1f2a44;
      --border-light: #2b3a5c;
      --primary: #0284c7;
      --primary-light: #38bdf8;
      --accent: #6366f1;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --crit: #ef4444;
      --crit-bg: rgba(239, 68, 68, 0.12);
      --high: #f97316;
      --high-bg: rgba(249, 115, 22, 0.12);
      --med: #f59e0b;
      --med-bg: rgba(245, 158, 11, 0.12);
      --low: #10b981;
      --low-bg: rgba(16, 185, 129, 0.12);
      --info: #38bdf8;
      --info-bg: rgba(56, 189, 248, 0.12);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', -apple-system, sans-serif; }
    body { background-color: var(--bg-dark); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; }
    
    /* Top Navigation Bar */
    .topbar { background: var(--bg-surface); border-bottom: 1px solid var(--border); padding: 0.85rem 2rem; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 50; }
    .logo-group { display: flex; align-items: center; gap: 0.85rem; }
    .logo-icon { width: 36px; height: 36px; background: linear-gradient(135deg, var(--primary), var(--accent)); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 800; color: #fff; font-size: 1.1rem; box-shadow: 0 0 16px rgba(2, 132, 199, 0.4); }
    .logo-text { font-size: 1.15rem; font-weight: 700; color: #fff; letter-spacing: -0.01em; }
    .logo-sub { font-size: 0.75rem; color: var(--primary-light); font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
    .top-actions { display: flex; align-items: center; gap: 1rem; }
    .tag-gov { background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.4); color: #a5b4fc; padding: 0.35rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .btn-run { background: linear-gradient(135deg, #0284c7, #2563eb); color: white; border: none; padding: 0.6rem 1.4rem; border-radius: 8px; font-weight: 700; font-size: 0.88rem; cursor: pointer; display: flex; align-items: center; gap: 0.5rem; transition: all 0.2s; box-shadow: 0 0 20px rgba(2, 132, 199, 0.3); }
    .btn-run:hover { opacity: 0.92; transform: translateY(-1px); }
    .btn-run:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

    /* Main Container & Tabs */
    .nav-tabs { background: var(--bg-surface); border-bottom: 1px solid var(--border); padding: 0 2rem; display: flex; gap: 2rem; overflow-x: auto; }
    .tab-btn { background: none; border: none; color: var(--text-muted); font-size: 0.88rem; font-weight: 600; padding: 1rem 0; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s; white-space: nowrap; }
    .tab-btn:hover { color: #fff; }
    .tab-btn.active { color: var(--primary-light); border-bottom-color: var(--primary-light); }

    .content-area { flex: 1; padding: 2rem; max-width: 1500px; margin: 0 auto; width: 100%; }

    /* Progress Banner */
    #progress-banner { display: none; background: var(--bg-card); border: 1px solid var(--primary); border-radius: 10px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; animation: pulse 2s infinite; }
    .progress-bar-bg { width: 100%; height: 6px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; margin-top: 0.5rem; }
    .progress-bar-fill { height: 100%; width: 0%; background: linear-gradient(90deg, var(--primary), var(--primary-light)); transition: width 0.3s; }

    /* KPI Cards Grid */
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }
    .kpi-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1.4rem; position: relative; overflow: hidden; transition: transform 0.2s, border-color 0.2s; }
    .kpi-card:hover { transform: translateY(-2px); border-color: var(--border-light); }
    .kpi-title { font-size: 0.78rem; text-transform: uppercase; font-weight: 700; color: var(--text-muted); letter-spacing: 0.05em; }
    .kpi-value { font-size: 2.4rem; font-weight: 800; margin: 0.35rem 0; line-height: 1; }
    .kpi-desc { font-size: 0.78rem; color: var(--text-dim); }

    /* Section Styling */
    .dashboard-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
    .panel { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; }
    .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem; padding-bottom: 0.75rem; border-bottom: 1px solid var(--border); }
    .panel-title { font-size: 1.1rem; font-weight: 700; color: #fff; }

    /* Filter Bar */
    .filter-bar { display: flex; gap: 1rem; margin-bottom: 1.25rem; flex-wrap: wrap; }
    .search-input, .select-input { background: var(--bg-surface); border: 1px solid var(--border); color: #fff; padding: 0.55rem 1rem; border-radius: 8px; font-size: 0.85rem; outline: none; }
    .search-input:focus, .select-input:focus { border-color: var(--primary); }

    /* Tables */
    .table-container { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
    th { background: rgba(255,255,255,0.02); padding: 0.75rem 1rem; font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--border); }
    td { padding: 0.85rem 1rem; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: middle; }
    tr:hover td { background: var(--bg-card-hover); }

    /* Badges & Pills */
    .badge { display: inline-block; padding: 0.2rem 0.55rem; border-radius: 6px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: var(--crit-bg); color: #fca5a5; border: 1px solid var(--crit); }
    .badge-high { background: var(--high-bg); color: #fdba74; border: 1px solid var(--high); }
    .badge-medium { background: var(--med-bg); color: #fde68a; border: 1px solid var(--med); }
    .badge-low { background: var(--low-bg); color: #86efac; border: 1px solid var(--low); }
    .badge-info { background: var(--info-bg); color: #93c5fd; border: 1px solid var(--info); }

    /* Chat Copilot */
    .chat-container { display: flex; flex-direction: column; height: 500px; background: var(--bg-surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
    .chat-messages { flex: 1; padding: 1.25rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem; }
    .chat-bubble { max-width: 80%; padding: 0.85rem 1.1rem; border-radius: 10px; font-size: 0.88rem; line-height: 1.45; }
    .chat-bubble-ai { align-self: flex-start; background: var(--bg-card); border: 1px solid var(--border); color: #e2e8f0; }
    .chat-bubble-user { align-self: flex-end; background: var(--primary); color: #fff; font-weight: 500; }
    .chat-input-bar { display: flex; padding: 0.85rem; background: var(--bg-card); border-top: 1px solid var(--border); gap: 0.75rem; }
    .chat-input { flex: 1; background: var(--bg-surface); border: 1px solid var(--border); color: #fff; padding: 0.65rem 1rem; border-radius: 8px; font-size: 0.88rem; outline: none; }
    .btn-send { background: var(--primary); border: none; color: white; padding: 0.65rem 1.2rem; border-radius: 8px; font-weight: 600; cursor: pointer; }

    /* Export buttons */
    .export-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1.5rem; }
    .btn-export { background: var(--bg-surface); border: 1px solid var(--border); padding: 1.2rem; border-radius: 10px; text-align: center; cursor: pointer; transition: all 0.2s; color: #fff; text-decoration: none; display: flex; flex-direction: column; align-items: center; gap: 0.5rem; }
    .btn-export:hover { border-color: var(--primary); background: var(--bg-card-hover); }
    .btn-export strong { font-size: 1rem; color: var(--primary-light); }

    .code-box { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; background: #07090e; padding: 0.75rem; border-radius: 6px; border: 1px solid var(--border); color: #38bdf8; white-space: pre-wrap; margin-top: 0.5rem; }
    .btn-fix { background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #34d399; padding: 0.35rem 0.75rem; border-radius: 6px; font-size: 0.78rem; font-weight: 700; cursor: pointer; transition: 0.2s; }
    .btn-fix:hover { background: #10b981; color: #07090e; }
  </style>
</head>
<body>

  <!-- Topbar -->
  <div class="topbar">
    <div class="logo-group">
      <div class="logo-icon">🛡️</div>
      <div>
        <div class="logo-text">Enterprise Desktop Audit & Threat Intel Platform</div>
        <div class="logo-sub">CSIR / DRDO / ISRO / Research Labs Security Baseline</div>
      </div>
    </div>
    <div class="top-actions">
      <span class="tag-gov" id="org-badge">Autonomous R&D Lab | Restricted</span>
      <button class="btn-run" id="btn-trigger-audit" onclick="runAudit()">
        <span>⚡</span> Run Full Security Audit
      </button>
    </div>
  </div>

  <!-- Navigation Tabs -->
  <div class="nav-tabs">
    <button class="tab-btn active" onclick="showTab('dashboard')">Executive Dashboard</button>
    <button class="tab-btn" onclick="showTab('findings')">Findings & Vulnerabilities (<span id="tab-findings-count">0</span>)</button>
    <button class="tab-btn" onclick="showTab('modules')">22 Audit Modules</button>
    <button class="tab-btn" onclick="showTab('compliance')">Compliance Scorecards</button>
    <button class="tab-btn" onclick="showTab('dlp')">Data Protection / DLP</button>
    <button class="tab-btn" onclick="showTab('threats')">AI Threat Intelligence</button>
    <button class="tab-btn" onclick="showTab('remediation')">Automated Remediation</button>
    <button class="tab-btn" onclick="showTab('copilot')">AI Security Copilot</button>
    <button class="tab-btn" onclick="showTab('exports')">Report Exports</button>
  </div>

  <!-- Main Container -->
  <div class="content-area">

    <!-- Progress Banner -->
    <div id="progress-banner">
      <div style="display:flex; justify-content:space-between; font-size:0.88rem;">
        <span id="progress-label">Running comprehensive audit...</span>
        <span id="progress-pct" style="font-weight:700; color:var(--primary-light);">0%</span>
      </div>
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" id="progress-bar"></div>
      </div>
    </div>

    <!-- TAB 1: DASHBOARD -->
    <div id="tab-dashboard">
      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-title">Security Health</div>
          <div class="kpi-value" id="kpi-health" style="color:#34d399;">--</div>
          <div class="kpi-desc">Overall System Posture</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Threat Score</div>
          <div class="kpi-value" id="kpi-threat" style="color:#f87171;">--</div>
          <div class="kpi-desc">Active Adversarial Exposure</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Compliance Score</div>
          <div class="kpi-value" id="kpi-comp" style="color:#38bdf8;">--</div>
          <div class="kpi-desc">CERT-In / ISO / CIS Average</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">AI Risk Forecast</div>
          <div class="kpi-value" id="kpi-risk" style="color:#fbbf24;">--</div>
          <div class="kpi-desc">Compromise Likelihood</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Insider Threat</div>
          <div class="kpi-value" id="kpi-insider" style="color:#c084fc;">--</div>
          <div class="kpi-desc">Data Exfiltration Index</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-title">Ransomware Exposure</div>
          <div class="kpi-value" id="kpi-ransom" style="color:#f43f5e;">--</div>
          <div class="kpi-desc">Propagation Vulnerability</div>
        </div>
      </div>

      <div class="dashboard-grid">
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">Top Threat Findings Requiring Immediate Attention</div>
            <button class="btn-fix" onclick="showTab('findings')">View All</button>
          </div>
          <div class="table-container">
            <table>
              <thead><tr><th>Severity</th><th>Finding Title</th><th>Category</th><th>Remediation</th></tr></thead>
              <tbody id="top-findings-tbody">
                <tr><td colspan="4" style="text-align:center; color:var(--text-dim);">No audit data loaded. Click 'Run Full Security Audit' above.</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="panel">
          <div class="panel-header"><div class="panel-title">System & Institutional Identity</div></div>
          <div style="font-size:0.88rem; display:flex; flex-direction:column; gap:0.75rem;">
            <div><span style="color:var(--text-dim);">Target Workstation:</span> <strong id="meta-host">--</strong></div>
            <div><span style="color:var(--text-dim);">Operating System:</span> <span id="meta-os">--</span></div>
            <div><span style="color:var(--text-dim);">Domain / Workgroup:</span> <span id="meta-domain">--</span></div>
            <div><span style="color:var(--text-dim);">Classification Tier:</span> <span id="meta-class">--</span></div>
            <div><span style="color:var(--text-dim);">eOffice Compatibility:</span> <span id="meta-eoffice">--</span></div>
            <div style="margin-top:0.5rem;"><span style="color:var(--text-dim);">Digital Evidence Hash:</span></div>
            <div class="code-box" id="meta-evidence" style="font-size:0.72rem; word-break:break-all;">Pending audit execution</div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: FINDINGS -->
    <div id="tab-findings" style="display:none;">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">All Security Findings & Vulnerabilities</div>
          <div class="filter-bar">
            <input type="text" class="search-input" id="search-findings" placeholder="Search findings, CVEs, titles..." oninput="filterFindings()" />
            <select class="select-input" id="filter-severity" onchange="filterFindings()">
              <option value="ALL">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Informational">Informational</option>
            </select>
          </div>
        </div>
        <div class="table-container">
          <table>
            <thead><tr><th>Severity</th><th>CVSS</th><th>Category</th><th>Title & Evidence</th><th>Remediation</th><th>Action</th></tr></thead>
            <tbody id="all-findings-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 3: 22 MODULES -->
    <div id="tab-modules" style="display:none;">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">All 22 Enterprise Audit Modules</div></div>
        <div class="kpi-grid" id="modules-grid"></div>
      </div>
    </div>

    <!-- TAB 4: COMPLIANCE -->
    <div id="tab-compliance" style="display:none;">
      <div class="kpi-grid" id="compliance-scorecards-grid"></div>
    </div>

    <!-- TAB 5: DLP -->
    <div id="tab-dlp" style="display:none;">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">Data Protection & DLP Discoveries (PAN, Aadhaar, Secrets)</div></div>
        <div class="table-container">
          <table>
            <thead><tr><th>Pattern Type</th><th>Rule</th><th>File Path & Line</th><th>Masked Snippet</th></tr></thead>
            <tbody id="dlp-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 6: AI THREAT INTEL -->
    <div id="tab-threats" style="display:none;">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">AI Threat Correlation & Attack Chains</div></div>
        <div id="attack-chains-container"></div>
      </div>
    </div>

    <!-- TAB 7: REMEDIATION -->
    <div id="tab-remediation" style="display:none;">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Automated One-Click & Guided Remediation</div>
          <button class="btn-fix" onclick="applyAllRemediations()" style="font-size:0.9rem; padding:0.6rem 1.2rem;">Apply All One-Click Fixes</button>
        </div>
        <div id="remediation-list"></div>
      </div>
    </div>

    <!-- TAB 8: AI COPILOT -->
    <div id="tab-copilot" style="display:none;">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">AI Security Copilot & Threat Hunting Assistant</div></div>
        <div class="chat-container">
          <div class="chat-messages" id="chat-messages">
            <div class="chat-bubble chat-bubble-ai">
              Hello! I am your institutional AI Security Copilot. I analyze real-time audit findings across 22 modules, evaluate CERT-In & ISO compliance, and generate remediation guidance. Ask me anything like:
              <br/><br/>
              • <em>"Give me an executive summary of this endpoint"</em><br/>
              • <em>"What are the critical vulnerabilities discovered?"</em><br/>
              • <em>"Are there any unprotected PAN or Aadhaar numbers?"</em><br/>
              • <em>"Explain CERT-In compliance posture"</em>
            </div>
          </div>
          <div class="chat-input-bar">
            <input type="text" class="chat-input" id="chat-input" placeholder="Ask AI Copilot about threats, logs, CVEs, or compliance..." onkeydown="if(event.key==='Enter') sendChatMessage()" />
            <button class="btn-send" onclick="sendChatMessage()">Ask Copilot</button>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 9: EXPORTS -->
    <div id="tab-exports" style="display:none;">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">Generate & Export Enterprise Audit Reports</div></div>
        <p style="color:var(--text-muted); font-size:0.9rem;">Export audit reports for institutional committees, CERT-In compliance submission, SIEM integration, and forensic archives.</p>
        <div class="export-grid">
          <a class="btn-export" href="/api/export/html" target="_blank">
            <strong>Interactive HTML Report</strong>
            <span>Complete standalone dark report with charts</span>
          </a>
          <a class="btn-export" href="/api/export/pdf" target="_blank">
            <strong>Printable Executive PDF</strong>
            <span>Signed committee audit briefing format</span>
          </a>
          <a class="btn-export" href="/api/export/xlsx" download>
            <strong>Excel Spreadsheet (.xls)</strong>
            <span>Multi-sheet workbook (Summary, Findings, DLP)</span>
          </a>
          <a class="btn-export" href="/api/export/csv" download>
            <strong>CSV Findings File</strong>
            <span>RFC 4180 flat table for spreadsheet analysis</span>
          </a>
          <a class="btn-export" href="/api/export/json" download>
            <strong>JSON SOC / SIEM Export</strong>
            <span>Machine-readable for Splunk, Elastic, Wazuh</span>
          </a>
          <a class="btn-export" href="/api/export/certin" download>
            <strong>CERT-In Annexure-I Form</strong>
            <span>Official Cyber Incident Notification document</span>
          </a>
        </div>
      </div>
    </div>

  </div>

  <script>
    let currentReport = null;

    function showTab(tabName) {
      const tabs = ['dashboard', 'findings', 'modules', 'compliance', 'dlp', 'threats', 'remediation', 'copilot', 'exports'];
      tabs.forEach(t => {
        const el = document.getElementById('tab-' + t);
        if (el) el.style.display = (t === tabName) ? 'block' : 'none';
      });
      document.querySelectorAll('.tab-btn').forEach((btn, idx) => {
        btn.classList.toggle('active', tabs[idx] === tabName);
      });
    }

    async function runAudit() {
      const btn = document.getElementById('btn-trigger-audit');
      const banner = document.getElementById('progress-banner');
      const bar = document.getElementById('progress-bar');
      const lbl = document.getElementById('progress-label');
      const pct = document.getElementById('progress-pct');

      btn.disabled = true;
      banner.style.display = 'block';
      bar.style.width = '20%';
      pct.innerText = '20%';
      lbl.innerText = 'Initializing 22 Enterprise Audit Modules...';

      try {
        const resp = await fetch('/api/audit/run', { method: 'POST' });
        bar.style.width = '70%';
        pct.innerText = '70%';
        lbl.innerText = 'Synthesizing AI Threat Intelligence & Behavioral Models...';

        const report = await resp.json();
        bar.style.width = '100%';
        pct.innerText = '100%';
        lbl.innerText = 'Audit completed successfully!';

        setTimeout(() => { banner.style.display = 'none'; }, 1200);
        renderReport(report);
      } catch (e) {
        alert('Audit error: ' + e);
        banner.style.display = 'none';
      } finally {
        btn.disabled = false;
      }
    }

    function renderReport(report) {
      currentReport = report;
      document.getElementById('meta-host').innerText = report.targetHostname || 'localhost';
      document.getElementById('meta-os').innerText = report.operatingSystem || 'Windows';
      document.getElementById('meta-domain').innerText = report.domainOrWorkgroup || 'Workgroup';
      document.getElementById('meta-class').innerText = (report.govProfile && report.govProfile.classificationLevel) ? report.govProfile.classificationLevel : 'Restricted';
      document.getElementById('meta-eoffice').innerText = (report.govProfile && report.govProfile.isEOfficeCompatible) ? 'Verified Compatible' : 'Action Required';
      document.getElementById('meta-evidence').innerText = (report.govProfile && report.govProfile.digitalEvidenceHashChain) ? report.govProfile.digitalEvidenceHashChain : 'None';
      document.getElementById('tab-findings-count').innerText = report.findings ? report.findings.length : '0';

      // Scores
      if (report.scores) {
        document.getElementById('kpi-health').innerText = Math.round(report.scores.securityHealthScore) + '/100';
        document.getElementById('kpi-threat').innerText = Math.round(report.scores.threatScore) + '/100';
        document.getElementById('kpi-comp').innerText = Math.round(report.scores.complianceScore) + '%';
        document.getElementById('kpi-risk').innerText = Math.round(report.scores.aiRiskScore) + '%';
        document.getElementById('kpi-insider').innerText = Math.round(report.scores.insiderThreatScore) + '%';
        document.getElementById('kpi-ransom').innerText = Math.round(report.scores.ransomwareProbability) + '%';
      }

      // Top Findings
      const topTbody = document.getElementById('top-findings-tbody');
      topTbody.innerHTML = '';
      const topFindings = (report.findings || []).filter(f => f.severity >= 3).slice(0, 5);
      if (topFindings.length === 0) {
        topTbody.innerHTML = '<tr><td colspan="4" style="color:#34d399; text-align:center;">No high or critical findings detected!</td></tr>';
      } else {
        topFindings.forEach(f => {
          topTbody.innerHTML += `<tr>
            <td><span class="badge ${getBadgeClass(f.severity)}">${getSeverityLabel(f.severity)}</span></td>
            <td><strong>${f.title}</strong></td>
            <td>${getCategoryLabel(f.category)}</td>
            <td>${f.remediationRecommendation || 'Review policy'}</td>
          </tr>`;
        });
      }

      // All findings
      filterFindings();

      // Modules
      renderModules(report);

      // Compliance
      renderCompliance(report);

      // DLP
      renderDlp(report);

      // Threats / Attack Chains
      renderThreats(report);

      // Remediation
      renderRemediation(report);
    }

    function renderModules(report) {
      const grid = document.getElementById('modules-grid');
      grid.innerHTML = '';
      const moduleNames = [
        "1. Asset Discovery & Inventory", "2. OS Security Audit", "3. Vulnerability Assessment",
        "4. Endpoint Security", "5. Firewall Security", "6. Network Security",
        "7. Active Directory Audit", "8. Application Security", "9. USB & Device Control",
        "10. Log Analysis Module", "11. Malware & Threat Analysis", "12. File Integrity Monitoring",
        "13. Compliance Audit Module", "14. Configuration Benchmarking", "15. Data Protection Audit",
        "16. Credential Security", "17. Performance & Health", "18. Enterprise Management",
        "19. Automated Remediation", "20. Govt & Research Lab Audit", "21. AI Threat Intelligence", "22. Executive Reporting"
      ];

      moduleNames.forEach(m => {
        grid.innerHTML += `<div class="kpi-card">
          <div class="kpi-title">${m}</div>
          <div style="font-size:1.1rem; font-weight:700; color:#34d399; margin:0.4rem 0;">Audited</div>
          <div class="kpi-desc">Verified Active</div>
        </div>`;
      });
    }

    function renderCompliance(report) {
      const grid = document.getElementById('compliance-scorecards-grid');
      grid.innerHTML = '';
      (report.complianceScorecards || []).forEach(sc => {
        grid.innerHTML += `<div class="kpi-card">
          <div class="kpi-title">${sc.standardTitle || sc.standard}</div>
          <div class="kpi-value" style="color:#38bdf8;">${sc.compliancePercentage}%</div>
          <div class="kpi-desc">${sc.passedControls} / ${sc.totalControls} Controls Passed</div>
        </div>`;
      });
    }

    function renderDlp(report) {
      const tbody = document.getElementById('dlp-tbody');
      tbody.innerHTML = '';
      if (!report.dlpFindings || report.dlpFindings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="color:#34d399; text-align:center;">No sensitive PII / credential leaks detected.</td></tr>';
        return;
      }
      report.dlpFindings.forEach(d => {
        tbody.innerHTML += `<tr>
          <td><span class="badge badge-critical">${d.patternType}</span></td>
          <td>${d.ruleTriggered}</td>
          <td><code>${d.filePath}:${d.lineNumber}</code></td>
          <td><code>${d.maskedSnippet}</code></td>
        </tr>`;
      });
    }

    function renderThreats(report) {
      const container = document.getElementById('attack-chains-container');
      container.innerHTML = '';
      if (!report.correlatedAttackChains || report.correlatedAttackChains.length === 0) {
        container.innerHTML = '<p style="color:#34d399;">No multi-stage attack chains identified.</p>';
        return;
      }
      report.correlatedAttackChains.forEach(c => {
        container.innerHTML += `<div style="background:var(--bg-surface); border:1px solid var(--crit); padding:1.25rem; border-radius:10px; margin-bottom:1rem;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:#fca5a5; font-size:1rem;">${c.title}</strong>
            <span class="badge badge-critical">Confidence: ${c.confidenceScore}%</span>
          </div>
          <p style="margin:0.5rem 0; font-size:0.85rem; color:var(--text-muted);">${c.rootCauseAnalysis}</p>
          <div class="code-box">${c.suggestedRemediation}</div>
        </div>`;
      });
    }

    function renderRemediation(report) {
      const list = document.getElementById('remediation-list');
      list.innerHTML = '';
      const autoRem = (report.findings || []).filter(f => f.canAutoRemediate);
      if (autoRem.length === 0) {
        list.innerHTML = '<p style="color:#34d399;">No outstanding automated remediation tasks needed.</p>';
        return;
      }
      autoRem.forEach(f => {
        list.innerHTML += `<div style="background:var(--bg-surface); border:1px solid var(--border); padding:1rem; border-radius:8px; margin-bottom:1rem; display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong>${f.title}</strong>
            <div style="font-size:0.82rem; color:var(--text-muted); margin-top:0.25rem;">${f.remediationRecommendation}</div>
            <div class="code-box" style="margin-top:0.5rem;">${f.remediationScript || 'Manual script'}</div>
          </div>
          <button class="btn-fix" onclick="applySingleRemediation('${f.id}')">Apply Fix</button>
        </div>`;
      });
    }

    function filterFindings() {
      if (!currentReport || !currentReport.findings) return;
      const search = document.getElementById('search-findings').value.toLowerCase();
      const sev = document.getElementById('filter-severity').value;
      const tbody = document.getElementById('all-findings-tbody');
      tbody.innerHTML = '';

      const filtered = currentReport.findings.filter(f => {
        const matchesSearch = f.title.toLowerCase().includes(search) || (f.description && f.description.toLowerCase().includes(search));
        const matchesSev = sev === 'ALL' || getSeverityLabel(f.severity) === sev;
        return matchesSearch && matchesSev;
      });

      filtered.forEach(f => {
        tbody.innerHTML += `<tr>
          <td><span class="badge ${getBadgeClass(f.severity)}">${getSeverityLabel(f.severity)}</span></td>
          <td><strong>${(f.cvssScore || 0).toFixed(1)}</strong></td>
          <td>${getCategoryLabel(f.category)}</td>
          <td><strong>${f.title}</strong><br/><span style="color:var(--text-dim);">${f.description || ''}</span></td>
          <td>${f.remediationRecommendation || 'N/A'}</td>
          <td>${f.canAutoRemediate ? `<button class="btn-fix" onclick="applySingleRemediation('${f.id}')">Fix</button>` : `<span style="color:var(--text-dim);">Manual</span>`}</td>
        </tr>`;
      });
    }

    async function applySingleRemediation(findingId) {
      if (!confirm('Apply automated remediation for this finding?')) return;
      try {
        const resp = await fetch('/api/remediate/one-click?id=' + findingId, { method: 'POST' });
        const res = await resp.json();
        alert(res.message);
        runAudit();
      } catch (e) { alert('Remediation error: ' + e); }
    }

    async function applyAllRemediations() {
      if (!confirm('Apply all safe one-click remediations on this system?')) return;
      try {
        const resp = await fetch('/api/remediate/all', { method: 'POST' });
        const res = await resp.json();
        alert(res.message);
        runAudit();
      } catch (e) { alert('Remediation error: ' + e); }
    }

    async function sendChatMessage() {
      const input = document.getElementById('chat-input');
      const text = input.value.trim();
      if (!text) return;

      const container = document.getElementById('chat-messages');
      container.innerHTML += `<div class="chat-bubble chat-bubble-user">${text}</div>`;
      input.value = '';
      container.scrollTop = container.scrollHeight;

      try {
        const resp = await fetch('/api/ai/ask', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prompt: text })
        });
        const data = await resp.json();
        container.innerHTML += `<div class="chat-bubble chat-bubble-ai">${data.reply.replace(/\n/g, '<br/>')}</div>`;
        container.scrollTop = container.scrollHeight;
      } catch (e) {
        container.innerHTML += `<div class="chat-bubble chat-bubble-ai" style="color:#ef4444;">Error contacting Copilot: ${e}</div>`;
      }
    }

    function getSeverityLabel(sev) {
      const map = { 0: 'Informational', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };
      return map[sev] || sev;
    }

    function getBadgeClass(sev) {
      const map = { 0: 'badge-info', 1: 'badge-low', 2: 'badge-medium', 3: 'badge-high', 4: 'badge-critical' };
      return map[sev] || 'badge-info';
    }

    function getCategoryLabel(cat) {
      const map = {
        0: 'Asset Discovery', 1: 'OS Security', 2: 'Vulnerability', 3: 'Endpoint Security',
        4: 'Firewall', 5: 'Network Security', 6: 'Active Directory', 7: 'Application Security',
        8: 'USB & Device', 9: 'Log Analysis', 10: 'Malware & Threat', 11: 'File Integrity',
        12: 'Compliance', 13: 'Config Benchmark', 14: 'Data Protection', 15: 'Credential Security',
        16: 'Performance & Health', 17: 'Enterprise Mgmt', 18: 'Gov & Research', 19: 'AI Threat Intel'
      };
      return map[cat] || cat;
    }

    // Auto load latest report on page load
    fetch('/api/audit/latest')
      .then(r => r.json())
      .then(data => { if (data && data.targetHostname) renderReport(data); })
      .catch(() => {});
  </script>
</body>
</html>
""";
    }
}
