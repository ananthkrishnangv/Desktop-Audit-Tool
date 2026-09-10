# Enterprise Desktop Security Audit & AI Threat Intelligence Platform

> **Tailored for Government, Defense, PSUs, and Autonomous Research Organizations (CSIR, DRDO, ISRO, IITs, NITs, Central Labs). Built on high-performance .NET 10.**

[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)]()
[![Framework](https://img.shields.io/badge/.NET-10.0-purple.svg)]()
[![Compliance](https://img.shields.io/badge/Compliance-CERT--In%20%7C%20ISO%2027001%20%7C%20NIST%20800--53%20%7C%20CIS-orange.svg)]()

---

## 🏛️ Architectural Decision: Why .NET 10 Over Rust?

When building an enterprise-grade security audit tool capable of deep endpoint inspection across 22 audit categories and 18 AI threat intelligence layers:

1. **Native OS & Kernel Integration**:
   - .NET 10 provides managed, first-class wrappers for Windows Management Instrumentation (WMI), Common Information Model (CIM), Windows Event Log Readers (`EventLogReader`), Registry hives, LSA/SAM security descriptors, BitLocker, and Active Directory (`System.DirectoryServices`).
   - In Rust, querying WMI, ETW tracing, or parsing Active Directory LDAP schemas requires heavy manual Win32 FFI (`windows-rs`/`winapi`), manual COM pointer management, and raw BSTR handling, which dramatically slows down development and increases code fragility.
2. **Zero-Dependency Standalone Air-Gapped Distribution**:
   - .NET 10 supports **Native AOT (`PublishAot=true`)** and **Single-File Publish**, compiling into a single standalone `.exe` or Linux ELF binary with zero external runtime requirements. Target government lab machines do not require the .NET runtime to be installed.
3. **Enterprise Multi-Format Reporting**:
   - Out-of-the-box support for generating multi-sheet XML-based Excel (`.xls`), print-ready PDF reports, RFC 4180 CSV, SIEM-compatible JSON, and CERT-In Annexure-I cyber incident notification forms.
4. **Integrated AI & ML Engine**:
   - First-class support for `Microsoft.ML`, local `ONNX Runtime` models, and async local LLM connections (Ollama, DeepSeek, Llama-3, Phi-3).

---

## 📋 The 22 Core Enterprise Audit Modules

1. **Asset Discovery & Inventory**:
   - Hardware: CPU model & cores, RAM layout, Motherboard manufacturer & product, Disks, Network NICs, USB bus devices, BIOS/UEFI version.
   - Software: Registry 32/64-bit installed applications, browser extensions (Chrome, Edge), running services, startup programs, driver signatures, software licenses.
   - Users: Local users, domain users, privileged administrator group members, dormant accounts (>90 days inactive), shared accounts.
2. **Operating System Security Audit**:
   - OS build validation, End-of-life (EOL) operating system detection.
   - Missing security updates (QuickFixEngineering hotfix verification).
   - OS hardening verification: Secure Boot validation, UAC settings (`EnableLUA`, `ConsentPromptBehaviorAdmin`), Password policy (min length, complexity), Account lockout policy, Screen lock timeout.
3. **Vulnerability Assessment**:
   - Built-in offline CVE identification matching software versions against high-severity CVEs (e.g. 7-Zip, Chrome, VLC, OpenSSH, Python, Adobe Acrobat).
   - CVSS v3.1 / v4.0 scoring, CISA Known Exploited Vulnerabilities (KEV) cross-referencing, exploit availability, and business impact scoring.
4. **Endpoint Security Verification**:
   - Antivirus detection: Windows Defender (`root\Microsoft\Windows\Defender` & `SecurityCenter2`), CrowdStrike Falcon, SentinelOne, Trellix ENS, Carbon Black, Sophos.
   - Real-time protection status, definition signature freshness, and Endpoint Health Score.
5. **Firewall Security Audit**:
   - Windows Defender Firewall: Domain, Private, and Public profile enabled statuses.
   - High-risk open listening ports detection (21, 23, 135, 139, 445).
   - Third-party firewalls: FortiClient, Sophos, Trend Micro, McAfee.
6. **Network Security Audit**:
   - Network adapters, IPv4/IPv6, DNS servers, default gateway, active listening TCP ports.
   - Legacy protocol analysis: SMBv1 status (EternalBlue vector), Telnet usage, FTP usage, SSH configuration, RDP Network Level Authentication (NLA) enforcement.
7. **Active Directory & Domain Audit**:
   - Domain join verification, stale accounts, accounts with `PasswordNeverExpires`, administrative network shares (C$, ADMIN$).
8. **Application Security Audit**:
   - Blacklisted/dangerous software detection: Unapproved remote access tools (AnyDesk, TeamViewer, Ammyy), P2P torrent clients (uTorrent, BitTorrent), packet sniffers (Wireshark), cryptominers.
   - Browser security: unencrypted saved credential store databases (`Login Data`), browser extensions.
9. **USB & Removable Device Control**:
   - Historical USB device enumeration from Windows Registry `SYSTEM\CurrentControlSet\Enum\USBSTOR`.
   - AutoPlay / AutoRun status (`NoDriveTypeAutoRun` != 255).
   - USB mass storage driver restriction on classified endpoints.
10. **Log Analysis & Tampering Audit**:
    - Windows Event Log inspection (`EventLogReader`):
      - Event ID 1102 / 104 (Security audit log cleared / anti-forensics tampering)
      - Event ID 4625 (High-volume failed authentication / brute force)
      - Event ID 4672 (Special privileges assigned / privilege escalation)
      - Event ID 7045 (New service registered)
    - Security log size verification against CERT-In 180-day retention baseline.
11. **Malware & Threat Analysis**:
    - Suspicious process execution (processes running from `%TEMP%`, `AppData\Local\Temp`, offensive tools Mimikatz, ProcDump, Netcat).
    - Unquoted service paths containing spaces without quotes.
    - Malicious startup persistence (obfuscated PowerShell in Registry `Run` / `RunOnce`).
12. **File Integrity Monitoring (FIM)**:
    - Critical system files monitored: `hosts`, `networks`, `protocol`, `services`.
    - Cryptographic SHA-256 baseline hashing and modification drift detection.
    - DNS hijacking / sinkhole detection in hosts file.
13. **Compliance Audit Module**:
    - Generates detailed scorecards with pass/fail controls and percentage compliance for:
      - **CERT-In Cyber Security Directions (Ministry of Electronics & IT)**
      - **ISO/IEC 27001:2022**
      - **NIST SP 800-53 Rev. 5**
      - **CIS Benchmarks (Level 1 & 2)**
      - **MeitY Government Desktop Security Guidelines**
      - **STQC e-Governance Security Guidelines**
14. **Configuration Benchmarking**:
    - CIS Windows 10/11 benchmarks: Built-in Guest account status, LSA Protection (`RunAsPPL`), RDP password saving restriction (`DisablePasswordSaving`), LLMNR multicast resolution.
15. **Data Protection & DLP Audit**:
    - Deep sensitive document scanner for user folders (`Desktop`, `Downloads`, `Documents`):
      - **Indian PAN Card Numbers** regex (`[A-Z]{5}[0-9]{4}[A-Z]{1}`)
      - **Indian Aadhaar Numbers** with full **Verhoeff Checksum Algorithm** verification
      - **Indian Passport Numbers** regex
      - **Indian Bank IFSC Codes** and Account Numbers
      - **Cloud API Keys & Tokens** (AWS `AKIA...`, GitHub `ghp_...`, RSA/SSH Private Keys)
      - **Plaintext Password Files** (`passwords.txt`, `credentials.json`, `.env`)
16. **Credential Security Assessment**:
    - WDigest cleartext password caching in LSASS (`UseLogonCredential`).
    - LSA Protection (`RunAsPPL`) & Credential Guard status.
    - Unencrypted private SSH keys in `~/.ssh/`.
    - Excessive cached domain logons (`CachedLogonsCount`).
17. **Performance & Resource Audit**:
    - Drive C: free storage capacity and disk health.
    - Security agent resource overhead and multiple concurrent AV/EDR engine conflicts.
18. **Enterprise Management & RBAC Console**:
    - RBAC enforcement (Auditor, SOC Analyst, Administrator, Department Head, Compliance Officer).
    - Departmental and asset grouping.
19. **Automated Remediation Engine**:
    - One-Click safe automated hardening (Firewall enable, SMBv1 disable, UAC fix, LSA protection, AutoRun disable).
    - Guided PowerShell and Bash script generation with rollback scripts.
20. **Government & Research Lab Specific Features**:
    - Designed for **CSIR, DRDO, ISRO, IITs, NITs, and Autonomous Labs**.
    - Classified asset tagging (Unclassified, Restricted, Confidential, Secret, Top Secret).
    - Scientific software inventory (MATLAB, LabVIEW, ANSYS, COMSOL, Gaussian, Mathematica, ROS).
    - NIC Network compliance checks and eOffice DSC Smart Card compatibility (`SCardSvr`).
    - Cryptographic digital evidence chain of custody (SHA256).
    - **CERT-In Cyber Security Incident Reporting Form (Annexure-I)** generation.
21. **AI Security Intelligence & Threat Assessment**:
    - Feeds findings into the AI Behavioral Analytics Layer.
22. **Executive Reporting & Dashboard**:
    - Synthesizes findings into unified KPI scorecards and exports to PDF, Excel, HTML, CSV, and JSON.

---

## 🤖 AI Security & Threat Intelligence Layer (18 Sub-Modules)

1. **AI-Powered Threat Detection Engine**: Continuous behavioral analysis for Living-Off-The-Land (LOLBins: `certutil`, `mshta`, `wmic`, `powershell`), mimikatz patterns, ransomware staging.
2. **User Behavior Analytics (UBA)**: Learns baseline working hours; flags abnormal 2:00 AM logins, anomalous USB device insertions, bulk project file copying.
3. **Entity Behavior Analytics (UEBA)**: Workstation behavioral baselines, rogue network services, and privilege drift.
4. **AI-Based Anomaly Detection**: Statistical & Isolation Forest heuristic engine detecting unexpected CPU spikes, outbound network bursts, and memory injection.
5. **Process Intelligence Engine**: Reconstructs parent-child process execution trees (`Parent -> Child`), detecting process hollowing and unquoted path abuse.
6. **AI-Based Log Analytics**: Ingests Windows Event Logs and translates raw Event IDs (4625, 4672, 7045, 1102) into natural language forensic narratives.
7. **Threat Hunting Assistant**: Natural language query engine embedded with direct mapping to the **MITRE ATT&CK** matrix.
8. **Ransomware Early Warning System**: Real-time heuristic detection of mass file modifications, shadow copy deletion (`vssadmin delete shadows`), and ransomware propagation vulnerability.
9. **Insider Threat Detection**: Monitors unauthorized copying of sensitive research proposals, confidential datasets, and USB mass transfers.
10. **Threat Correlation Engine**: Correlates multi-stage attack patterns (e.g. *Failed Logins -> USB Device Inserted -> New Local Admin Created -> Firewall Disabled*) into unified high-confidence incident chains.
11. **Predictive Risk Analysis**: Machine learning probabilistic formula forecasting the likelihood of imminent endpoint compromise.
12. **Zero-Day Attack Detection**: Non-signature behavioral anomaly scoring for memory-resident and novel exploit patterns.
13. **AI-Powered Vulnerability Prioritization**: Contextual prioritization combining CVSS + EPSS (Exploit Prediction Scoring System) + asset criticality + internet exposure.
14. **Security Knowledge Graph**: Graph model linking `User -> Workstation -> Project -> Department -> Vulnerabilities -> Threats`.
15. **AI Incident Investigation Assistant**: Automatically generates chronological attack timelines, forensic root cause deductions, and impact assessments.
16. **LLM Security Copilot**: Built-in intelligent chatbot with an offline security knowledge base and optional connection to local Ollama (Llama 3, DeepSeek, Phi) or cloud LLMs.
17. **SOC Dashboard with AI Scores**:
    - **Security Health Score** (0-100)
    - **Threat Score** (0-100)
    - **Compliance Score** (0-100)
    - **AI Risk Forecast Index** (0-100)
    - **Insider Threat Score** (0-100)
    - **Ransomware Probability** (0-100)
18. **Government & Research Lab AI Features**: Project-specific risk scoring for strategic computing initiatives and classified research data protection.

---

## 🚀 Getting Started

### Prerequisites
- Windows 10/11 Enterprise / Server (or Linux/macOS)
- [.NET 10 SDK](https://dotnet.microsoft.com/download)

### 1. Build the Solution
```powershell
dotnet build -c Release
```

### 2. Run Test Suite
```powershell
dotnet test
```

### 3. Launch Interactive Standalone Desktop GUI
Simply run the executable without arguments (or with `--gui`):
```powershell
dotnet run --project src/DesktopAuditTool.App
```
The embedded Desktop Server activates at `http://127.0.0.1:58200/` and automatically opens the Desktop SOC Dashboard window in your browser.

### 4. Run Headless Command-Line Audit (for Servers & Automation)
```powershell
dotnet run --project src/DesktopAuditTool.App -- --cli --export ./reports
```

Command-Line Arguments:
- `--cli`, `--audit`, `--all`: Execute full 22-module audit and print executive scorecard.
- `--export <dir>`: Directory to export PDF, Excel, HTML, CSV, JSON, and CERT-In form.
- `--dept <name>`: Department name (e.g., `'Advanced Aerospace Simulation'`).
- `--project <name>`: Project name (e.g., `'Strategic HPC Computing'`).
- `--classification <tier>`: `Unclassified`, `Restricted`, `Confidential`, `Secret`, `TopSecret`.

---

## 📊 Exported Reports

When an audit is executed, all 6 enterprise reporting formats are automatically generated:
1. **Interactive HTML Report** (`.html`): High-fidelity dark-themed SOC report with interactive tables, scorecards, and evidence hash badges.
2. **Printable Executive PDF** (`.pdf.html`): Paginated briefing report formatted for audit committees and institutional directors.
3. **Multi-Sheet Excel Workbook** (`.xls`): Structured spreadsheet with tabs: `Executive Summary`, `Audit Findings`, and `Sensitive Data DLP`.
4. **CSV Findings File** (`.csv`): RFC 4180 flat table ready for Excel, SIEM, or database imports.
5. **JSON SOC / SIEM Export** (`.json`): Structured machine-readable schema for Splunk, Elastic, and Wazuh.
6. **CERT-In Annexure-I Form** (`.txt`): Official Incident Notification format compliant with Indian Computer Emergency Response Team Directions.

---

## 🛡️ Git Repository & Backup

Repository: [https://github.com/ananthkrishnangv/Desktop-Audit-Tool.git](https://github.com/ananthkrishnangv/Desktop-Audit-Tool.git)
Branch: `main`

---

## 📄 License
Enterprise Security License - Tailored for Institutional Research & Defense Workstations.
