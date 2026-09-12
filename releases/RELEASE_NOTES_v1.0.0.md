# Release v1.0.0: Enterprise Desktop Security Audit & AI Threat Intelligence Platform

> **Native WinUI 3 Desktop Application & Standalone Portable Distribution**  
> *Tailored for Indian Government, Defense, PSUs, CSIR, DRDO, ISRO, US Defense Contractors, and Financial Institutions.*

---

## 🚀 Quick Download & Execution

| Asset | Size | Description |
| :--- | :--- | :--- |
| ⚡ **[DesktopAuditTool-Portable.exe](./DesktopAuditTool-Portable.exe)** | 87.6 MB | **Single Portable Executable (Self-Extract & Run)**. 100% self-contained, zero external dependencies, bundles .NET 10 Desktop runtime. Double-click to extract automatically and launch the native WinUI 3 dashboard in full screen. |
| 💻 **[DesktopAuditTool-Setup-v1.0.0.msi](./DesktopAuditTool-Setup-v1.0.0.msi)** | 61.4 MB | **Enterprise Windows Installer (MSI Package)**. Authored with WiX Toolset v5. Self-contained setup with Desktop and Start Menu shortcuts, embedded application logo, and seamless uninstallation. |
| 📦 **[DesktopAuditTool-WinUI-Portable-v1.0.0.zip](./DesktopAuditTool-WinUI-Portable-v1.0.0.zip)** | 76.5 MB | **Complete Standalone Portable Suite** (Self-Contained Native WinUI 3 + CLI Scanner). Unpack anywhere and run without .NET runtime or administrative setup. |
| 📑 **[Enterprise-Desktop-Security-Audit-Tool-Documentation.pdf](./Enterprise-Desktop-Security-Audit-Tool-Documentation.pdf)** | 4.42 MB | **Publication-Grade Technical Documentation & Manual** with full UI screenshots, AI threat modeling, and regulatory compliance mapping. |
| 🔑 **[SHA256SUMS.txt](./SHA256SUMS.txt)** | < 1 KB | Official cryptographic hash manifest for air-gapped terminal integrity verification. |

---

## 🏃 How to Run on Any Windows System

### Option 1: Single Portable Executable (Recommended for On-Demand Audits)
1. Download `DesktopAuditTool-Portable.exe` to any folder or USB stick.
2. Double-click `DesktopAuditTool-Portable.exe`.
3. The launcher automatically extracts the runtime into your local application cache (`%LocalAppData%\DesktopAuditTool\v1.0.0`) and immediately launches the dark-themed WinUI 3 application with official taskbar branding in full-screen mode.
   - *Command-line switch*: Run `DesktopAuditTool-Portable.exe --extract-only` to unpack without launching.

### Option 2: Enterprise Windows Installer (Recommended for Workstations)
1. Download `DesktopAuditTool-Setup-v1.0.0.msi`.
2. Double-click to install. It installs to `C:\Program Files\DesktopSecurityAuditTool` and creates Desktop & Start Menu shortcuts with the official application logo.
3. Launch from the Start Menu or Desktop shortcut anytime.

### Option 3: Standalone Portable ZIP
1. Download `DesktopAuditTool-WinUI-Portable-v1.0.0.zip` to your local drive or USB drive.
2. Extract all files to a folder of your choice (e.g. `C:\AuditTool` or `D:\AuditTool`).
3. Double-click `Launch-DesktopAuditTool-WinUI.bat` (or execute `DesktopAuditTool.WinUI.exe`).
4. For headless/automated scanning, double-click `Launch-DesktopAuditTool-CLI.bat`.

---

## 🔒 100% Air-Gapped & Zero Data Egress Verification

- **Zero Outbound Telemetry**: The application contains **zero external network sockets**, **zero DNS queries**, and **zero cloud analytics**.
- **Self-Contained Intelligence**: Built-in offline CVE catalogs, MITRE ATT&CK taxonomy, and local heuristic inference models.
- **Air-Gap Certified**: Verified via Wireshark and `AiSecurityGuard.AssertAirGappedOfflineIntegrity()`.

---

## 🛡️ Statutory Compliance & Regulatory Frameworks (13 Standards)

The platform evaluates workstations against selectable compliance profiles:

### 🇮🇳 Indian Sovereign Profile
- **DPDP Act 2023 Verified Compliance**: Mathematical Verhoeff Checksum validation on Indian Aadhaar numbers, PAN protection, and local PII masking.
- **CERT-In Guidelines Compliant**: 180-day event log retention checking and automatic CERT-In Annexure-I Incident Reporting form generator.
- **MeitY & STQC e-Governance**: eOffice Smart Card DSC (`SCardSvr`) integrity and NIC network verification.

### 🛡️ US Military & Defense Profile
- **DoD DISA STIG (Windows 10/11 Enterprise)**: Legal notice warning banner (`V-253280`), LM/NTLMv1 disabling (`LmCompatibilityLevel = 5`), BitLocker XTS-AES 256, DoD CAC/Smart Card logon (`V-253315`), PowerShell script block logging (`V-253340`), and Exploit Guard mitigations.
- **CMMC 2.0 Level 2 (Advanced)**: Defense Industrial Base CUI protection: authorized access (`AC.L2-3.1.1`), 15-minute inactivity session lockout (`AC.L2-3.1.10`), audit logging (`AU.L2-3.3.1`), and flaw remediation (`SI.L2-3.14.1`).
- **NIST SP 800-171 Rev. 2/3**: Non-privileged execution restrictions (`3.1.7`), legacy protocol elimination (SMBv1, LLMNR) (`3.4.7`), and FIPS-validated cryptography (`3.13.11`).

### 🏦 US Financial & Banking Profile
- **PCI-DSS v4.0**: Host firewall on all profiles (Req 1.2), hardening & unused service removal (Req 2.2), anti-malware signatures <24h (Req 5.2), strong authentication & 15-minute lock (Req 8.2/8.3), and 64MB+ security audit logging (Req 10.2).
- **SOX Section 404 ITGC**: Segregation of duties (local admins <= 3), dormant account revocation (>90 days inactive), software whitelist integrity, and file integrity monitoring (FIM).
- **GLBA Safeguards Rule (16 CFR Part 314)**: Nonpublic customer financial record controls (§ 314.4(c)(1)), encryption at rest with BitLocker and in transit with TLS 1.2+ (§ 314.4(c)(3)), and continuous vulnerability monitoring.

### 🌐 Global Enterprise Baselines
- **ISO/IEC 27001:2022 Architecture**: Annex A controls across endpoint access, configuration, and cryptography.
- **NIST SP 800-53 Rev. 5**: Federal technical controls across AC, AU, SC, and SI families.
- **CIS Benchmarks (Level 1 & 2)**: Windows 10/11 Enterprise endpoint hardening baseline.

---

## 🔍 Module 3: Vulnerability Assessment Features

- **Offline CVE Version Matching**: Assesses installed software against known vulnerable version thresholds for Google Chrome, 7-Zip, VLC Media Player, OpenSSH, Python, Node.js, and Adobe Acrobat Reader without any internet connectivity.
- **CVSS v3.1 / v4.0 Scoring**: Computes exact CVSS vector scores (from Medium 7.5 to Critical 9.8).
- **CISA Known Exploited Vulnerabilities (KEV)**: Flags actively exploited in-the-wild zero-days (such as OpenSSH *regreSSHion* CVE-2024-6387, libwebp CVE-2023-4863).
- **Cross-Framework Mapping**: Every vulnerability automatically correlates to CERT-In (CI-03), DoD DISA STIG (V-253370), CMMC 2.0 (SI.L2-3.14.1), NIST SP 800-171 (3.14.1), and PCI-DSS v4.0 (Req 11.3.1).

---

## 🤖 AI Vulnerability Assessment & Hardening (OWASP LLM Top 10)

The `AiSecurityGuard` engine enforces defense-in-depth against AI threat vectors:
- **OWASP LLM01 (Prompt Injection)**: Regex-based adversarial pattern defusing and strict XML boundary isolation (`<analyst_query>`).
- **OWASP LLM02 (Insecure Output)**: AI outputs are strictly diagnostic; autonomous shell execution is prohibited.
- **OWASP LLM04 (Model DoS)**: Enforced 1,000-character input bounds and 5-second asynchronous timeout cancellation.
- **OWASP LLM06 (Sensitive Data Disclosure)**: Automated deterministic DPDP masking on all inputs before entering AI synthesis.
- **OWASP LLM09 (Overreliance)**: Pre-compiled, digitally hashed C# remediation engine with explicit human approval and rollback scripts.

---

## 🔑 Cryptographic Checksums (SHA-256)

```
32BA3E565C1BD5AD965B072752DA9F649FCE49C23015CFC26080B33EA7D0B9E0  DesktopAuditTool-Portable.exe
0749D0E80732494B22FC5861616FF3BBA6755F09FA1C429AB8F2370088F77D28  DesktopAuditTool-Setup-v1.0.0.msi
5FB8E85AF35CAF1B404DE66E511EA380AB714EDCFAECFDA294DC5475ADB85485  DesktopAuditTool-WinUI-Portable-v1.0.0.zip
776B855CEC97983BDC1D9946AE54ECF524677886839455B7F67472214C82A37E  Enterprise-Desktop-Security-Audit-Tool-Documentation.pdf
```
