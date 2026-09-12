# Release v1.0.0: Enterprise Desktop Security Audit & AI Threat Intelligence Platform

> **Native WinUI 3 Desktop Application & Standalone Portable Distribution**  
> *Tailored for Indian Government, Defense, PSUs, and Autonomous Research Laboratories (CSIR, DRDO, ISRO, IITs, NITs).*

---

## 🚀 Quick Download & Execution

| Asset | Size | Description |
| :--- | :--- | :--- |
| ⚡ **[DesktopAuditTool-Portable.exe](./DesktopAuditTool-Portable.exe)** | 69.3 MB | **Single Portable Executable (Self-Extract & Run)**. Zero installation, zero external dependencies. Double-click to extract automatically and launch the native WinUI 3 dashboard. |
| 💻 **[DesktopAuditTool-Setup-v1.0.0.msi](./DesktopAuditTool-Setup-v1.0.0.msi)** | 46.1 MB | **Enterprise Windows Installer (MSI Package)**. Automated setup with Desktop and Start Menu shortcuts, embedded application logo, and seamless uninstallation. |
| 📦 **[DesktopAuditTool-WinUI-Portable-v1.0.0.zip](./DesktopAuditTool-WinUI-Portable-v1.0.0.zip)** | 55.5 MB | **Complete Standalone Portable Suite** (Native WinUI 3 + CLI Scanner). Unpack anywhere and run without administrative setup. |
| 📑 **[Enterprise-Desktop-Security-Audit-Tool-Documentation.pdf](./Enterprise-Desktop-Security-Audit-Tool-Documentation.pdf)** | 1.62 MB | **Publication-Grade Technical Documentation & Manual** with UI screenshots, AI threat modeling, and regulatory compliance mapping. |
| 🔑 **[SHA256SUMS.txt](./SHA256SUMS.txt)** | < 1 KB | Official cryptographic hash manifest for air-gapped terminal integrity verification. |

---

## 🏃 How to Run on Any Windows System

### Option 1: Single Portable Executable (Recommended for On-Demand Audits)
1. Download `DesktopAuditTool-Portable.exe` to any folder or USB stick.
2. Double-click `DesktopAuditTool-Portable.exe`.
3. The launcher automatically extracts the runtime into your local application cache (`%LocalAppData%\DesktopAuditTool\v1.0.0`) and immediately launches the dark-themed WinUI 3 application with official taskbar branding.
   - *Command-line switch*: Run `DesktopAuditTool-Portable.exe --extract-only` to unpack without launching.

### Option 2: Enterprise Windows Installer (Recommended for Workstations)
1. Download `DesktopAuditTool-Setup-v1.0.0.msi`.
2. Double-click to install. It installs to `C:\Program Files\DesktopAuditTool` and creates Desktop & Start Menu shortcuts with the official application logo.
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

## 🛡️ Statutory Compliance & Regulatory Seals

The platform displays verified compliance badges:
- 🇮🇳 **DPDP Act 2023 Verified Compliance**: Mathematical Verhoeff Checksum validation on Indian Aadhaar numbers, PAN protection, and local PII masking.
- 🇮🇳 **CERT-In Guidelines Compliant**: 180-day event log retention checking and automatic CERT-In Annexure-I Incident Reporting form generator.
- 🌐 **ISO/IEC 27001:2022 Architecture**: Annex A controls across endpoint access, configuration, and cryptography.
- 🏛️ **NIST SP 800-53 Rev. 5**: Federal technical controls across AC, AU, CM, and SI families.
- 🎯 **CIS Benchmarks (Level 1 & 2)**: Windows 10/11 Enterprise endpoint hardening baseline.
- 🇮🇳 **MeitY & STQC e-Governance**: eOffice Smart Card DSC (`SCardSvr`) integrity and NIC network verification.

---

## 🤖 AI Vulnerability Assessment & Mitigation (OWASP LLM Top 10)

This release introduces the `AiSecurityGuard` engine providing defense-in-depth against AI threat vectors:
- **OWASP LLM01 (Prompt Injection)**: Regex-based adversarial pattern defusing and strict XML boundary isolation (`<analyst_query>`).
- **OWASP LLM02 (Insecure Output)**: AI outputs are strictly diagnostic; autonomous shell execution is prohibited.
- **OWASP LLM04 (Model DoS)**: Enforced 1,000-character input bounds and 5-second asynchronous timeout cancellation.
- **OWASP LLM06 (Sensitive Data Disclosure)**: Automated deterministic DPDP masking on all inputs before entering AI synthesis.
- **OWASP LLM09 (Overreliance)**: Pre-compiled, digitally hashed C# remediation engine with explicit human approval and rollback scripts.

---

## 🔑 Cryptographic Checksums (SHA-256)

```
B5BC7957935372627175634473420AE18680BF2735D6287AABAC7D926F20F8AC  DesktopAuditTool-Portable.exe
2AD10C011D5629BF17A4F7E224EA63BBB9428A3AF10A079339332228BBEC1839  DesktopAuditTool-Setup-v1.0.0.msi
A4F482EA00AC513355DEDE90D294FD6B78ADFFA9034E7E6DC4DD9E40889530B7  DesktopAuditTool-WinUI-Portable-v1.0.0.zip
08CC3290A962786298C53BF3DBA91653A00A5C64F5F5B0097EC566FBDA32AAAA  Enterprise-Desktop-Security-Audit-Tool-Documentation.pdf
```

