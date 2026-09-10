# Release v1.0.0: Enterprise Desktop Security Audit & AI Threat Intelligence Platform

> **Native WinUI 3 Desktop Application & Standalone Portable Distribution**  
> *Tailored for Indian Government, Defense, PSUs, and Autonomous Research Laboratories (CSIR, DRDO, ISRO, IITs, NITs).*

---

## 🚀 Quick Download & Execution

| Asset | Size | Description |
| :--- | :--- | :--- |
| 📦 **[DesktopAuditTool-WinUI-Portable-v1.0.0.zip](./DesktopAuditTool-WinUI-Portable-v1.0.0.zip)** | ~55.5 MB | **Complete Standalone Portable Suite** (Native WinUI 3 + CLI Scanner). Unpack and run on any Windows 10/11 machine without installation or administrative setup. |
| 📑 **[Enterprise-Desktop-Security-Audit-Tool-Documentation.pdf](./Enterprise-Desktop-Security-Audit-Tool-Documentation.pdf)** | 1.62 MB | **Publication-Grade Technical Documentation & Manual** with UI screenshots, AI threat modeling, and regulatory compliance mapping. |
| 🔑 **[SHA256SUMS.txt](./SHA256SUMS.txt)** | < 1 KB | Official cryptographic hash manifest for air-gapped terminal integrity verification. |

---

## 🏃 How to Run on Any Windows System

1. **Download and Extract**:
   - Download `DesktopAuditTool-WinUI-Portable-v1.0.0.zip` to your local drive or USB stick.
   - Right-click and extract all files to a folder of your choice (e.g. `C:\AuditTool` or `D:\AuditTool`).
2. **Launch Native WinUI 3 GUI Application**:
   - Double-click `Launch-DesktopAuditTool-WinUI.bat` (or execute `DesktopAuditTool.WinUI.exe`).
   - The dark-themed WinUI 3 interface opens with real-time SOC scorecards and one-click auditing.
3. **Launch Automated Headless CLI Audit**:
   - Double-click `Launch-DesktopAuditTool-CLI.bat`.
   - Generates all 6 export formats (HTML, PDF, Excel `.xls`, CSV, JSON, and CERT-In Annexure-I form) into the `./Reports` directory.

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
35AE463B3ACB34265438CE9A81143DABCB8D49EF33E097BC4BE2EA0A929205B1  DesktopAuditTool-WinUI-Portable-v1.0.0.zip
DA03E1D4F92CC787485FF66E659D6E9ECC39E6237CF8E250E607607DA94B277E  Enterprise-Desktop-Security-Audit-Tool-Documentation.pdf
```
