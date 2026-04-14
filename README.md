# 🚨 Splunk Detection Rules

![Splunk](https://img.shields.io/badge/SIEM-Splunk-FF5733?style=flat-square)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-B22222?style=flat-square)
![Rules](https://img.shields.io/badge/Detection%20Rules-11-brightgreen?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

A library of custom SPL (Search Processing Language) detection rules developed and validated in my [SOC Home Lab](https://github.com/Qwortie/SOC-Home-Lab). Each rule is mapped to MITRE ATT&CK, documented with detection logic, tuning notes, and the data sources it targets.

Rules are organised by MITRE ATT&CK tactic. All rules are written for Splunk Enterprise with Windows Event Log and Sysmon data sources.

---

## 📋 Rule Index

### 🔑 Credential Access

| Rule | Technique | ID | Severity | File |
|---|---|---|---|---|
| Password Spray — Multiple Account Failures | Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | High | [credential-access/password-spray.spl](./credential-access/password-spray.spl) |
| Kerberoasting — RC4 Service Ticket Requested | Kerberoasting | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | High | [credential-access/kerberoasting.spl](./credential-access/kerberoasting.spl) |
| Mimikatz — LSASS Memory Access | OS Credential Dumping | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Critical | [credential-access/mimikatz-lsass.spl](./credential-access/mimikatz-lsass.spl) |

### 🔁 Persistence

| Rule | Technique | ID | Severity | File |
|---|---|---|---|---|
| Scheduled Task Creation — Persistence | Scheduled Task/Job | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Medium | [persistence/scheduled-task.spl](./persistence/scheduled-task.spl) |
| New Local Admin Account Created | Create Account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | High | [persistence/new-local-admin.spl](./persistence/new-local-admin.spl) |
| LNK Payload Execution via PowerShell | Boot/Logon Autostart | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | High | [persistence/lnk-execution.spl](./persistence/lnk-execution.spl) |

### 🔀 Lateral Movement

| Rule | Technique | ID | Severity | File |
|---|---|---|---|---|
| Pass-the-Hash — NTLM Lateral Movement | Use Alternate Auth Material | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | High | [lateral-movement/pass-the-hash.spl](./lateral-movement/pass-the-hash.spl) |

### ⚙️ Execution

| Rule | Technique | ID | Severity | File |
|---|---|---|---|---|
| Office Application Spawning Suspicious Child Process | Command and Scripting Interpreter | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | High | [execution/macro-child-process.spl](./execution/macro-child-process.spl) |
| ISO Mount + rundll32 DLL Execution | Signed Binary Proxy Execution | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | High | [execution/iso-rundll32.spl](./execution/iso-rundll32.spl) |

### 🛡️ Defense Evasion

| Rule | Technique | ID | Severity | File |
|---|---|---|---|---|
| PowerShell Encoded Command Execution | Obfuscated Files or Information | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | High | [defense-evasion/encoded-powershell.spl](./defense-evasion/encoded-powershell.spl) |
| certutil Used as File Downloader (LOLBAS) | Signed Binary Proxy Execution | [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | Medium | [defense-evasion/certutil-download.spl](./defense-evasion/certutil-download.spl) |

---

## 📁 Repository Structure

```
splunk-detection-rules/
├── README.md
├── credential-access/
│   ├── password-spray.spl
│   ├── kerberoasting.spl
│   └── mimikatz-lsass.spl
├── persistence/
│   ├── scheduled-task.spl
│   ├── new-local-admin.spl
│   └── lnk-execution.spl
├── lateral-movement/
│   └── pass-the-hash.spl
├── execution/
│   ├── macro-child-process.spl
│   └── iso-rundll32.spl
└── defense-evasion/
    ├── encoded-powershell.spl
    └── certutil-download.spl
```

---

## 📖 Rule Format

Each `.spl` file follows this structure:

```
Title:        Rule name
MITRE ID:     Technique ID and link
Tactic:       ATT&CK tactic
Severity:     Low / Medium / High / Critical
Data Source:  wineventlog / sysmon
Event IDs:    Relevant Windows Event IDs
Description:  What this detects and why

--- SEARCH ---
[SPL query]

--- TUNING NOTES ---
[False positive sources and suppression logic]
```

---

## 🧪 Lab Environment

All rules were developed and validated in my SOC home lab:

| Component | Detail |
|---|---|
| SIEM | Splunk Enterprise 10.0.5 — Ubuntu 22.04 (10.10.10.13) |
| Log Sources | Windows Event Log, Sysmon (AD_LAB segment) |
| Domain Controller | Windows Server 2019 — ad.lab (10.80.80.2) |
| Clients | Windows 10 Enterprise x2 |
| Attack Host | Kali Linux (10.0.0.2) |

---

## 🔗 Related Repositories

- [SOC-Home-Lab](https://github.com/Qwortie/SOC-Home-Lab) — Lab environment these rules were developed in
- [Phishing-tickets](https://github.com/Qwortie/Phishing-tickets) — Phishing investigations that drove several of these rules
