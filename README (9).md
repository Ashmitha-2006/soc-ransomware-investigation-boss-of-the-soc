# 🔍 Splunk BOTS v1 — Scenario 2: Cerber Ransomware Investigation

![Splunk](https://img.shields.io/badge/Splunk-SIEM-black?style=for-the-badge&logo=splunk&logoColor=green)
![Score](https://img.shields.io/badge/Score-6%2C321%20pts-brightgreen?style=for-the-badge)
![Questions](https://img.shields.io/badge/Questions-12%2F12%20Correct-brightgreen?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-BOTS%20v1-blue?style=for-the-badge)
![Malware](https://img.shields.io/badge/Malware-Cerber%20Ransomware-red?style=for-the-badge)

> **A full forensic investigation of a Cerber ransomware attack using Splunk SIEM, Sysmon, Suricata IDS, and Windows Event Logs — documenting the complete attack chain from USB baiting to encrypted file recovery.**

---

## 📋 Table of Contents

- [Scenario Overview](#-scenario-overview)
- [Environment & Infrastructure](#-environment--infrastructure)
- [Attack Timeline](#-attack-timeline)
- [Investigation — Full Q&A with Methodology](#-investigation--full-qa-with-methodology)
- [Attacker TTPs — MITRE ATT&CK](#-attacker-ttps--mitre-attck)
- [Real-Life Impact](#-real-life-impact)
- [Skills Demonstrated](#-skills-demonstrated)
- [Key SPL Searches Reference](#-key-spl-searches-reference)
- [Lessons Learned](#-lessons-learned)
- [Score Summary](#-score-summary)

---

## 🎯 Scenario Overview

Alice, a new SOC analyst at **Wayne Corp**, discovers an unaddressed **critical** incident ticket that had been sitting in the queue unresolved. On **August 24th, 2016**, employee **Bob Smith** returned to his desk to find:

- 🔊 Speakers blaring a ransom audio warning
- 🖥️ Desktop wallpaper replaced with a ransom note
- 🔒 All files inaccessible and encrypted

After interviewing Bob, Alice discovers he had found a **USB drive in the parking lot**, plugged it into his workstation `we8105desk`, and opened a file named `Miranda_Tate_unveiled.dotm` — a malicious Word document containing a macro that silently deployed **Cerber ransomware**.

Alice begins a full **SIEM-based forensic investigation** using Splunk to reconstruct the entire attack chain.

---

## 🖥️ Environment & Infrastructure

| Asset | Value |
|-------|-------|
| **Victim Workstation** | `we8105desk` (Windows 10) |
| **Victim User** | `WAYNECORPINC\bob.smith` |
| **Victim IP** | `192.168.250.100` |
| **File Server** | `we9041srv` |
| **File Server IP** | `192.168.250.20` |
| **IDS System** | `suricata-ids.waynecorpinc.local` |
| **Domain** | `waynecorpinc.local` |
| **Infection Date** | August 24, 2016 |
| **Malware Family** | Cerber Ransomware |
| **Splunk Index** | `botsv1` |

### All Hosts Discovered in the Environment

![Hosts Overview](screenshots/hosts_overview.png)

> Running `index=botsv1 | stats count by host` reveals every asset logging to Splunk — a critical first step in any SIEM investigation to understand the full environment scope.

---

## ⏱️ Attack Timeline

```
16:42:17  Bob plugs USB drive (MIRANDA_PRI) into we8105desk
          └─ Windows Registry logs insertion under HKLM\SYSTEM\...\USBSTOR

16:48:12  Malicious macro executes → first C2 callout to solidaritedeproximite.org
          └─ DNS query observed in stream:dns logs

16:48:16  DNS resolves C2 IP addresses (reverse PTR lookups)
          └─ 150.37.187.37 and 182.104.222.92

16:48:21  WScript.exe (PID 3968) launches 20429.vbs
          └─ 4,490-char obfuscated VBScript executes

16:48:21  cmd.exe (PID 1476) spawned → drops and launches 121214.tmp (PID 2948)
          └─ Cerber cryptor begins execution

16:48:41  File encryption begins
          └─ 406 .txt files encrypted in Bob's Windows profile
          └─ 257 PDF files encrypted on file server we9041srv
          └─ taskkill used to clean up process traces

17:15:12  Cerber phones home → DNS query for cerberhhyed5frqa.xmfir0.win
          └─ Encryption complete — victim directed to ransom payment portal
```

---

## 🔬 Investigation — Full Q&A with Methodology

---

### Q1 | #200 — What was the most likely IPv4 address of we8105desk on 24AUG2016?

**✅ Answer: `192.168.250.100`**

**SPL Search:**
```spl
index=botsv1 host=we8105desk
| stats count by src_ip
| sort - count
```

**Methodology:**
Filtered all Splunk events by the known hostname `we8105desk` and grouped results by source IP address. In a Windows environment, a workstation retains the same IP throughout the day — the IP appearing with the highest event count across all log sources is the machine's actual address. `192.168.250.100` dominated with **23,929 events**, anchoring all subsequent investigation searches.

| Screenshot | Description |
|-----------|-------------|
| ![Q1 Methodology](screenshots/q1_methodology.png) | `src_ip` stats showing `192.168.250.100` dominating with 23,929 events |
| ![Q1 Answer](screenshots/q1_answer.png) | BOTS #200 — Confirmed correct (100/100 pts) |

---

### Q2 | #201 — Which Suricata signature alerted the fewest times? (7-digit ID)

**✅ Answer: `2816763`**

**SPL Search:**
```spl
index=botsv1 sourcetype="suricata" src=192.168.250.100
| stats count by alert.signature_id, alert.signature
| sort + count
```

**Methodology:**
Filtered Suricata IDS logs to only traffic originating from Bob's infected machine, grouped by signature ID and name, then sorted **ascending** by count. Three Cerber-related signatures were detected — `2816763` (ETPRO TROJAN Ransomware/Cerber Checkin 2) fired only **once**, making it the answer. Sorting ascending (`sort + count`) puts the lowest-firing signature at the top of the results instantly.

| Screenshot | Description |
|-----------|-------------|
| ![Q2 Methodology](screenshots/q2_methodology.png) | Three Cerber signatures sorted by count — `2816763` at count=1 |
| ![Q2 Answer](screenshots/q2_answer.png) | BOTS #201 — Confirmed correct (100/100 pts) |

---

### Q3 | #202 — What FQDN does Cerber direct the user to at the end of its encryption phase?

**✅ Answer: `cerberhhyed5frqa.xmfir0.win`**

**SPL Search:**
```spl
index=botsv1 src=192.168.250.100 sourcetype="stream:dns" query="*.win"
| table _time, query
| sort _time asc
```

**Methodology:**
Cerber's final action after encrypting all files is to resolve a DNS name for the payment portal — the victim's browser is then directed there to pay the ransom. Filtering DNS logs for the `.win` TLD (virtually never seen in legitimate corporate traffic) immediately surfaced the FQDN at exactly `17:15:12` — the final event in the attack timeline.

> 💡 **Pro Tip:** Shannon entropy analysis using the URL Toolbox app (`| eval ut_shannon(query{})`) is an advanced method to surface algorithmically-generated C2 domains like this one, which have abnormally high entropy scores compared to legitimate domain names.

| Screenshot | Description |
|-----------|-------------|
| ![Q3 Methodology](screenshots/q3_methodology.png) | `stream:dns` filtered for `*.win` — domain appears at `17:15:12` |
| ![Q3 Answer](screenshots/q3_answer.png) | BOTS #202 — Confirmed correct (485/500 pts) |

---

### Q4 | #203 — What was the first suspicious domain visited by we8105desk on 24AUG2016?

**✅ Answer: `solidaritedeproximite.org`**

**SPL Search:**
```spl
index=botsv1 src=192.168.250.100 sourcetype="stream:dns"
earliest="08/24/2016:00:00:00" latest="08/25/2016:00:00:00"
| table _time, query
| sort _time asc
```

**Methodology:**
Sorted all DNS queries from Bob's machine chronologically and analysed each entry against known-normal Windows background traffic patterns:

| Time | Query | Classification |
|------|-------|----------------|
| `16:34:53` | `67.188.63.23.in-addr.arpa` | ✅ Normal — PTR reverse DNS lookup |
| `16:42:36` | `FHEFDJDADEDBFDFCFG...` | ✅ Normal — NetBIOS/LLMNR name resolution |
| `16:42:36` | `_ldap._tcp.pdc._msdcs.waynecorpinc.local` | ✅ Normal — Active Directory LDAP lookup |
| **`16:48:12`** | **`solidaritedeproximite.org`** | **🚨 SUSPICIOUS — First external C2 callout** |

Everything before `16:48:12` was standard OS background noise. `solidaritedeproximite.org` ("solidarity of proximity" in French) had zero relevance to Wayne Corp and was triggered **seconds after Bob opened the malicious `.dotm` file**.

| Screenshot | Description |
|-----------|-------------|
| ![Q4 Methodology](screenshots/q4_methodology.png) | DNS timeline — normal traffic then `solidaritedeproximite.org` at `16:48:12` |
| ![Q4 Answer](screenshots/q4_answer.png) | BOTS #203 — Confirmed correct (970/1000 pts) |

---

### Q5 | #204 — What is the length of the VBScript CommandLine field?

**✅ Answer: `4490` characters**

**SPL Search:**
```spl
index=botsv1 host=we8105desk
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
CommandLine="*.vbs*"
| eval script_length=len(CommandLine)
| table script_length, CommandLine
```

**Methodology:**
Sysmon **Event ID 1** (Process Creation) logs the full `CommandLine` field — which includes both the launching executable name AND the entire inline script content. This is exactly what the question asks for: the `.exe` prepended to the script. Using Splunk's `len()` eval function calculates the exact character count programmatically. The obfuscated VBScript (`20429.vbs`) executed by `WScript.exe` produced a CommandLine of exactly **4,490 characters** — the obfuscation is clearly visible in the raw field output.

| Screenshot | Description |
|-----------|-------------|
| ![Q5 Methodology](screenshots/q5_methodology.png) | `len(CommandLine) = 4490` — full obfuscated VBScript content visible |
| ![Q5 Answer](screenshots/q5_answer.png) | BOTS #204 — Confirmed correct (965/1000 pts) |

---

### Q6 | #205 — What is the name of the USB key inserted by Bob Smith?

**✅ Answer: `MIRANDA_PRI`**

**SPL Search:**
```spl
index=botsv1 host=we8105desk sourcetype="WinRegistry" USBSTOR
| search registry_value_data="*MIRANDA*"
| table _time, registry_value_data
```

**Methodology:**
Windows automatically logs USB device insertions in the Registry under `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, capturing the device's friendly name, vendor, and product information. Searching the `WinRegistry` sourcetype for USBSTOR-related keys at the time of insertion (`16:42:17`) revealed the device name `MIRANDA_PRI` — deliberately chosen by the attacker to match the social engineering lure in the document filename `Miranda_Tate_unveiled.dotm`.

| Screenshot | Description |
|-----------|-------------|
| ![Q6 Methodology](screenshots/q6_methodology.png) | WinRegistry USBSTOR keys — `MIRANDA_PRI` confirmed at `16:42:17` |
| ![Q6 Answer](screenshots/q6_answer.png) | BOTS #205 — Confirmed correct (900/1000 pts) |

---

### Q7 | #206 — What is the IPv4 address of the file server Bob was connected to?

**✅ Answer: `192.168.250.20`**

**SPL Search:**
```spl
index=botsv1 host=we8105desk
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 DestinationPort=445
| stats count by DestinationHostname, DestinationIp
```

**Methodology:**
Sysmon **EventCode 3** (Network Connection) captures all outbound network connections with full source/destination detail. Filtering for **port 445** (SMB — Windows file sharing protocol) from Bob's workstation revealed `we9041srv` at `192.168.250.20` as the sole internal file server destination. The 30 connection events recorded indicate Cerber was actively hammering this server, attempting to encrypt every accessible network share.

| Screenshot | Description |
|-----------|-------------|
| ![Q7 Methodology](screenshots/q7_methodology.png) | Sysmon EventCode=3, Port 445 → `WE9041SRV` at `192.168.250.20` |
| ![Q7 Answer](screenshots/q7_answer.png) | BOTS #206 — Confirmed correct |

---

### Q8 | #207 — How many distinct PDFs did the ransomware encrypt on the remote file server?

**✅ Answer: `257`**

**SPL Search:**
```spl
index=botsv1 host=we9041srv sourcetype="WinEventLog:Security"
EventCode=5145 RelativeTargetName="*.pdf"
| stats dc(RelativeTargetName) as distinct_pdfs
```

**Methodology:**
Windows Security **EventCode 5145** ("A network share object was accessed") is logged on the **file server** every time a remote client reads or writes a file on a share. Because Cerber touches each file during encryption, every encrypted file generates a 5145 event. Targeting `we9041srv`, filtering for `.pdf` extensions, and using `dc()` (distinct count) on `RelativeTargetName` returns the exact count of unique PDFs encrypted.

> ⚠️ **Key Insight:** Using SMB sourcetype (`sourcetype="stream:smb"`) was a red herring — Windows Security logs on the **server** are the correct and more granular data source for this question.

![Q8 Answer](screenshots/q8_answer.png)

---

### Q9 | #208 — What is the ParentProcessId of the initial 121214.tmp launch?

**✅ Answer: `3968`**

**SPL Search:**
```spl
index=botsv1 host=we8105desk
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
CommandLine="*121214.tmp*"
| table _time, ProcessId, ParentProcessId, CommandLine, ParentCommandLine
```

**Process Execution Chain:**

| Time | PID | Parent PID | Process | Notes |
|------|-----|-----------|---------|-------|
| `16:48:21` | `3968` | — | `WScript.exe` → `20429.vbs` | VBScript executor |
| `16:48:21` | `1476` | **`3968`** | `cmd.exe /C START 121214.tmp` | Spawned by WScript |
| `16:48:21` | `2948` | `1476` | `121214.tmp` | **Initial cryptor launch** |
| `16:48:29` | `3828` | `2948` | `121214.tmp` | Child process |

**Methodology:**
Searched for all Sysmon process creation events referencing `121214.tmp` and displayed the full process lineage. Tracing backwards up the parent chain: `121214.tmp` (2948) → `cmd.exe` (1476) → `WScript.exe` **(3968)**. The question asks for the ParentProcessId of the *initial* launch — tracing to the root of the chain identifies `3968` as the originating process that set the entire execution in motion.

| Screenshot | Description |
|-----------|-------------|
| ![Q9 Methodology](screenshots/q9_methodology.png) | Full process chain — WScript (3968) → cmd (1476) → 121214.tmp (2948) |
| ![Q9 Answer](screenshots/q9_answer.png) | BOTS #208 — Confirmed correct |

---

### Q10 | #209 — How many .txt files does Cerber encrypt in Bob's Windows profile?

**✅ Answer: `406`**

**SPL Search:**
```spl
index=botsv1 host=we8105desk
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=2 TargetFilename="*bob.smith*" TargetFilename="*.txt"
| stats dc(TargetFilename) as distinct_txt
```

**Methodology:**
Sysmon **EventCode 2** (File Creation Time Changed) is the definitive forensic indicator of ransomware activity — ransomware modifies file timestamps as part of the encryption and rename process. Filtering by `*bob.smith*` scopes results to Bob's Windows user profile directory, and `*.txt` isolates text files. Using `dc()` (distinct count) ensures each uniquely-named file is only counted once, returning **406 distinct .txt files** encrypted.

| Screenshot | Description |
|-----------|-------------|
| ![Q10 Methodology](screenshots/q10_methodology.png) | Sysmon EventCode=2 + `*bob.smith*` + `*.txt` → `dc() = 406` |
| ![Q10 Answer](screenshots/q10_answer.png) | BOTS #209 — Confirmed correct (380/500 pts) |

---

### Q11 | #210 — What is the name of the file containing the Cerber cryptor code?

**✅ Answer: `mhtr.jpg`**

**SPL Search:**
```spl
index=botsv1 src=192.168.250.100 sourcetype="stream:http" http_method=GET
| stats count by uri_path
| sort - count
```

**Methodology:**
Examined all HTTP GET requests from Bob's machine — the method used to download external files. The majority of traffic was legitimate Windows Update downloads (`.cab`, `.crl` certificate files). `mhtr.jpg` immediately stood out: a random, meaningless filename downloaded from the C2 domain `solidaritedeproximite.org` with no legitimate business context. Despite the `.jpg` extension, this file contained the Cerber ransomware cryptor code concealed via **steganography**.

| Screenshot | Description |
|-----------|-------------|
| ![Q11 Methodology](screenshots/q11_methodology.png) | HTTP GET log — `/mhtr.jpg` anomalous among Windows Update traffic |
| ![Q11 Answer](screenshots/q11_answer.png) | BOTS #210 — Confirmed correct |

---

### Q12 | #211 — What obfuscation technique does the encryptor file likely use?

**✅ Answer: `steganography`**

**Methodology:**
No Splunk search required — this is an applied forensics concepts question. The Cerber cryptor was delivered inside `mhtr.jpg`, a file that appears to be a standard JPEG image to any casual inspection or file extension filter. **Steganography** is the practice of concealing executable code or data within innocent-looking carrier files — images, audio files, PDFs, or documents. This technique is specifically designed to bypass security controls that block `.exe` or script file downloads while permitting image transfers. The `.jpg` extension also avoids triggering AV signatures that scan for known malicious file types.

![Q12 Answer](screenshots/q12_answer.png)

---

## 🎭 Attacker TTPs — MITRE ATT&CK

| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|---------|
| **Initial Access** | T1091 | Replication Through Removable Media | USB drive planted in parking lot |
| **Execution** | T1204.002 | User Execution: Malicious File | `Miranda_Tate_unveiled.dotm` opened by Bob |
| **Execution** | T1059.005 | Command & Scripting: Visual Basic | `20429.vbs` executed by `WScript.exe` |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | 4,490-char obfuscated VBScript |
| **Defense Evasion** | T1027.003 | Steganography | Cryptor code hidden inside `mhtr.jpg` |
| **Command & Control** | T1071.001 | Web Protocols | HTTP beacon to `solidaritedeproximite.org` |
| **Command & Control** | T1568 | Dynamic Resolution | `.win` TLD for payment portal FQDN |
| **Impact** | T1486 | Data Encrypted for Impact | 406 .txt + 257 PDFs encrypted |
| **Impact** | T1490 | Inhibit System Recovery | `taskkill` used to eliminate process traces |

---

## 💥 Real-Life Impact

### Quantified Damage

| Metric | Value |
|--------|-------|
| Files encrypted (Bob's profile) | 406 `.txt` files |
| Files encrypted (file server) | 257 `.pdf` files |
| Workstations compromised | 1 (`we8105desk`) |
| Time from USB insertion to full encryption | ~27 minutes |
| Incident ticket response delay | >24 hours |

### Business Risk Assessment

| Risk Category | Description | Severity |
|--------------|-------------|----------|
| **Data Loss** | Bob's entire profile + 257 corporate PDFs inaccessible without paying ransom | 🔴 Critical |
| **Business Disruption** | Corporate file server shares encrypted — all connected users potentially impacted | 🔴 Critical |
| **Financial Exposure** | Bitcoin ransom demanded via `cerberhhyed5frqa.xmfir0.win` payment portal | 🟡 High |
| **Lateral Movement** | Cerber actively scanned and targeted `we9041srv` network shares | 🟡 High |
| **Incident Response Failure** | Critical ticket sat unaddressed — ransomware fully executed before detection | 🔴 Critical |

---

## 🛡️ Skills Demonstrated

### SIEM & Log Analysis
- Multi-sourcetype correlation across **Sysmon, Suricata, WinEventLog:Security, stream:dns, stream:http, WinRegistry**
- Forensic timeline reconstruction from disparate log sources across a 40-minute attack window
- Raw event field identification and extraction without pre-built dashboards

### Threat Hunting
- DNS anomaly detection using TLD-based filtering (`.win`)
- Process parent-child chain tracing for malware execution analysis
- Ransomware file activity detection using Sysmon EventCode 2 (timestamp modification)
- Network share forensics using Windows Security EventCode 5145
- USB artifact forensics via Windows Registry analysis

### Splunk SPL
- `stats`, `dc()`, `eval len()`, `sort`, `table`, `search`, `regex`
- Multi-condition field filtering
- Time-scoped investigations with `earliest`/`latest`
- Cross-sourcetype pivoting to follow attack chain
- `sort + count` (ascending) vs `sort - count` (descending) for different investigation needs

### Security Concepts Applied
- Ransomware infection chain reconstruction (delivery → execution → encryption → C2)
- MITRE ATT&CK framework mapping of observed TTPs
- Steganography identification and evasion technique analysis
- Shannon entropy for high-entropy domain detection
- Social engineering attack vector analysis (USB baiting)
- Distinguishing normal Windows background traffic from malicious indicators

---

## 🔑 Key SPL Searches Reference

```spl
-- Q1: Find infected machine IP
index=botsv1 host=we8105desk
| stats count by src_ip | sort - count

-- Q2: Find Cerber Suricata signatures by alert frequency
index=botsv1 sourcetype="suricata" src=192.168.250.100
| stats count by alert.signature_id, alert.signature | sort + count

-- Q3: Find ransomware C2 domain at end of encryption
index=botsv1 src=192.168.250.100 sourcetype="stream:dns" query="*.win"
| table _time, query | sort _time asc

-- Q4: Find first suspicious DNS callout
index=botsv1 src=192.168.250.100 sourcetype="stream:dns"
earliest="08/24/2016:00:00:00" | table _time, query | sort _time asc

-- Q5: Calculate VBScript CommandLine length
index=botsv1 host=we8105desk CommandLine="*.vbs*"
| eval script_length=len(CommandLine) | table script_length, CommandLine

-- Q6: Find USB device name from Registry
index=botsv1 host=we8105desk sourcetype="WinRegistry" USBSTOR
| search registry_value_data="*MIRANDA*" | table _time, registry_value_data

-- Q7: Find file server via SMB connections
index=botsv1 host=we8105desk EventCode=3 DestinationPort=445
| stats count by DestinationHostname, DestinationIp

-- Q8: Count distinct PDFs encrypted on file server
index=botsv1 host=we9041srv sourcetype="WinEventLog:Security"
EventCode=5145 RelativeTargetName="*.pdf"
| stats dc(RelativeTargetName) as distinct_pdfs

-- Q9: Trace 121214.tmp process execution chain
index=botsv1 host=we8105desk CommandLine="*121214.tmp*"
| table _time, ProcessId, ParentProcessId, CommandLine, ParentCommandLine

-- Q10: Count .txt files encrypted in user profile
index=botsv1 host=we8105desk EventCode=2
TargetFilename="*bob.smith*" TargetFilename="*.txt"
| stats dc(TargetFilename) as distinct_txt

-- Q11: Find malicious file download via HTTP
index=botsv1 src=192.168.250.100 sourcetype="stream:http" http_method=GET
| stats count by uri_path | sort - count
```

---

## 📚 Lessons Learned

1. **USB baiting is highly effective** — Leaving a USB drive in a parking lot requires zero technical skill from the attacker but exploits natural human curiosity. Organizations should enforce **removable media policies** and **disable autorun** across all endpoints.

2. **Macro security is non-negotiable** — A single `.dotm` file triggered an entire ransomware chain. Microsoft Office should be configured to **block all macros from untrusted sources** via Group Policy.

3. **Always set "All Time" in Splunk** — The most common investigative mistake is leaving the default 24-hour time window, causing all historical results to show zero. Always verify time range before concluding "no data."

4. **Malware hides in plain sight** — `mhtr.jpg` looked like an innocent image download. Security tools must inspect **file content and entropy**, not just extensions or MIME types.

5. **Critical tickets demand immediate action** — This ticket sat unaddressed for over 24 hours, allowing Cerber to fully execute. **SLA enforcement for critical severity incidents** is essential — every minute matters in ransomware response.

6. **EventCode 5145 > SMB for file forensics** — For quantifying files encrypted on a network share, Windows Security EventCode 5145 provides far more accurate and granular data than SMB traffic analysis.

7. **Shannon entropy reveals C2 domains** — Algorithmically generated domains like `cerberhhyed5frqa.xmfir0.win` have abnormally high entropy. Adding Shannon entropy analysis to DNS hunting playbooks surfaces these immediately.

---

## 🏆 Score Summary

| BOTS # | Topic | Answer | Points | Max |
|--------|-------|--------|--------|-----|
| #200 | Victim IP Address | `192.168.250.100` | 100 | 100 |
| #201 | Suricata Signature ID | `2816763` | 100 | 100 |
| #202 | Encryption FQDN | `cerberhhyed5frqa.xmfir0.win` | 485 | 500 |
| #203 | First Suspicious Domain | `solidaritedeproximite.org` | 970 | 1,000 |
| #204 | VBScript Field Length | `4490` | 965 | 1,000 |
| #205 | USB Key Name | `MIRANDA_PRI` | 900 | 1,000 |
| #206 | File Server IP | `192.168.250.20` | 91 | 100 |
| #207 | Distinct PDFs Encrypted | `257` | 390 | 500 |
| #208 | ParentProcessId | `3968` | 77 | 100 |
| #209 | .txt Files Encrypted | `406` | 380 | 500 |
| #210 | Cryptor File Name | `mhtr.jpg` | 373 | 500 |
| #211 | Obfuscation Technique | `steganography` | 1,490 | 2,000 |
| | **TOTAL** | | **6,321** | **8,400** |

---

*Investigation conducted on the Splunk BOTS v1 dataset — a real-world attack simulation dataset used for SOC analyst training and blue team skill development.*
