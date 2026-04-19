# Capstone Report
## Scenario:

Ryan Adams, a local administrator at a small dental clinic, contacted the MahCyberDefense SOC hotline after suspecting his computer may have been compromised. He explained that around October 15 2025 at 13:00 UTC, his mouse was randomly moving so he became suspicious.
## Contexte 

As a SOC analyst, your task is to investigate this incident using Splunk. Analyze the available data to determine what occurred, identify any indicators of compromise, and document your findings in a SOC report using the provided format found in the community.

**SIEM**: Splunk
**Index:** `mydfir-soc`
**Timezone:** UTC
**Incident Date:** 15 October 2025
**Data Hour Range:** 12:00:11 => 13:10:07
**Files** : 

| Files           | Start    | End      | Event nb |
| --------------- | -------- | -------- | -------: |
| suricata.csv    | 12:00:11 | 13:10:07 |    1 607 |
| sysmon.csv      | 12:00:14 | 13:06:43 |    2 582 |
| zeek.csv        | 12:01:17 | 13:10:00 |    1 568 |
| security.csv    | 12:03:54 | 13:06:41 |    1 132 |
| system.csv      | 12:03:55 | 12:56:11 |       32 |
| defender.csv    | 12:22:07 | 12:56:28 |        9 |
| application.csv | 12:31:26 | 13:05:53 |       42 |
| powershell.csv  | 13:00:51 | 13:05:06 |       41 |

---
# **Analyse**

## Investigation Summary

The 15 October 2025 (UTC),`Ryan.Adams` account was compromised through a password-based attack targeting `FRONTDESK-PC1.KCD.local` from the IP address `172.16.0.184` via the RDP protocol. 

This initial access enabled the attacker to tamper Windows Defender, download a malicious payload `python.exe` from an malicious URL `http://157.245.46.190:9999/` without triggering any alert, and then execute it successfully on the host.

Once active, the payload established a stable Command & Control (C2) channel, to `157.245.46.190:8888` allowing the threat actor to remotely orchestrate and pilot subsequent phases of the attack. Network telemetry further suggests that `python.exe` performed internal reconnaissance targeting the domain controller, likely in preparation for lateral movement but no indicator of a domain controller compromise have been found in the available data set.

To ensure persistence, the attacker created a scheduled task `PythonUpdate` running under `SYSTEM` privileges, providing a consistent and privileged backdoor on the compromised host. Every time the computer restarts, this task will be launched automatically and a connection to the C2 server will be attempted.

## Scoping 

From a global perspective and based on the available data, `python.exe` and the scheduled task `PythonUpdate` exist exclusively on `FRONTDESK-PC1.KCD.local`.

`index="mydfir_soc" python.exe |stats count by Computer`
<img width="567" height="233" alt="image" src="https://github.com/user-attachments/assets/ed1d8719-8b7f-4af8-a7e9-97367c878d0a" />

`index="mydfir_soc" PythonUpdate |stats count by Computer`
<img width="1246" height="391" alt="image" src="https://github.com/user-attachments/assets/de894dab-3c2b-40b2-b46c-5de6c05a6463" />
The IP address `157.245.46.190` communicated exclusively with the machine `FRONTDESK-PC1` (`172.16.0.110`).

`index="mydfir_soc" 157.245.46.190 |stats count by src_ip, dest_ip`
<img width="1851" height="381" alt="image" src="https://github.com/user-attachments/assets/5f874132-fabf-4088-b98a-0a0067384064" />

No lateral movement was observed from the attacker's IP address `172.16.0.184` toward any other host.

`index="mydfir_soc" sourcetype="winevent:security" EventCode=4624 src_ip= "172.16.0.184" ComputerName!="FRONTDESK-PC1.KCD.local"`
<img width="775" height="356" alt="image" src="https://github.com/user-attachments/assets/e0c3812e-e678-46c4-b38a-6c515bd6cce0" />

No credential dumping was identified. No suspicious access to LSASS was observed.	

`index="mydfir_soc" sourcetype="sysmon" source="sysmon.csv" EventCode="10" TargetImage="*lsass.exe"`
<img width="1032" height="456" alt="image" src="https://github.com/user-attachments/assets/ccf9d3fd-265c-4dae-9c03-cb95676c863b" />
No Mimikatz artifacts were discovered.	

`index="mydfir_soc" sourcetype="sysmon" host="FRONTDESK-PC1" (CommandLine="*sekurlsa*" OR CommandLine="*mimikatz*" OR CommandLine="*lsadump*" OR CommandLine="*privilege::debug*") | table _time, Image, CommandLine, User | sort _time`
<img width="1334" height="431" alt="image" src="https://github.com/user-attachments/assets/e8f02b3d-cbf5-47a1-bdae-b5a18c0dd0b5" />


## Criticality, Impact, and Next Steps Prioritization

The incident is confirmed with the compromise of a local administrator account and a machine. Within the provided dataset, nothing indicates that the domain controller was compromised, nor that python.exe was installed on any other machine.

Since the local administrator account and machine were compromised, the first actions — prior to deep analysis and post-incident reflection — are:

- Investigate the IP address 172.16.0.184 — as per RFC 1918, this is an internal IP address. We therefore need to understand the root cause of the threat's initial access to the organization in order to properly scope the threat before taking action
- Containment of `FRONTDESK-PC1` by blocking ports at the switch or disconnecting the machine from the network without shutting it down
- Block IP `157.245.46.190` outbound on the firewall / proxy and block port 9999 on outgoing traffic
- Collection and preservation of all available data (firewall, proxy, endpoint...) to secure evidence, conduct threat hunting, and gather material for post-incident reflection
- Check other hosts — lateral movement toward the DC is possible
- Invalidate active sessions for the Ryan.Adams profile and reset the password in a robust manner for all targeted accounts, with particular attention to high-privilege accounts
- Re-image `FRONTDESK-PC1` (if possible), or remove the scheduled task, kill the malicious process, re-enable Defender and run a full scan

## CyberKillChain : IOA/IOC
| IOA (Behavior) | Kill Chain Phase | MITRE Technique | IOC (Artifact) | SPL |
|---|---|---|---|---|
| High volume of failed login attempts across multiple accounts, followed by a success | Initial Access | T1110 — Brute Force | Administrator: 33× ID4625/7s — Guest: 31× EventCode4625/8s — Andrew.Henderson: 34× EventCode4625/8s — Ryan.Adams: 62× EventCode4625/49s followed by 8× EventCode4624 within 3 min / Attacking IP: `172.16.0.184` / Attacking machine: `DESKTOP-924H12` | `index="mydfir_soc" sourcetype="winevent:security" EventCode IN (4625) \|stats count by user`<br><br>`index="mydfir_soc" sourcetype="winevent:security" EventCode IN (4624) user="ryan.adams" 172.16.0.184 \|table _time src_ip Elevated_Token Logon_type EventCode Logon_ID`<br><br>`index="mydfir_soc" sourcetype="sysmon" EventCode=3 \| stats count by src_ip, DestinationIp, DestinationPort, Image \| where count > 20 \| sort - count` |
| Deliberate disabling of Windows Defender before any offensive action | Defense Evasion | T1562.001 — Impair Defenses | Defender logs — Real-time protection disabled — EventCode=5001 | `index="mydfir_soc" sourcetype="WinEvent:Defender" source="defender.csv" \| table _time raw` |
| Download of an executable from a suspicious IP via Chrome | Delivery | T1105 — Ingress Tool Transfer | Source IP: `157.245.46.190:9999` — File: `python.exe` → `C:\Users\Ryan.Adams\Music\` | `index="mydfir_soc" sourcetype="suricata" alert_signature="*" Download`<br><br>`index="mydfir_soc" sourcetype="Sysmon" source="sysmon.csv" EventCode=11 python.exe` |
| Execution of the downloaded file by the user | Execution | T1204.002 — User Execution: Malicious File | Sysmon EventCode 1 — process spawned from `Music\` / MD5=`DE070C106BD0EB0E092F31A2C4285020` / SHA256=`CFFAB896E9F0B12101034D9CED76332EF5AA4036AFA08E940E825E277C21A044` | `index="mydfir_soc" sourcetype="sysmon" source="sysmon.csv" python EventID IN (7,1,3) \|table _time EventID src_ip dest_ip ProcessId Image ImageLoaded Hashes Signed Signature SignatureStatus` |
| Outbound connection to a public IP flagged as a threat | Command & Control | T1071 — Application Layer Protocol | `157.245.46.190:8888` | `index="mydfir_soc" sourcetype="sysmon" source="sysmon.csv" python EventID IN (7,1,3) \|table _time EventID src_ip dest_ip ProcessId Image ImageLoaded Hashes Signed Signature SignatureStatus` |
| Internal DNS resolution — Domain Controller reconnaissance | Command & Control | T1018 — Remote System Discovery | `172.16.0.7` / `python.exe` | `index="mydfir_soc" sourcetype="sysmon" source="sysmon.csv" 172.16.0.7 python.exe \|table Image QueryName QueryResults User Computer` |
| Creation of a scheduled task to ensure persistence | Persistence | T1053.005 — Scheduled Task | Task `PythonUpdate` — EventCode 4104 / Command: `schtasks.exe /create /tn "PythonUpdate" /tr "C:\Users\Ryan.Adams\Music\python.exe" /sc onstart /ru SYSTEM /f` | `index="mydfir_soc" sourcetype="winevent:powershell" source="powershell.csv" schtasks \|table ScriptBlock_ID _time EventCode Message` |

## Timeline 
- Brute Force
  - 12:51:44=>12:52:57 : Multiple profile connection failures in less than 30 seconds
    <img width="1840" height="711" alt="image" src="https://github.com/user-attachments/assets/17353dc4-1e78-4e30-aac7-b4f6901f49bd" />
  - 12:52:12 : Connection confirmed from IP `172.16.0.184` with admin privileges on Ryan's profile
    <img width="1846" height="457" alt="image" src="https://github.com/user-attachments/assets/72a9d9de-cc75-4c13-82b9-345ff9cd4d59" />
- Modification Defender
  - 12:55:50 : Real time protection scanning disabled on FRONTDESK-PC1
    <img width="1853" height="745" alt="image" src="https://github.com/user-attachments/assets/60977dfa-38e2-4008-a8c2-86a7b4103968" />
- Python.exe dowload
  - 12:59:26: File downloaded via an HTTP request with a successful **GET 200** response on **FRONTDESK-PC1**
    <img width="1875" height="846" alt="image" src="https://github.com/user-attachments/assets/b08427c4-e95c-4683-9c97-1139e1baa618" />
- Execution of `python.exe`
  - 13:00:33: ID1/ID7: `python.exe` loaded from the **Music** directory.
    <img width="1855" height="427" alt="image" src="https://github.com/user-attachments/assets/5e5fa1a1-6f34-48df-b6d2-c376f0da1780" />
- C2 Connection and Domain Controller Reconnaissance:
  - 13:00:34— **ID3**: Outbound connection to `157.245.46.190:8888`
  - 13:00:35— **ID3**: Outbound connection to `172.16.0.7:49669`
    <img width="1860" height="464" alt="image" src="https://github.com/user-attachments/assets/3cde397f-9008-4279-8aed-a20654d85f9e" />
- Scheduled task created.
  - 13:04:16 : PowerShell execution and creation of a scheduled job
	<img width="1862" height="209" alt="image" src="https://github.com/user-attachments/assets/f8aa24b7-ee8a-47d8-9e8d-7cb6b666d78a" />

## Reputation Analysis

### File Hash Reputation

#### TalosIntelligence

<img width="1273" height="853" alt="image" src="https://github.com/user-attachments/assets/5b0ac242-38e9-4838-8705-8bf4ec4a7154" />
- Disposition: Unknown
- Detection Name: Not found
- Associated Domains: None

The absence of classification suggests low distribution or custom tooling.

### Infrastructure Reputation

#### VirusTotal
 http://157.245.46.190:9999/ 
 
<img width="1394" height="683" alt="image" src="https://github.com/user-attachments/assets/03705b4d-3624-4610-b7a0-fdf793a02bd0" />
- 11/98 vendors flagged as malicious
- Classification: Malware / Malicious

#### AbuseIPDB
<img width="1398" height="849" alt="image" src="https://github.com/user-attachments/assets/c006d8a4-12c2-4509-85be-1a5e56f81fd9" />
- Reported 115 times
- 29 distinct reporters
- Categories: Hacking, Port Scanning, DNS Compromise
- ISP: DigitalOcean LLC

Multiple independent sources classify the IP as malicious

# Continuous improvement

### MFA on RDP

No second factor was in place despite RDP being exposed internally. Enforce MFA on all RDP endpoints — intra-LAN exposure is a real vector as demonstrated by this incident. Restrict RDP access to a dedicated jump host or VPN gateway.

### Account Lockout Policy

49 failed attempts on Ryan.Adams triggered no lockout. Configure GPO lockout threshold at 5–10 attempts / 10-minute observation window. Pair with a SIEM alert on 4625 bursts from a single source IP to catch slow-and-low variants that stay under the lockout threshold.

### Brute Force Detection

162 EventCode 4625 and 573 EventCode 4776 events went unalerted. Create a correlation rule: N failed logons from a single IP across multiple accounts within a time window, followed by a 4624 success. Include 4776 (NTLM) in scope 

### Defense Tampering Detection

Defender Real-Time Protection was disabled (EventCode 5001) with no alert. 5001 and 5007 should be P1 near-real-time alerts — there is no legitimate reason for this to occur outside a maintenance window. Enable Tamper Protection via Microsoft Defender for Endpoint to block programmatic disabling entirely.

### Non-Signed Executable Detection

`python.exe` executed from `Music\`, unsigned, with a Zone.Identifier ADS confirming internet origin — none of this triggered an alert. Build a compound detection rule: execution from a user-writable non-standard path + unsigned binary + Zone.Identifier present (Sysmon EID 1, 7, 15). 
