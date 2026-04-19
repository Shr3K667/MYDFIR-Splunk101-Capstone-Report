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
- Python.exe dowload
- Execution of `python.exe`
- C2 Connection and Domain Controller Reconnaissance:
- Scheduled task created.
	
