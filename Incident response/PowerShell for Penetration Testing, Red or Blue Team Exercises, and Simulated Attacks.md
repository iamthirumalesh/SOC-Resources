# PowerShell for Penetration Testing, Red/Blue Team Exercises, and Simulated Attacks


## Detailed Analysis – PowerShell for Penetration Testing, Red or Blue Team Exercises, and Simulated Attacks

### Objective

**Detect, audit, and monitor the use of PowerShell during legitimate penetration tests or red team assessments.** This includes identifying simulated attacks, post-exploitation scenarios, and ensuring defensive teams can distinguish between authorized testing activities and real threats.

### Common Penetration Testing Use Cases

- **Reconnaissance:** Automating domain/user/group discovery with PowerShell.
- **Vulnerability Scanning:** Running scan scripts against endpoints and network assets.
- **Exploitation \& Privilege Escalation:** Attempting privilege escalation, token manipulation, or exploitation of misconfigurations using PowerShell.
- **Persistence \& Evasion:** Simulating attacker methods for persistence or defense evasion—scheduled tasks, registry autoruns, security control modifications.
- **Lateral Movement:** Testing lateral movement techniques and how defenders respond.
- **Reporting \& Documentation:** Aggregating findings and evidence via PowerShell data collection[^7_1].


### Detection Logic: SIEM/EDR Use Case

**Key Observables:**

- Unusual frequency of PowerShell script execution (especially those using encoded/obfuscated commands).
- Execution of PowerShell by pen testers’ accounts from jump-boxes or admin workstations.
- Known attack simulation frameworks (e.g., Cobalt Strike, Empire, PoshC2) emitting telltale patterns.
- Use of domain discovery, persistence, lateral movement, or defense evasion cmdlets/flags typical of simulated attacks.


## Detecting PowerShell Attack Simulations in SIEM/EDR

### **Splunk (SPL) Queries**

#### PowerShell ScriptBlock and Offensive Tool Detection

```splunk
index=main (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" OR EventCode=4104)
(ScriptBlockText="*Invoke-Mimikatz*" OR ScriptBlockText="*Empire*" OR ScriptBlockText="*Invoke-Obfuscation*" OR ScriptBlockText="*CobaltStrike*" OR ScriptBlockText="*Get-Domain*" OR ScriptBlockText="*powersploit*" OR ScriptBlockText="*Invoke-*" OR ScriptBlockText="*Invoke-Shellcode*")
```


#### High Volume/Spike of PowerShell Commands (Test Automation/Simulation)

```splunk
index=main process_name="powershell.exe"
| timechart count by user span=15m
| where count>100
```


### **CrowdStrike Falcon Query Examples**

#### Detect Use of Known Pen-Test Frameworks or Post-Exploitation Scripts

```crowdstrike
event_simpleName=ProcessRollup2
| search TargetFileName="powershell.exe"
AND (CommandLine="*Invoke-Mimikatz*" OR CommandLine="*Empire*" OR CommandLine="*Cobalt*" OR CommandLine="*Invoke-Shellcode*" OR CommandLine="*PowerUp*" OR CommandLine="*Invoke-Privesc*")
```


#### Detect PowerShell Run by Pen-Tester User Accounts/Jump Boxes

```crowdstrike
event_simpleName=ProcessRollup2
| search TargetFileName="powershell.exe" AND (UserName="pentest_account" OR DeviceName="pentest-jumphost")
```


### **ELK Stack (Lucene) Queries**

#### Pen-Testing/Simulated Attack Detection via Keywords

```lucene
process_name:"powershell.exe" AND process_command_line:("Invoke-Mimikatz" OR "Empire" OR "Cobalt" OR "Invoke-Shellcode" OR "Invoke-Obfuscation" OR "PowerUp" OR "Invoke-Privesc" OR "powersploit")
```


#### Spike Detection: Many PowerShell Scripts in Short Time

```lucene
process_name:"powershell.exe"
```

*Correlate with event frequency analytics to map bursts indicating pen-test activity.*

## Attack Flow Scenario (Red Team Example)

1. **Kick-Off:** Pen tester starts post-exploitation tool with PowerShell (`powershell.exe -nop -w hidden -encodedcommand ...`)
2. **Recon:** PowerShell runs domain and group enumeration scripts (`Get-DomainUser`, `Get-DomainGroup`)
3. **Privilege Escalation:** Executes `Invoke-Privesc` or `PowerUp.ps1` for privilege escalation checks.
4. **Persistence/Evasion:** Test scripts add autorun registry keys, scheduled tasks using simulation scripts.
5. **Lateral Movement:** Simulates lateral movement via `Invoke-WMI` or `Invoke-SMBExec`.
6. **Clean-Up:** Tester removes persistence, uninstalls tools, or signals “end-of-test”.

## Incident Response and Blue Team Considerations

| Step | Action |
| :-- | :-- |
| Separation | Distinguish test from real threat using known IPs, accounts, and time windows. |
| Audit | Correlate with run books—ensure actions match scope/ROE of test. |
| Logging | Ensure all ScriptBlock and event logs are captured for after-action review. |
| Communicate | Blue and red teams coordinate to tune alerts, update detection/fidelity rules. |
| Lessons Learned | Use simulated activity for tuning SIEM/EDR and improving detection coverage. |

## Best Practices and Recommendations

- **Tag/Whitelabel test accounts and ranges** in SIEM to reduce alert fatigue and avoid confusion.
- **Enforce full logging (4104, 4688, Sysmon, etc.)** for all test devices and accounts during simulations.
- **Conduct after-action reviews**—search for test-related patterns, gaps, and non-detections.
- **Hone alert logic** so overly broad rules don’t miss advanced techniques or become noisy during tests.
- **Automate report generation** of all PowerShell-related detection hits during exercises.
- **Blur the lines on the tabletop—mix red/blue/yellow (exercise control) to simulate real responses and ambiguity**[^7_2][^7_1][^7_3].


## Infographic: Penetration Testing With PowerShell

**Attack/Test Chain:**

1. **Initial Access (Test Account)**
2. **Domain Recon Scripts**
3. **Privilege Escalation Attempts**
4. **Persistence/Defensive Tamper Scripts**
5. **Lateral Movement Simulations**
6. **Cleanup \& End-of-Exercise**

**Implementing robust logging and monitoring, clear communication of ranges/accounts in use, and SIEM queries tailored for red/blue/yellow team activities ensures drills are both effective and safe—and helps your organization prepare for real PowerShell-based attacker scenarios.**

**References to PowerShell logging, detection strategies, and SIEM integration—Splunk, CrowdStrike, ELK—provided in the above queries can be customized to match your environment and improve detection without excessive alerting[^7_2][^7_4][^7_5][^7_6].**

<div style="text-align: center">⁂</div>

[^7_1]: https://www.eccouncil.org/cybersecurity-exchange/penetration-testing/powershell-scripting-definition-use-cases/

[^7_2]: https://redcanary.com/threat-detection-report/techniques/powershell/

[^7_3]: https://www.nccgroup.com/us/research-blog/machine-learning-from-idea-to-reality-a-powershell-case-study/

[^7_4]: https://www.splunk.com/en_us/blog/security/powershell-detections-threat-research-release-august-2021.html

[^7_5]: https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html

[^7_6]: https://cyberwardog.blogspot.com/2017/06/enabling-enhanced-ps-logging-shipping.html

[^7_7]: https://www.reddit.com/r/PowerShell/comments/phf9md/how_does_an_organization_detect_a_powershell/

[^7_8]: https://community.splunk.com/t5/Getting-Data-In/Is-it-possible-to-create-a-command-that-launches-a-powershell/m-p/396952

[^7_9]: https://gist.github.com/lukeplausin/4e473c0cd899063d092df7d7523cbad0

[^7_10]: https://discuss.elastic.co/t/powershell-query-examples/201439

[^7_11]: https://www.trendmicro.com/vinfo/in/security/news/cybercrime-and-digital-threats/tracking-detecting-and-thwarting-powershell-based-malware-and-attacks

[^7_12]: https://docs.splunk.com/Documentation/Splunk/9.4.2/Data/MonitorWindowsdatawithPowerShellscripts

[^7_13]: https://stackoverflow.com/questions/79534684/how-to-capture-output-from-crowdstrike-falcon-sensor-powershell-script

[^7_14]: https://docs.gatewatcher.com/en/gcenter/2.5.3/103/07_use_cases_operator/6_analyse_alerts/12_powershell_detect.html

[^7_15]: https://cloud.google.com/chronicle/docs/soar/marketplace-integrations/crowdstrike-falcon

[^7_16]: https://www.elastic.co/guide/en/elasticsearch/reference/8.16/sql-client-apps-ps1.html

[^7_17]: https://www.securonix.com/blog/hiding-the-powershell-execution-flow/

[^7_18]: https://0xcybery.github.io/blog/Splunk+Use+Cases

[^7_19]: https://www.reddit.com/r/crowdstrike/comments/1iug5h0/trying_to_run_an_advanced_event_search_for/

[^7_20]: https://0xmedhat.gitbook.io/whoami/hunting-with-elk

---
