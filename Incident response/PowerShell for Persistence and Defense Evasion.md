# PowerShell for Persistence and Defense Evasion


## Detailed Analysis – PowerShell for Persistence and Defense Evasion

### Objective

**Detect and respond to attackers using PowerShell to establish persistence or evade defenses**—such as creating autoruns, modifying registry keys, disabling defenses, or leveraging trusted Windows tools (LOLBAS) for stealthy operations.

### MITRE ATT\&CK Mapping

- **T1547** – Boot or Logon Autostart Execution (Persistence)
- **T1562** – Impair Defenses (Disabling Windows Defender, Security Tools)
- **T1059.001** – PowerShell


### Why It Matters

Attackers frequently abuse PowerShell because it provides:

- **Direct access to critical system settings and defenses**
- **The ability to create persistence (scheduled tasks, registry, WMI, services) with native tools**
- **Powerful functions to disable defenses or tamper with Windows security settings**

These activities are highly effective and hard to detect without appropriate monitoring of script block and process logs.

## Detection Logic: SIEM/EDR Use Case

**Key Suspicious Behaviors:**

- PowerShell commands creating/changing scheduled tasks (e.g., `New-ScheduledTask`, `schtasks.exe`)
- PowerShell modifying registry autorun keys (e.g., `Set-ItemProperty` with `HKCU:` or `HKLM:` Run/RunOnce)
- Disabling/enabling Windows Defender settings (e.g., `Add-MpPreference`, `Set-MpPreference`, `Remove-MpPreference`)
- PowerShell running LOLBins to set persistence (e.g., `regsvr32.exe`, `mshta.exe`, `wscript.exe`)


### ELK Stack Detection Query (Lucene Example)

For events indexed from Windows process and script logs. Here are Lucene queries you can use:

#### 1. Detect PowerShell Creating Scheduled Tasks

```lucene
process_name:"powershell.exe" AND process_command_line:("New-ScheduledTask" OR "schtasks.exe")
```


#### 2. Detect PowerShell Modifying Autorun Registry Keys

```lucene
process_name:"powershell.exe" AND process_command_line:("Set-ItemProperty" AND ("Run" OR "RunOnce"))
```


#### 3. Detect PowerShell Disabling Defender Protections

```lucene
process_name:"powershell.exe" AND process_command_line:("Add-MpPreference" OR "Set-MpPreference" OR "Remove-MpPreference")
```


#### 4. Detect PowerShell Invoking LOLBAS (Living Off the Land Binaries)

```lucene
process_name:"powershell.exe" AND process_command_line:("regsvr32.exe" OR "mshta.exe" OR "wscript.exe" OR "rundll32.exe")
```

### 1. **Splunk Search Examples (SPL)**

#### Detect PowerShell Creating/Modifying Scheduled Tasks

```splunk
index=main (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" OR EventCode=4104 OR EventCode=4688)
(process="powershell.exe" AND (CommandLine="*New-ScheduledTask*" OR CommandLine="*schtasks.exe*"))
```


#### Detect PowerShell Modifying Autorun Registry Keys

```splunk
index=main (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" OR EventCode=4104 OR EventCode=4688)
process="powershell.exe" AND CommandLine="*Set-ItemProperty*" AND (CommandLine="*Run*" OR CommandLine="*RunOnce*")
```


#### Detect PowerShell Disabling Defender Protections

```splunk
index=main (EventCode=4104 OR EventCode=4688)
process="powershell.exe" AND (CommandLine="*Add-MpPreference*" OR CommandLine="*Set-MpPreference*" OR CommandLine="*Remove-MpPreference*")
```


#### Detect PowerShell Invoking LOLBAS

```splunk
index=main (EventCode=4104 OR EventCode=4688)
process="powershell.exe" AND (CommandLine="*regsvr32.exe*" OR CommandLine="*mshta.exe*" OR CommandLine="*wscript.exe*" OR CommandLine="*rundll32.exe*")
```

*Tip: Leverage 4104 (ScriptBlockLogging), 4688 (process creation), and correlate with abnormal parent-child relationships for enhanced fidelity.*[^6_1][^6_2][^6_3]

### 2. **CrowdStrike Falcon Query Examples**

#### Detect PowerShell Scheduling Tasks or Persistence

```crowdstrike
event_simpleName=ProcessRollup2
| search (TargetFileName="powershell.exe") AND
(CommandLine="*New-ScheduledTask*" OR CommandLine="*schtasks.exe*")
```


#### Detect PowerShell Registry Persistence

```crowdstrike
event_simpleName=RegistryRollup2
| search RegistryKeyPath="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" AND
(ImageFileName="powershell.exe")
```


#### Detect PowerShell Defender Tampering

```crowdstrike
event_simpleName=ProcessRollup2
| search TargetFileName="powershell.exe" AND
(CommandLine="*Add-MpPreference*" OR CommandLine="*Set-MpPreference*" OR CommandLine="*Remove-MpPreference*")
```


#### Detect PowerShell Invoking LOLBins

```crowdstrike
event_simpleName=ProcessRollup2
| search ParentBaseFileName="powershell.exe" AND
TargetFileName IN ("regsvr32.exe","mshta.exe","wscript.exe","rundll32.exe")
```

*CrowdStrike queries leverage process relationships, command-line arguments, and registry events—consider additional telemetry such as ScheduledTaskRegister and ServiceProcessRollup for complete coverage.[^6_4][^6_5]*

### 3. **ELK Stack (Lucene Syntax) Recap**

- Creating Scheduled Tasks:
`process_name:"powershell.exe" AND process_command_line:("New-ScheduledTask" OR "schtasks.exe")`
- Modifying Autorun Registries:
`process_name:"powershell.exe" AND process_command_line:("Set-ItemProperty" AND ("Run" OR "RunOnce"))`
- Disabling Defender:
`process_name:"powershell.exe" AND process_command_line:("Add-MpPreference" OR "Set-MpPreference" OR "Remove-MpPreference")`
- Invoking LOLBins:
`process_name:"powershell.exe" AND process_command_line:("regsvr32.exe" OR "mshta.exe" OR "wscript.exe" OR "rundll32.exe")`


You can combine these blocks with `OR` to form a broader hunting logic, then pivot to specific timeline or host-based queries when something triggers suspicion[^5_1][^5_2].

## Attack Flow Scenario

1. **Initial Access:** Attacker completes phishing and gets a foothold.
2. **Persistence via Task/Registry:** PowerShell creates or modifies an autorun scheduled task or registry key.
3. **Defense Evasion:** PowerShell disables anti-virus or adds exclusions with Defender cmdlets.
4. **Stealthy Execution:** LOLBins executed via PowerShell to maintain stealthy persistence on reboot.
5. **Ongoing Control:** Attacker can regain access or sustain command and control after reboot or user logout.

## Incident Response Steps

| Step | Action |
| :-- | :-- |
| Isolation | Isolate the host if persistence/defense evasion is detected. |
| Log Review | Investigate script block/process logs for PowerShell creating or editing persistence. |
| Artefact Hunt | Search for new scheduled tasks, modified registry keys, AV exclusions, or stopped services. |
| Remediation | Remove persistence artefacts, re-enable AV protections, review all scheduled tasks. |
| Hardening | Enable PowerShell logging, restrict who can manage tasks via GPO/AppLocker, baseline tasks. |

## Hardening \& Recommendations

- **Enable PowerShell Script Block and Module Logging** for deep command visibility.
- **Monitor for suspicious task creation/registry modifications** via process logs.
- **Audit AV exclusions regularly** to spot attacker-placed backdoors.
- **Use AppLocker or WDAC** to only allow signed PowerShell scripts.
- **Limit LOLBins and PowerShell write access** for non-admin users.
- **Alert on rapid/automated task creation** or sudden surges in registry modifications.
- **Educate admins and staff** about the risks of PowerShell-based persistence.



## Summary: Detection Coverage Best Practices

- **Use multiple log sources and correlate scheduled tasks, registry, and process creation events.**
- **Monitor command-line parameters** for suspicious patterns and LOLBin usage.
- **Enrich detections** with script block logging (4104), especially in Splunk and ELK environments.
- **Leverage behavioral hunting in CrowdStrike** to map parent/child process relationships and registry changes for persistence and defense evasion.

These example queries provide a solid foundation for hunting and alerting on suspicious PowerShell activities related to persistence and disabling of security controls in modern enterprise SOC workflows.

[^6_1][^6_2][^6_6][^6_4][^6_5][^6_3]

<div style="text-align: center">⁂</div>

[^6_1]: https://www.splunk.com/en_us/blog/security/powershell-detections-threat-research-release-august-2021.html

[^6_2]: https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html

[^6_3]: https://research.splunk.com/endpoint/907ac95c-4dd9-11ec-ba2c-acde48001122/

[^6_4]: https://www.linkedin.com/posts/himanshu-jindal-b2bb8a85_crowdstrikes-threat-hunting-platform-uses-activity-7243112957335764992-JBZ3

[^6_5]: https://blog.nviso.eu/2023/12/13/scaling-your-threat-hunting-operations-with-crowdstrike-and-psfalcon/

[^6_6]: https://www.splunk.com/en_us/blog/security/onboard-windows-events-powershell-threat-detection-uba.html

[^6_7]: https://research.splunk.com/detections/tactics/defense-evasion/

[^6_8]: https://www.linkedin.com/pulse/deep-dive-apt29-threat-hunting-splunk-experimental-analysis-seifu-qpile

[^6_9]: https://www.splunk.com/en_us/blog/security/using-splunk-user-behavior-analytics-uba-to-detect-malicious-powershell-activity.html

[^6_10]: https://redcanary.com/blog/threat-detection/defense-evasion-why-is-it-so-prominent-how-can-you-detect-it/

[^6_11]: https://attack.mitre.org/tactics/TA0005/

[^6_12]: https://www.cybertriage.com/blog/how-to-investigate-malware-wmi-event-consumers-2025/

[^6_13]: https://www.crowdstrike.com/en-us/blog/four-popular-defensive-evasion-techniques-in-2021/

[^6_14]: https://0xcybery.github.io/blog/Splunk+Use+Cases

[^6_15]: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules_building_block/defense_evasion_posh_defender_tampering

[^6_16]: https://research.splunk.com/endpoint/27958de0-2857-43ca-9d4c-b255cf59dcab/

[^6_17]: https://www.reddit.com/r/crowdstrike/comments/144f19i/20230608_cool_query_friday_t1562009_defense/

[^6_18]: https://www.crowdstrike.com/en-us/blog/investigating-powershell-command-and-script-logging/

[^6_19]: https://research.splunk.com/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/

[^6_20]: https://evals.mitre.org/results/enterprise/?vendor=crowdstrike\&scenario=1\&evaluation=apt29\&view=individualParticipant


---

**Implementing detailed PowerShell and process monitoring, especially for persistence mechanisms and AV manipulations, is critical to quickly detecting and reversing these high-impact attacker actions in modern Windows environments.**

[^5_1]: https://www.elastic.co/guide/en/security/8.18/powershell-script-with-discovery-capabilities.html

[^5_2]: https://0xmedhat.gitbook.io/whoami/hunting-with-elk

<div style="text-align: center">⁂</div>

[^5_1]: https://www.elastic.co/guide/en/security/8.18/powershell-script-with-discovery-capabilities.html

[^5_2]: https://0xmedhat.gitbook.io/whoami/hunting-with-elk

[^5_3]: https://www.elastic.co/guide/en/security/current/potential-privilege-escalation-via-recently-compiled-executable.html

[^5_4]: https://glanfield.co.uk/sqli-privilage-escalation-and-powershell-empire/

[^5_5]: https://www.varonis.com/blog/how-to-use-powershell-for-privilege-escalation-with-local-computer-accounts

[^5_6]: https://www.criticaldesign.net/post/privileged-account-discovery-script-reduce-privilege-escalation-attacks

[^5_7]: https://www.pluralsight.com/labs/aws/achieve-privilege-escalation-persistence-using-powershell

[^5_8]: https://www.elastic.co/docs/explore-analyze/query-filter/languages/lucene-query-syntax

[^5_9]: https://www.slideshare.net/slideshow/2017-thotcon-hacking-sql-servers-on-scale-with-powershell/75682617

[^5_10]: https://discuss.elastic.co/t/how-to-search-all-domain/282797

[^5_11]: https://www.packtpub.com/en-pl/product/powershell-for-penetration-testing-9781835082454/chapter/chapter-16-post-exploitation-in-linux-20/section/using-powershell-for-privilege-escalation-in-linux-ch20lvl1sec14

[^5_12]: https://stackoverflow.com/questions/76040676/batch-file-auto-elevation-using-powershell-and-not-mangling-the-arguments-but-pr

[^5_13]: https://research.splunk.com/endpoint/9a5a41d6-04e7-11ec-923c-acde48001122/

[^5_14]: https://www.diva-portal.org/smash/get/diva2:1333165/FULLTEXT01.pdf

[^5_15]: https://gist.github.com/sh1nz0n/0c11dd4e15e11506b955ceefddf4911a

[^5_16]: https://stackoverflow.com/questions/76417199/how-can-i-make-it-run-on-all-my-domains-powershell

[^5_17]: https://elastic.github.io/detection-rules-explorer/

[^5_18]: https://dl.packetstormsecurity.net/papers/general/Priv-Esc-cheatsheet.pdf

[^5_19]: https://stackoverflow.com/questions/58445871/powershell-get-current-domain-or-computer-name-user-and-the-difference-between-t

[^5_20]: https://manage.offsec.com/app/uploads/2023/01/SOC200-Syllabus-Google-Docs.pdf


---
