# Malicious PowerShell Used for Lateral Movement

## Detailed Analysis: – Malicious PowerShell Used for Lateral Movement

### Objective

**Detect and respond to PowerShell activity leveraged for lateral movement within a Windows environment.** This typically involves attackers using PowerShell to move between compromised systems without dropping files to disk, abusing legitimate administrative capabilities.

### MITRE ATT\&CK Mapping

- **T1021.002** – Remote Services: SMB/Windows Admin Shares
- **T1059.001** – Command and Scripting Interpreter: PowerShell
- **T1569** – System Services (for remote service creation)
- **T1570** – Lateral Tool Transfer


### Why It Matters

Attackers exploit PowerShell’s legitimate functions to:

- **Access remote systems silently** by leveraging WinRM, SMB shares, or remote scheduled tasks
- **Transfer tools or payloads** between hosts (fileless or minimal footprint)
- **Execute commands remotely using unsecured admin credentials**

Because these actions can blend in with normal administrative activity, detection and investigation require visibility into both **command-line usage and remote activity patterns**[^2_1][^2_2].

### Detection Logic: SIEM/EDR Use Case

#### Detection Rule Example (Pseudo KQL/EQL)

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemoteUrl != "" or RemotePort == 5985  // WinRM default
| project Timestamp, DeviceName, InitiatingProcessParentFileName, FileName, ProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemotePort
```

- **Log Source**: Defender for Endpoint, Sysmon, or Windows Event Logs 4688/4689 with network context

**Suspicious Flags:**

- PowerShell using `Invoke-Command`, `Invoke-WmiMethod`, `New-PSSession`, `Copy-Item` targeting UNC paths
- Use of admin shares (e.g., `\\target\C$`) in the command line
- Unexpected remote connections by non-admin or service accounts


### Attack Flow Scenario (Example)

1. **Post-Compromise Enumeration**
    - Attacker runs `net view`, `Get-ADComputer`, `Invoke-Command` via PowerShell to find target hosts.
2. **Password Dumping/Harvesting**
    - Mimikatz run via PowerShell (`Invoke-Mimikatz`) to collect admin passwords.
3. **Remote Execution on New Host**
    - Using harvested credentials, attacker runs:
        - `Invoke-Command -ComputerName Server02 -ScriptBlock {...}`
        - Or copies tools via `Copy-Item -Path ... -Destination \\Server02\C$\Temp`
4. **Persistence or Further Tool Transfer**
    - Registers a scheduled task or WMI event for persistence on new host, all via PowerShell.

### Infographic: PowerShell Lateral Movement Attack Chain

1. **Compromise initial host**
2. **Credential harvesting (PowerShell Mimikatz)**
3. **Remote PowerShell session to another host (WinRM/SMB)**
4. **Fileless tool/payload transfer to remote host**
5. **Remote code execution and persistence**

### Incident Response Steps

| Step | Action |
| :-- | :-- |
| Isolation | Contain all involved hosts |
| Investigation | Audit all remote PowerShell connections and command-line logs |
| Privilege Review | Check if non-admin accounts made remote PowerShell calls |
| Credential Hygiene | Identify and reset compromised accounts |
| Tool Hunt | Search for lateral tool transfer artifacts and persistence |
| Network Review | Analyze remote SMB/WinRM connections for data exfiltration |
| Timeline | Build a timeline of lateral movement events |

### Post-Incident Hardening Actions

- **Restrict Remote PowerShell Access:** Allow only for specific, secured admin groups and require MFA.
- **Monitor for Remote Session Creation:** Alert on `New-PSSession`, `Invoke-Command`, and PowerShell use over WinRM, especially from unexpected source hosts.
- **Disable Dangerous Features:** If not required, disable PowerShell remoting and WinRM on endpoints.
- **Tighten Credential Usage:** Enforce unique local admin passwords (LSA Isolation), minimize shared/admin account use.


### Analyst Deep Dive: Uncovering Lateral Movement

#### Steps:

1. **Identify source and destination IPs** of remote PowerShell activity.
2. **Check logon types:** Is the activity using network logon (type 3) or interactive?
3. **Correlate with logon success/failure events** to reveal credential misuse.
4. **Investigate transferred tools/scripts:** Are tools like PsExec or custom scripts used for further access?
5. **Track parent process lineage** – many attacks will have explorer.exe/cmd.exe > powershell.exe > lateral movement call[^2_3][^2_1].

### Additional Scenarios to Monitor

- **Service Account Abuse:** Service accounts spawning PowerShell with remote targets.
- **Unscheduled or After-Hours Remote Sessions:** Lateral movement often happens outside business hours.
- **Automation Framework Abuse:** Attackers leveraging legitimate orchestration tools (SCCM, scripts) for widespread movement.


### Recommendations for Enhanced Detection

- **Enable and Forward Windows PowerShell Logs:** Especially Module Logging (Event ID 4104) and Detailed Tracking (Event ID 4688).
- **Correlate Remote Logons + PowerShell:** If a host receives a new PowerShell session with an unfamiliar source, escalate.
- **Monitor for Use of `-Credential` and Hardcoded Passwords:** These often indicate abuse of harvested credentials.
- **Block SMB/WinRM at Network and Firewall:** Especially to/from workstations unless explicitly required.
- **Limit PowerShell Execution Policy:** Harden to restrict unauthorized scripts, combined with AMSI and Constrained Language Mode.
- **Use JEA (Just Enough Administration):** Provide only required privileges.


### Infographic: Lateral Movement Detection

- Diagram showing **initial compromise (Host A)**, **PowerShell remote commands (WinRM/SMB/Invoke-Command)**, **spread to Host B, C, D** with alerts highlighting command-line logging and credential artifacts.


#### Implementing strict controls over PowerShell remoting, tight privilege and credential management, and continuous monitoring for remote PowerShell activity can break the attack chain early and significantly reduce risk from lateral movement.

**Invest in continuous improvement of detection logic and routinely audit remote administrative behavior to defeat adversary abuse of PowerShell for lateral movement.**[^2_1][^2_3][^2_2]

<div style="text-align: center">⁂</div>

[^2_1]: https://s3.ca-central-1.amazonaws.com/esentire-dot-com-assets/assets/resourcefiles/Threat_Dissection_Powershell_3.pdf

[^2_2]: https://redcanary.com/threat-detection-report/techniques/powershell/

[^2_3]: https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html

[^2_4]: https://www.reddit.com/r/PowerShell/comments/1ct7s1s/had_a_very_suspicious_powershell_script_run_on_my/

[^2_5]: https://www.securonix.com/blog/hiding-the-powershell-execution-flow/

[^2_6]: https://blogs.quickheal.com/powershell-an-attackers-paradise/

[^2_7]: https://www.infosecurity-magazine.com/news/powershell-exploits-spotted-over/

[^2_8]: https://s3.ca-central-1.amazonaws.com/esentire-dot-com-assets/assets/pardot/Threat_Dissection_Powershell_4.pdf

[^2_9]: https://www.devo.com/resources/use-case/soar-use-case-malicious-powershell-commands/

[^2_10]: https://learn.microsoft.com/en-us/powershell/scripting/security/preventing-script-injection?view=powershell-7.5

[^2_11]: https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-windows-powershell-arguments.html

[^2_12]: https://paperswithcode.com/paper/detecting-malicious-powershell-commands-using

[^2_13]: https://www.cybereason.com/blog/fileless-malware-powershell

[^2_14]: https://attack.mitre.org/techniques/T1059/001/

[^2_15]: https://techcommunity.microsoft.com/discussions/windowspowershell/threat-hunting-with-powershell---security-even-with-a-small-budget---there-is-no/3826224

[^2_16]: https://calcomsoftware.com/the-different-stages-of-a-powershell-attack/

[^2_17]: https://docs.stellarcyber.ai/5.1.1/Using/ML/Alert-Rule-Based-PowerShell.htm

[^2_18]: https://www.eccouncil.org/cybersecurity-exchange/penetration-testing/powershell-scripting-definition-use-cases/

[^2_19]: https://www.reddit.com/r/PowerShell/comments/12mxght/malicious_powershell_commands_for_demo/

[^2_20]: https://www.sumologic.com/blog/powershell-and-fileless-attacks


---
