# PowerShell for Privilege Escalation and Domain Discovery

## Detailed Analysis – PowerShell for Privilege Escalation and Domain Discovery

### Objective

**Detect and respond to PowerShell usage for privilege escalation and domain reconnaissance**—where attackers utilize native Windows cmdlets and scripts to gather domain information, assess privileges, and attempt to escalate their access[^4_1][^4_2].

### MITRE ATT\&CK Mapping

- **T1069** – Permission Groups Discovery
- **T1087** – Account Discovery
- **T1059.001** – PowerShell
- **T1068** – Exploitation for Privilege Escalation


### Why It Matters

Attackers abuse PowerShell to:

- **Enumerate domains and privileges:** Instantly map out target environments.
- **Escalate privileges:** Discover misconfigurations, weak ACLs, or group memberships that can be exploited.
- **Blend in:** Operations often resemble legitimate administrator activities, making detection challenging.

PowerShell-based domain discovery and privilege escalation often precede lateral movement and credential dumping phases[^4_1].

## Detection Logic: SIEM/EDR Use Case

**Key Suspicious Indicators:**

- Extensive use of PowerShell cmdlets like `Get-ADDomain`, `Get-ADUser`, `Get-ADGroupMember`, `net group`, and `Get-Acl`.
- PowerShell execution by unexpected users, or outside business hours.
- Enumeration of large sets of accounts, groups, or permissions in a short timeframe.


### Detection Queries: Splunk, CrowdStrike, ELK

#### 1. **Splunk Search Example**

Search for reconnaissance and privilege escalation attempts using known domain enumeration cmdlets (EventCode 4104 captures script block execution):

```sql

index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 
(ScriptBlockText="*Get-ADDomain*" OR ScriptBlockText="*Get-ADUser*" OR ScriptBlockText="*Get-ADGroupMember*" OR ScriptBlockText="*Get-Acl*" OR ScriptBlockText="*net group*")

```

- **Best Practice:** Adapt the search by filtering for spike analytics (e.g., excessive results in a short window) and by user or host[^4_3][^4_4][^4_5].


#### 2. **CrowdStrike Falcon Query Example**

CrowdStrike Falcon’s threat hunting language enables process searches for PowerShell spawned by suspicious parents or running key enumeration cmdlets:

```crowdstrike
event_simpleName=ProcessRollup2
| search (TargetFileName="powershell.exe") 
AND (CommandLine="*Get-ADDomain*" OR CommandLine="*Get-ADUser*" OR CommandLine="*Get-Acl*" OR CommandLine="*net group*")
```

- Tailor this to surface only non-standard users or endpoints, and correlate with RegistryRollup events for any suspicious privilege escalation attempts[^4_6][^4_7].


#### 3. **ELK Stack Query Example**

Detect PowerShell executing key enumeration commands by searching event logs ingested in ELK:

```json
GET /logstash-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"winlog.event_id": "4104"}},
        {
          "query_string": {
            "query": "message:(\"Get-ADDomain\" OR \"Get-ADUser\" OR \"Get-ADGroupMember\" OR \"Get-Acl\" OR \"net group\")"
          }
        }
      ]
    }
  }
}
```

- This will surface script block log entries containing common domain or privilege discovery commands[^4_3][^4_8][^4_9].


## Attack Flow Scenario

1. **Initial Access:** Attacker lands on a workstation, escalates to a local admin.
2. **Reconnaissance:** Executes PowerShell to enumerate domains (`Get-ADDomain`), user lists (`Get-ADUser`), and group memberships (`Get-ADGroupMember`).
3. **ACL Analysis:** Uses `Get-Acl` to analyze file/folder or group permission misconfigurations.
4. **Privilege Escalation:** Leverages discovered weaknesses (e.g., weak group memberships) to gain higher privileges.
5. **Weaponization:** Prepares for lateral movement, dumping credentials, or persistence.

## Visual Infographic: PowerShell Privilege Escalation and Discovery Attack Chain

1. **External Compromise or Initial Access**
2. **Domain+Privilege Reconnaissance** (PowerShell cmdlets, e.g., `Get-ADDomain`, `Get-ADUser`)
3. **ACL/Permission Analysis** (`Get-Acl`, `net group`)
4. **Privilege Escalation** (gains higher access)
5. **Preparation for Lateral Movement, Persistence, or Exfiltration**

## Incident Response Steps

| Step | Action |
| :-- | :-- |
| Isolation | Contain host/user if suspicious enumeration or privilege escalation is detected. |
| Log Review | Gather all PowerShell 4104 (script block) events, process logs, and correlating user activity. |
| Group Membership Review | Audit for changes/additions to high-privilege groups or new service accounts. |
| ACL/Permission Audit | Check for changes to permissions or unexpected ACL modifications. |
| Credential Reset | Reset passwords/credentials of compromised user accounts. |
| Threat Hunt | Sweep environment for similar enumeration patterns from other users/endpoints. |

## Hardening \& Recommendations

- **Enable Full PowerShell Logging:** Script Block, Module, and Transcription logging for user/command attribution.
- **Alert on Reconnaissance Cmdlets:** Specific rules for `Get-AD*`, `net group`, and `Get-Acl` in SIEM/EDR.
- **Monitor for Large Enumerations:** Trigger investigation if a user queries large numbers of accounts/groups in a short period.
- **Least Privilege Principle:** Restrict AD cmdlet usage to only required admin accounts.
- **Anomaly Detection:** Use UBA/SIEM machine learning to baseline typical usage and trigger on deviations.
- **User Training:** Warn about phishing, social engineering, and proper PowerShell/account management[^4_10][^4_11].

**Implementing robust monitoring for PowerShell-based domain discovery and privilege escalation is essential for early detection of attack progression inside Windows environments. Combining rich script logging with targeted SIEM/EDR queries and tight privilege management helps break the attacker’s chain of escalation.**

<div style="text-align: center">⁂</div>

[^4_1]: https://www.manageengine.com/log-management/cyber-security/powershell-cyberattacks.html

[^4_2]: https://www.eccouncil.org/cybersecurity-exchange/penetration-testing/powershell-scripting-definition-use-cases/

[^4_3]: https://letsdefend.io/blog/detecting-fileless-malware

[^4_4]: https://www.marketscreener.com/quote/stock/SPLUNK-INC-10454129/news/Splunk-Hunting-for-Malicious-PowerShell-using-Script-Block-Logging-36455116/

[^4_5]: https://research.splunk.com/endpoint/d6f2b006-0041-11ec-8885-acde48001122/

[^4_6]: https://www.linkedin.com/posts/himanshu-jindal-b2bb8a85_crowdstrikes-threat-hunting-platform-uses-activity-7243112957335764992-JBZ3

[^4_7]: https://www.crowdstrike.com/tech-hub/endpoint-security/detecting-remediating-threats-with-crowdstrike-endpoint-detection-and-response/

[^4_8]: https://www.diva-portal.org/smash/get/diva2:1333165/FULLTEXT01.pdf

[^4_9]: https://0xmedhat.gitbook.io/whoami/hunting-with-elk

[^4_10]: https://www.codecademy.com/article/powershell-commands-for-cybersecurity-analysts

[^4_11]: https://indiancybersecuritysolutions.com/powershell-for-cybersecurity-unleashing-the-potential-of-automation/

[^4_12]: https://redcanary.com/threat-detection-report/techniques/powershell/

[^4_13]: https://www.splunk.com/en_us/blog/security/using-splunk-user-behavior-analytics-uba-to-detect-malicious-powershell-activity.html

[^4_14]: https://www.elastic.co/guide/en/security/8.18/potential-malicious-powershell-based-on-alert-correlation.html

[^4_15]: https://www.logsign.com/siem-use-cases/detecting-and-preventing-malicious-power-shell-attacks/

[^4_16]: https://www.reddit.com/r/crowdstrike/comments/10qyg4d/investigate_powershell_queries/

[^4_17]: https://www.linkedin.com/pulse/powershell-cybersecurity-reconnaissance-enumeration-scripts-pacheco-qluec

[^4_18]: https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html

[^4_19]: https://www.crowdstrike.com/en-us/blog/how-crowdstrike-uses-similarity-search-to-detect-script-based-malware-attacks/

[^4_20]: https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-powershell-hacktool-script-by-function-names.html

---
