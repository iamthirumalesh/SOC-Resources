# PowerShell in Supply Chain Attacks and Third-Party Compromise


## Detailed Analysis – PowerShell in Supply Chain Attacks and Third-Party Compromise

### Objective

**Detect and respond to malicious PowerShell activity delivered through supply chain attacks or compromised third-party software/updaters.** This includes scenarios where attackers inject PowerShell code into legitimate vendor software, update packages, MSI installers, or supply chain components—using trusted processes to bypass traditional security controls.

### MITRE ATT\&CK Mapping

- **T1554** – Compromise Software Supply Chain
- **T1059.001** – Command and Scripting Interpreter: PowerShell
- **T1204** – User Execution (malicious update, signed installer, etc.)
- **T1078** – Valid Accounts (abuse of third-party or vendor credentials)


### Why It Matters

- Supply chain attacks deliver **malicious PowerShell code disguised as vendor actions or updates**, as seen in cases like SolarWinds, Kaseya, and NotPetya.
- Malicious PowerShell often runs **with elevated privileges** and trusted signatures, sidestepping allowlists and basic defenses.
- Compromised updaters/MSIs/Auto-Updaters can spawn hidden PowerShell processes to **download backdoors, exfiltrate data, or establish C2**.


## Detection Logic \& Practical Queries

### Key Suspicious Behaviors

- **PowerShell launched from unusual parent processes:** Updater.exe, msiexec.exe, vendor-specific binaries.
- **PowerShell activity immediately after software updates or admin tool installation.**
- **Unexpected network connections following vendor process spawning PowerShell.**
- **PowerShell running encoded, obfuscated, or non-standard commands during system maintenance windows.**
- **New tasks/registry autoruns, C2 beacons, or mass file manipulation after known vendor processes execute.**


### SIEM/EDR Detection Queries

#### **Splunk (SPL) Example**

Detect PowerShell spawned by supply chain-related EXEs or MSIs:

```splunk
index=main (EventCode=4688 OR EventCode=4104)
process="powershell.exe" AND (parent_process="msiexec.exe" OR parent_process="setup.exe" OR parent_process="Updater.exe" OR parent_process="update*.exe" OR parent_process="vendor*.exe")
```

*Enrich with network/beacon destination, timing after update installs, and cross-match against software inventory.*

#### **CrowdStrike Falcon Query Example**

```crowdstrike
event_simpleName=ProcessRollup2
| search TargetFileName="powershell.exe"
AND (ParentBaseFileName="msiexec.exe" OR ParentBaseFileName="setup.exe" OR ParentBaseFileName="Updater.exe" OR ParentBaseFileName="update*" OR ParentBaseFileName="vendor*")
```

- Combine with command line keyword search for encoded/obfuscated commands, URLs, or unusual flags.
- Track by installation/upgrade timestamps.


#### **ELK Stack (Lucene) Query Example**

Search for PowerShell execution with suspicious parents:

```lucene
process_name:"powershell.exe" AND parent_process_name:("msiexec.exe" OR "setup.exe" OR "Updater.exe" OR "update" OR "vendor")
```

- Pivot on hosts receiving new software versions or where mass deployment occurs.


## Attack Flow Scenario

1. **Supply Chain Compromise:** Attacker poisons a vendor update/installer to embed a PowerShell payload.
2. **Deployment:** Organization runs legitimate update (msiexec.exe, setup.exe, Updater.exe).
3. **Payload Launch:** Malicious PowerShell code executes, often as SYSTEM or with high privileges.
4. **C2 Establishment:** PowerShell script connects to attacker's C2 for further commands or downloads additional payloads.
5. **Lateral \& Stealth:** Attacker can move laterally or establish persistence, appearing as routine software activity.

## Infographic: Supply Chain PowerShell Attack Chain

1. **Vendor/Supplier Compromise**
2. **Malicious Update Pushed to Customers**
3. **Installer/MSI/Updater Spawns PowerShell**
4. **Hidden Script Execution \& C2**
5. **Lateral Movement, Persistence, Data Exfiltration**

## Incident Response Steps

| Step | Action |
| :-- | :-- |
| Identification | Correlate PowerShell execution with recent update/installer activity. |
| Isolation | Remove affected hosts from the network. |
| Vendor Verification | Validate hash, signature, version, and source of all installed/updated software. |
| IOC Sweep | Search for C2 connections, PowerShell autoruns, unexpected scheduled tasks. |
| Reverse Engineering | Analyze PowerShell payloads/scripts for further IOCs or secondary actions. |
| Forensics | Review EDR logs for all endpoints that ran affected vendor processes. |
| Communication | Notify vendor, legal, and regulatory bodies as required by policy/law. |

## Hardening \& Best Practices

- **Restrict PowerShell execution from standard user accounts and third-party updaters.**
- **Monitor parent-child process relationships:** Flag PowerShell spawned by non-Microsoft, non-admin tools.
- **Verify digital signatures and checksums** on all vendor/third-party updates.
- **Delay auto-updates** and review in sandbox/test environments before global rollout.
- **Enable Script Block and Module Logging:** Track PowerShell execution regardless of source.
- **Limit outbound connections** from installer/updater processes not needing internet access.
- **Engage in vendor/supplier risk management:** Only allow trusted software signed by verified vendors.


## Blue Team/Threat Hunting Tips

- **Hunt for rare or first-seen parent process names** launching PowerShell—especially updaters or MSI installers.
- **Inspect PowerShell command lines**—look for encoded/obfuscated actions tied to install events/sequences.
- **Prioritize alerts during patch cycles** or after hotfixes are distributed—attackers often "ride the wave".
- **Collaborate with vendors and threat intelligence** to obtain compromise indicators proactively.

**Proactive defense and continuous monitoring for PowerShell spawned by third-party processes—even when signed and "trusted"—is essential for rapid detection of modern supply chain attacks. Combining SIEM, EDR, and script auditing with strong vendor validation provides the best chance to prevent, detect, and respond to these complex threats early.**

---
