# Mastering Windows Security Analysis: Essential Commands for Every Analyst

In the ever-evolving realm of cybersecurity, a Windows Security Analyst’s day may start with coffee—but it’s made productive with the right set of Windows commands. Whether you’re hunting for signs of compromise, hardening endpoints, or troubleshooting network anomalies, the right CLI (Command Line Interface) skills can separate the novice from the pro. Today, let’s journey through the Windows command-line toolkit—layer by layer—with practical, real-world usage.

## Complete Guide: Every Useful Windows Command for Security Analysts

### 1. System Information \& Configuration

- **systeminfo**
Gets exhaustive details on OS version, build, hardware, and installed patches.
    - Examples:
        - `systeminfo`
Shows details like OS, BIOS, RAM, applied hotfixes.
        - `systeminfo | findstr /B /C:"OS Name"`
Filter output for quicker reviews.
        - `systeminfo /s <remote_host>`
Query remote machines (needs proper rights).
- **whoami**
Reveals the current user context.
    - Examples:
        - `whoami`
Output: `domain\username`.
        - `whoami /groups`
Lists all groups the user belongs to.
        - `whoami /priv`
Displays user privileges.
        - `whoami /fqdn`
Shows full domain naming.
        - `whoami /all`
Combines all above details.
- **ver / winver**
    - `ver`: Prints version string in command prompt.
    - `winver`: Pop-up with detailed build and OS version.
- **getmac**
Views machine MAC addresses—vital for asset tracking.
    - Use `/v` for adapter details.
- **bcdedit**
Examines or changes Boot Configuration Data. Check for persistence threats or bootkit attacks.
    - `bcdedit /enum all`: List all boot entries.
- **hostname**
Prints current computer’s name—useful when managing many systems.
- **driverquery**
    - `driverquery`: Shows all loaded drivers.
    - `/v`: With signature info.
    - `/si`: Signed driver details to spot unauthorized drivers.
- **msinfo32**
Opens GUI with complete system info, or use `/report` to save to a file.
- **path**
Shows or edits the system’s executable search path for commands.
- **wmic**
(Deprecated but still handy)
    - OS details: `wmic os get Caption,Version,BuildNumber,OSArchitecture`
    - Installed software: `wmic product get name,version`
    - Quick Fix Engineering: `wmic qfe list brief`
    - Processes: `wmic process list brief`
- **powercfg**
    - `/a`: Shows sleep states.
    - `/energy`: Generates a report (can reveal issues/malware tweaks).
    - `/lastwake`: What woke the system.
- **fsutil**
Advanced file system queries and tuning.
    - Drives: `fsutil fsinfo drives`
    - Volume: `fsutil fsinfo volumeinfo C:`
    - Dirty flag: `fsutil dirty query C:`
    - USN journal: `fsutil usn readjournal C:`
- **set**
Lists or changes environment variables.
- **msconfig**
GUI utility for managing startup items and services.


### 2. Network Analysis \& Configuration

- **ipconfig**
    - `ipconfig`: Basic IP info.
    - `/all`: Everything—MAC, DNS, DHCP.
    - `/displaydns`: View current DNS cache.
    - `/flushdns`: Clear DNS cache.
    - `/registerdns`: Register DNS name and IP.
    - `/release` \& `/renew`: Handle DHCP leases.
- **ping**
Test reachability and latency.
    - `ping 8.8.8.8`: Test internet.
    - `-n 20`: 20 pings.
    - `-t`: Continuous.
- **netstat**
View all network connections.
    - `-ano`: All connections and PIDs.
    - `-anob`: Adds binary name (admin rights).
    - `-r`: Show routing table.
    - `-e`: Ethernet stats.
    - `-s`: Protocol stats.
- **tracert**
Map the path to a host across the network.
- **pathping**
Combines ping and tracert, showing detailed hop-performance.
- **nslookup**
DNS query utility.
    - Check A records, MX records, or use alternative DNS servers.
- **arp**
Map IPs to MACs on the LAN.
    - `arp -a`: List.
    - `arp -d *`: Delete entries.
- **netsh**
Edit/manage network configs, Wi-Fi profiles and firewalls.
    - `netsh interface ip show config`
    - `netsh advfirewall firewall show rule name=all`
- **route**
Print/modify routing tables.


### 3. Process \& Service Management

- **tasklist**
    - `/svc`: See services per process.
    - `/m <dll>`: See what uses a DLL.
    - `/v`: Verbose.
    - `/fi`: Filter results.
    - `/s <host>`: Remote queries.
- **query process/user/session**
See Remote Desktop sessions and processes/users on a server.
- **taskkill**
Stops processes.
    - `/IM notepad.exe`: By name.
    - `/PID 1234`: By process ID.
    - `/F`: Force.
    - `/T`: Kill tree (process + children).
- **schtasks**
Scheduled task management.
    - `/query /fo LIST /v`
    - `/create`
    - `/delete`
    - `/run`
    - `/end`
- **sc**
Full service management tool.
    - Query state, config, start/stop/delete.
    - `/queryex`: Extended status (PID).
- **net start / net stop**
Simplified service starter/stoppers.
- **taskmgr**
GUI version of task management.


### 4. File System \& Data Management

- **dir, cd, md, rd, ren, move, copy**
    - Explore, traverse, create, rename, move, and remove folders and files.
    - Use `/a` for all file types and `/s` for recursion.
    - `md`/`mkdir`: Create directories
    - `rd`/`rmdir`: Remove directories
- **xcopy, robocopy**
    - `xcopy`: Copy files, directories with options.
    - `robocopy`: Advanced tool for larger/more complex jobs, mirroring, preserving timestamps/ACLs.
- **del/erase**
Removes files—use `/f` for force, `/q` for quiet.
- **type**
Reads file content to console.
- **find/findstr**
    - Search for patterns in files; `findstr` supports regex and recursion.
- **sort**
Sorts output or files alphabetically.
- **comp/fc**
File compare tools—`comp` for binary, `fc` for text.
- **tree**
Visualizes directory structure.
- **attrib**
    - Show/set file attributes.
    - `+h`: Hide a file.
    - `-r`: Remove read-only.
- **cipher**
    - `/c`: Show encryption state.
    - `/e`: Encrypt folder (EFS).
    - `/w`: Wipe free space.
- **compact**
For NTFS compression.
    - `/c`: Compress.
    - `/u`: Uncompress.
- **diskpart**
Advanced disk/partition management (destructive, use with care!)
- **format**
Erases and sets up a volume for use.
- **chkdsk**
Disk check, with `/f` to fix errors and `/r` to recover sectors.
- **takeown**
Take file/folder ownership (recursively if needed).
- **icacls**
Edit permissions and ACLs.
- **openfiles**
List open files/folders, especially useful on file servers.


### 5. User, Group \& Policy Management

- **net user**
    - List, manage, reset, disable, and remove user accounts.
- **net localgroup**
    - Show/edit local group memberships.
- **gpupdate**
Forces application of Group Policy changes.
- **gpresult**
See policy results—use `/h` for HTML report.
- **runas**
Launch a process as another user (requires credentials).
- **assoc**
Comfortably edit file extension associations.
- **ftype**
Set default opening application for file types.
- **control**
Quick-open Control Panel or specific applets.


### 6. Event Log Management

- **wevtutil**
Command-line event log querying, exporting, and clearing.
- **eventvwr**
Open Event Viewer GUI directly.


### 7. Security Auditing Utilities

- **sfc**
System file integrity scanner and self-repair.
- **auditpol**
Check and edit audit policy on the fly.
- **bitsadmin**
View/cancel BITS downloads/uploads (attackers often abuse this for file transfer).
- **certutil**
Hash, encode/decode, download, or manage certificates. Attackers often leverage for file transfer or obfuscation.
- **fltmc**
Manage and query filter drivers.


### 8. PowerShell (The Modern Era)

- **PowerShell core commands:**
    - `Get-Process`, `Stop-Process`
    - `Get-Service`, `Start-Service`, `Stop-Service`
    - `Get-NetIPConfiguration`, `Get-NetTCPConnection`, `Test-NetConnection`, `Resolve-DnsName`
    - `Get-WinEvent` and advanced event log querying
    - File manipulation: `Get-ChildItem`, `Get-Content`, `Get-FileHash`, `Select-String`
    - WMI/CIM queries: `Get-CimInstance`, e.g., enumerate OS version in a modern way.


### 9. Helper Commands \& GUI Shortcuts

- **cls**
Clears command prompt window.
- **echo**
Print strings or turn command echoing on/off.
- **clip**
Pipe output to Windows clipboard.
- **shutdown**
    - `/r`: Restart.
    - `/s`: Shutdown.
    - `/a`: Abort shutdown.
- **mmc, diskmgmt.msc, defrag, cleanmgr, mstsc, services.msc, devmgmt.msc, perfmon, resmon**
    - `mmc`: Open Microsoft Management Console for adding snap-ins.
    - `diskmgmt.msc`: Disk management GUI.
    - `defrag`: Disk defragmentation (less critical with SSDs, but helpful on spinning disks).
    - `cleanmgr`: Launches Disk Cleanup.
    - `mstsc`: Remote Desktop client.
    - `services.msc`: Services management console.
    - `devmgmt.msc`: Device Manager GUI.
    - `perfmon`: Performance monitoring.
    - `resmon`: Resource monitor.
- **winget**
Windows Package Manager for app installation/management.


### 10. Sysinternals Suite (External, Highly-Recommended)

- **Autoruns/Autorunsc**
Discover and manipulate all auto-run locations.
- **Process Explorer**
A deep-dive Task Manager.
- **Process Monitor**
Real-time file, registry, and network logging.
- **PsExec**
Execute processes on remote systems.
- **Sigcheck**
File signature, hash, and VirusTotal checking.
- **TCPView**
GUI visualization of network endpoints and used processes.

**This covers every built-in and external (Sysinternals) command from your material with a detailed explanation of its purpose and practical usage for security analysis**[^2_1]. If you need usage scenario examples or in-depth PowerShell analogs for any of these commands, let me know!

<div style="text-align: center">⁂</div>

[^2_1]: windows_commands_for_security_analyst__1753531615.pdf


---
