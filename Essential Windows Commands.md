# Complete Windows Commands for Security Analysts

## 1. System Information \& Configuration

- **systeminfo**
    - Retrieves detailed information about the OS, hardware, updates, and patches.
    - *Example:*

```
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
systeminfo /s <remote_hostname>
```

- **whoami**
    - Displays the user currently logged in and available details about their session.
    - *Example:*

```
whoami
whoami /groups
whoami /priv
whoami /fqdn
whoami /all
```

- **ver / winver**
    - Shows the Windows version string in CMD (`ver`), or a detailed GUI window (`winver`).
    - *Example:*

```
ver
winver
```

- **getmac**
    - Lists the machine’s MAC address(es), essential for hardware inventory.
    - *Example:*

```
getmac
getmac /v
```

- **bcdedit**
    - Examines/manages boot configuration data (requires admin).
    - *Example:*

```
bcdedit /enum all
```

- **hostname**
    - Prints the computer's host name.
    - *Example:*

```
hostname
```

- **driverquery**
    - Enumerates installed device drivers.
    - *Example:*

```
driverquery
driverquery /v
driverquery /si
```

- **msinfo32**
    - Opens the System Information GUI or exports a hardware/software report.
    - *Example:*

```
msinfo32
msinfo32 /report C:\temp\sysinfo.txt
```

- **path**
    - Views or sets the executable path search variable.
    - *Example:*

```
path
```

- **wmic**
    - Runs WMI queries for system, disk, process, patches, and more (deprecated, but still present).
    - *Example:*

```
wmic os get Caption,Version,BuildNumber,OSArchitecture
wmic product get name,version
wmic qfe list brief
wmic process list brief
wmic useraccount list brief
wmic logicaldisk get caption,description,filesystem,size,freespace
```

- **powercfg**
    - Manages power settings and analyzes system energy usage.
    - *Example:*

```
powercfg /a
powercfg /energy
powercfg /lastwake
```

- **fsutil**
    - Advanced file system queries and configuration (admin for advanced options).
    - *Example:*

```
fsutil fsinfo drives
fsutil fsinfo volumeinfo C:
fsutil dirty query C:
fsutil usn readjournal C:
```

- **set**
    - Shows or modifies environment variables.
    - *Example:*

```
set
set PROCESSOR_ARCHITECTURE
```

- **msconfig**
    - Opens the System Configuration GUI utility.
    - *Example:*

```
msconfig
```


## 2. Network Analysis \& Configuration

- **ipconfig**
    - Displays all network adapter settings and IP info.
    - *Example:*

```
ipconfig
ipconfig /all
ipconfig /displaydns
ipconfig /flushdns
ipconfig /registerdns
ipconfig /release
ipconfig /renew
```

- **ping**
    - Checks network connectivity via ICMP.
    - *Example:*

```
ping 8.8.8.8
ping -n 20 <host>
ping -t <host>
```

- **netstat**
    - Shows all active network connections, listening ports, and associated process IDs.
    - *Example:*

```
netstat -ano
netstat -anob
netstat -p tcp -ano
netstat -r
netstat -e
netstat -s
```

- **tracert**
    - Traces route of packets to remote host.
    - *Example:*

```
tracert 8.8.8.8
tracert -d <hostname>
```

- **pathping**
    - Combines `ping` and `tracert` for hop-by-hop analysis and latency/loss tracking.
    - *Example:*

```
pathping 8.8.8.8
pathping -n -q 15 google.com
```

- **nslookup**
    - DNS query tool for records and resolving issues.
    - *Example:*

```
nslookup google.com
nslookup -type=mx google.com
nslookup google.com 8.8.8.8
```

- **arp**
    - Manages the ARP cache (IP-to-MAC mapping).
    - *Example:*

```
arp -a
arp -d *
```

- **netsh**
    - Network management tool: interface, Wi-Fi, firewall, etc.
    - *Example:*

```
netsh interface ip show config
netsh advfirewall firewall show rule name=all
netsh advfirewall set currentprofile state off
netsh wlan show profiles
netsh wlan show profile name="ProfileName" key=clear
```

- **route**
    - Displays and modifies local routing tables.
    - *Example:*

```
route print
route print -4
route add <destination> MASK <subnet_mask> <gateway> METRIC <metric_cost> IF <interface_index>
route delete <destination>
```


## 3. Process \& Service Management

- **tasklist**
    - Lists running processes; filter, verbose mode, DLL users.
    - *Example:*

```
tasklist
tasklist /svc
tasklist /m <dllname.dll>
tasklist /v
tasklist /fi "IMAGENAME eq chrome.exe"
tasklist /s <remote_hostname>
```

- **query process / user / session**
    - RDS/Terminal Services: Show processes/users/sessions.
    - *Example:*

```
query process
query user
query session
```

- **taskkill**
    - Terminates processes by image name, PID, or tree (with force options).
    - *Example:*

```
taskkill /IM notepad.exe
taskkill /PID 1234
taskkill /IM program.exe /F
taskkill /T /IM parent.exe /F
```

- **schtasks**
    - Manage scheduled tasks: create, modify, run, delete, query.
    - *Example:*

```
schtasks /query /fo LIST /v
schtasks /create /tn "Backup" /tr "C:\backup.bat" /sc daily /st 23:00
schtasks /delete /tn "Backup" /f
schtasks /run /tn "Backup"
schtasks /end /tn "Backup"
```

- **sc**
    - Service control: query, configure, start/stop/delete Windows services.
    - *Example:*

```
sc query
sc query state= all
sc qc <ServiceName>
sc queryex <ServiceName>
sc start <ServiceName>
sc stop <ServiceName>
sc config <ServiceName> start= disabled
sc delete <ServiceName>
```

- **net start / net stop**
    - Easily start or stop services.
    - *Example:*

```
net start
net start "Print Spooler"
net stop "Print Spooler"
```

- **taskmgr**
    - Opens Task Manager GUI.
    - *Example:*

```
taskmgr
```


## 4. File System \& Data Management

- **dir**
    - Lists files/folders. Use `/a`, `/s`, `/b`, `/o:d` for various views.
    - *Example:*

```
dir C:\Windows
dir /a
dir /s
dir /b
dir /o:d
dir /tc
```

- **cd / chdir**
    - Changes working directory.
    - *Example:*

```
cd C:\Users
cd ..
```

- **md / mkdir**
    - Create new directory.
    - *Example:*

```
md C:\Temp\NewFolder
mkdir C:\Temp\NewFolder
```

- **rd / rmdir**
    - Remove directories; `/s /q` removes directory and contents quietly.
    - *Example:*

```
rd C:\Temp\OldFolder
rd /s /q C:\Temp\Trash
```

- **xcopy**
    - Copies files/directories; more advanced than `copy`.
    - *Example:*

```
xcopy C:\source D:\dest /E /H /I /Y
```

- **robocopy**
    - Robust utility for large, recursive, or mirrored copying, preserves ACLs, timestamps.
    - *Example:*

```
robocopy C:\source D:\dest /E /COPYALL /R:3 /W:10
robocopy C:\source D:\dest /MIR
```

- **move**
    - Moves files, renames directories.
    - *Example:*

```
move C:\file.txt D:\
move C:\OldFolder C:\NewFolder
```

- **ren / rename**
    - Renames files/directories.
    - *Example:*

```
ren old.txt new.txt
```

- **del / erase**
    - Deletes files. Use `/f` for force, `/q` for quiet.
    - *Example:*

```
del C:\Temp\file.txt
del /f /q C:\Temp\*.tmp
```

- **type**
    - Outputs the contents of a text file.
    - *Example:*

```
type C:\Windows\System32\drivers\etc\hosts
```

- **find / findstr**
    - Search for text pattern in files or output; `findstr` supports regex.
    - *Example:*

```
find "error" C:\logs\app.log
findstr /i /s /c:"password" C:\Users\*.txt
ipconfig /all | findstr /i "DNS Servers"
```

- **sort**
    - Sorts input/output alphabetically.
    - *Example:*

```
type names.txt | sort
sort < names.txt > sorted_names.txt
```

- **comp / fc**
    - Compare files. `comp` for binary; `fc` for text.
    - *Example:*

```
comp file1.bin file2.bin
fc file1.txt file2.txt
```

- **tree**
    - Displays graphical directory structure.
    - *Example:*

```
tree C:\Windows /F
```

- **attrib**
    - Sets/shows file/folder attributes. Hide, read-only, etc.
    - *Example:*

```
attrib C:\file.txt
attrib +h C:\secret.txt
attrib -r C:\config.ini
```

- **cipher**
    - Encrypts, decrypts, or wipes free space (EFS).
    - *Example:*

```
cipher /c filename
cipher /e C:\SecretFolder
cipher /w:C:
```

- **compact**
    - Compresses/uncompresses files/folders using NTFS.
    - *Example:*

```
compact /c /s:C:\Logs
compact /u /s:C:\Logs
```

- **diskpart**
    - Advanced disk/partition management (destructive: use caution!).
    - *Example:*

```
diskpart
list disk
select disk 0
list partition
create partition primary
format fs=ntfs quick
assign letter=E
```

- **format**
    - Formats a disk/partition (destructive!).
    - *Example:*

```
format D: /fs:ntfs /q
```

- **chkdsk**
    - Check and repair disk errors.
    - *Example:*

```
chkdsk C:
chkdsk C: /f
chkdsk C: /r
```

- **takeown**
    - Take ownership of files/folders (and recursively).
    - *Example:*

```
takeown /f <filepath>
takeown /f <folderpath> /r /d y
```

- **icacls**
    - Modify/view permissions and ACLs.
    - *Example:*

```
icacls <filepath>
icacls <filepath> /grant Administrators:F
icacls <folderpath> /inheritance:d
icacls <folderpath> /reset /t
```

- **openfiles**
    - Lists files/folders open remotely or locally after enabling feature.
    - *Example:*

```
openfiles /local on
openfiles /query /v
```


## 5. User, Group \& Policy Management

- **net user**
    - Manages local user accounts: show, enable/disable, reset/remove.
    - *Example:*

```
net user
net user <username>
net user <username> <newpassword>
net user <username> /active:no
net user <username> /add <password>
net user <username> /delete
```

- **net localgroup**
    - Lists and edits group memberships.
    - *Example:*

```
net localgroup
net localgroup Administrators
net localgroup Administrators <username> /add
net localgroup Administrators <username> /delete
net localgroup NewGroup /add
```

- **gpupdate**
    - Forces update or reapplies Group Policy.
    - *Example:*

```
gpupdate
gpupdate /force
```

- **gpresult**
    - Shows which GPOs apply to system/user. Ideal for compliance audits.
    - *Example:*

```
gpresult /r
gpresult /Scope Computer /v
gpresult /Scope User /v
gpresult /h C:\temp\gp_report.html
```

- **runas**
    - Runs programs with alternate credentials.
    - *Example:*

```
runas /user:DOMAIN\Admin cmd.exe
runas /user:LocalAdmin /savecred "notepad.exe C:\Windows\System32\drivers\etc\hosts"
```

- **assoc / ftype**
    - Manages file extension-to-type and file type program associations.
    - *Example:*

```
assoc .txt
ftype txtfile
```

- **control**
    - Opens Control Panel or specific applets.
    - *Example:*

```
control
control printers
control userpasswords2
```


## 6. Event Log Management

- **wevtutil**
    - Queries, exports, and clears event logs (admin for security/system logs).
    - *Example:*

```
wevtutil el
wevtutil qe Security /c:10 /rd:true /f:text
wevtutil qe System /q:"*[System[Level=2]]" /c:5 /f:text
wevtutil epl Security C:\Backup\SecurityLog.evtx
wevtutil cl Security
```

- **eventvwr**
    - Opens the Windows Event Viewer GUI.
    - *Example:*

```
eventvwr
eventvwr <logname>
```


## 7. Security Auditing \& Utilities

- **sfc**
    - Scans and repairs protected system files.
    - *Example:*

```
sfc /scannow
sfc /verifyonly
```

- **auditpol**
    - Sets or views audit policies (admin typically required).
    - *Example:*

```
auditpol /get /category:*
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

- **bitsadmin**
    - Views and manages Background Intelligent Transfer Service jobs (often abused by malware).
    - *Example:*

```
bitsadmin /list /allusers
bitsadmin /info <JobID> /verbose
bitsadmin /reset
```

- **certutil**
    - Views, hashes, or manages certificates; also used to download, encode, decode files.
    - *Example:*

```
certutil -hashfile <filename> SHA256
certutil -urlcache -split -f <URL> <outputfile>
certutil -encode <infile> <outfile.b64>
certutil -decode <infile.b64> <outfile>
```

- **fltmc**
    - Manages filter drivers, views status.
    - *Example:*

```
fltmc instances
fltmc filters
```


## 8. PowerShell (Modern Security Scripting)

- **PowerShell starter:**
    - Start by launching `powershell.exe` or `pwsh.exe`
- **Key cmdlets:**
    - Process: `Get-Process`, `Stop-Process -Id <PID> -Force`
    - Service: `Get-Service`, `Start-Service Name`, `Stop-Service Name`
    - Networking: `Get-NetIPConfiguration`, `Test-NetConnection <host> -Port <port>`, `Get-NetTCPConnection`, `Resolve-DnsName <host>`
    - Event Log: `Get-WinEvent -LogName Security -MaxEvents 10`, `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50`
    - Files: `Get-ChildItem`, `Get-Content`, `Get-FileHash`, `Select-String -Path <file> -Pattern "error"`
    - System/hotfixes: `Get-ComputerInfo`, `Get-HotFix`
    - WMI/CIM: `Get-CimInstance -ClassName Win32_OperatingSystem`
    - User/groups: `Get-LocalUser`, `Get-LocalGroup`, `Get-LocalGroupMember Administrators`
    - Security: `Get-MpComputerStatus`
    - Remote: `Invoke-Command -ComputerName <remote_host> -ScriptBlock { Get-Process }`


## 9. Helper Commands \& GUI Shortcuts

- **cls**
    - Clears the command window.
    - *Example:*

```
cls
```

- **echo**
    - Displays message or toggles command echoing.
    - *Example:*

```
echo Hello, Security Analyst!
echo %DATE% %TIME%
```

- **clip**
    - Pipes output to the clipboard.
    - *Example:*

```
ipconfig /all | clip
```

- **shutdown**
    - Shuts down, restarts, or aborts scheduled shutdowns.
    - *Example:*

```
shutdown /r /t 0
shutdown /s /t 0
shutdown /a
```

- **mmc / diskmgmt.msc / defrag / cleanmgr / mstsc / winget / services.msc / devmgmt.msc / perfmon / resmon**
    - Opens GUI-based management panels for system functions and monitoring.
    - *Example:*

```
mmc
diskmgmt.msc
defrag C: /U /V
cleanmgr
mstsc
winget list
winget install <AppId>
services.msc
devmgmt.msc
perfmon
resmon
```


## 10. Sysinternals Suite (Download separately from Microsoft)

- **Autoruns/Autorunsc:**
Detects/manage all startup programs, drivers, tasks, etc.
- **Process Explorer (procexp.exe):**
Advanced Task Manager with DLL, handle, and process tree monitoring.
- **Process Monitor (procmon.exe):**
Real-time log of file, registry, network, and process activity.
- **PsExec:**
Secure remote shell/command execution.
- **Sigcheck:**
Lists file signatures, hashes, VirusTotal scans.
- **TCPView:**
Real-time GUI view of network endpoints and associated processes.

This exhaustive list covers every relevant Windows command from your file, including admin, networking, audit, PowerShell, and essential helper GUIs, each with a clear use case and real-world example. Use this as your operational quick-reference or a foundation for automation and incident response.

<div style="text-align: center">⁂</div>

[^3_1]: windows_commands_for_security_analyst__1753531615.pdf


---
