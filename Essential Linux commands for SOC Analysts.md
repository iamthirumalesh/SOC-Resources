# Essential Linux commands for SOC Analysts.md
## 1. System Information \& Configuration

- **uname**
    - Shows system information (kernel, OS, hardware).
    - *Example:*

```
uname -a             # Detailed kernel and system info
uname -r             # Kernel release
```

- **hostname / hostnamectl**
    - Displays or sets the system hostname.
    - *Example:*

```
hostname
hostnamectl set-hostname sec-analyst-lab
```

- **lsb_release / cat /etc/os-release**
    - Shows OS/distribution info.
    - *Example:*

```
lsb_release -a
cat /etc/os-release
```

- **uptime**
    - System uptime and load averages.
    - *Example:*

```
uptime
```

- **dmesg**
    - Kernel and hardware related logs.
    - *Example:*

```
dmesg | tail -40
```

- **df / du**
    - Disk space usage.
    - *Example:*

```
df -h                   # Disk free in human-readable format
du -sh /var/log/*       # Size of each subdir in /var/log
```


## 2. File \& Directory Management

- **ls**
    - Lists directory contents.
    - *Example:*

```
ls -l /etc
ls -a                  # Show hidden files
```

- **cd, pwd**
    - Change directories; print current path.
    - *Example:*

```
cd /var/log
pwd
```

- **mkdir / rmdir**
    - Create or remove directories.
    - *Example:*

```
mkdir security_audit
rmdir old_logs
```

- **cp, mv, rm**
    - Copy, move/rename, or remove files/directories.
    - *Example:*

```
cp /etc/passwd /tmp/
mv logs.tar.gz /backup/
rm -rf suspicious_folder/
```

- **cat, less, head, tail**
    - View file contents (whole or in parts).
    - *Example:*

```
cat /var/log/auth.log              # Show entire file
head -20 /var/log/syslog           # First 20 lines
tail -f /var/log/messages          # Watch live log updates
```

- **find / grep / awk / sed**
    - Search and process files.
    - *Examples:*

```
find / -type f -perm -4000          # Find all SUID files (privesc risk)
grep -i "failed" /var/log/auth.log  # Find failed login attempts
awk -F: '{print $1}' /etc/passwd    # List all usernames
sed 's/password/*******/g' config   # Mask password values in config
```

- **chmod / chown**
    - Change permissions/ownership.
    - *Example:*

```
chmod 600 secret.txt
chown root:root secret.txt
```


## 3. User, Group, \& Privilege Management

- **id / whoami / groups**
    - Show current user, group memberships.
    - *Example:*

```
id john
whoami
groups jane
```

- **useradd / usermod / userdel**
    - Add, modify, delete user accounts (requires sudo).
    - *Example:*

```
sudo useradd alice
sudo usermod -aG sudo alice        # Add alice to sudoers
sudo userdel -r olduser
```

- **groupadd / groupmod / groupdel**
    - Add, modify, delete groups.
    - *Example:*

```
sudo groupadd analysts
sudo groupmod -n security analysts
sudo groupdel oldgroup
```

- **passwd / chage**
    - Set or audit password status/policy.
    - *Example:*

```
sudo passwd bob
sudo chage -l alice               # Password policy for alice
```

- **su / sudo**
    - Switch user or run commands as root/admin.
    - *Example:*

```
su -
sudo apt update
```


## 4. Process \& System Activity

- **ps, pgrep, top, htop**
    - Process monitoring and querying.
    - *Example:*

```
ps aux                    # All running processes
pgrep sshd
top                       # Live system monitor
htop                      # (if installed) Interactive process viewer
```

- **kill, pkill, killall**
    - End processes by PID or name.
    - *Example:*

```
kill -9 1234
pkill -u alice
killall firefox
```

- **jobs, bg, fg, nohup, disown**
    - Manage background/foreground jobs.
    - *Example:*

```
nohup script.sh &   # Run in background, immune to hangup
jobs                # List shell jobs
disown %1           # Remove job from shell
```

- **nice, renice**
    - Adjust process priorities.
    - *Example:*

```
nice -n 10 backup.sh
renice -p 1234 -n 5
```


## 5. Network Configuration \& Analysis

- **ip, ifconfig (deprecated), iwconfig, ip addr / link / route**
    - Display or set network device config.
    - *Example:*

```
ip a                       # Show all interfaces/addresses
sudo ip link set eth0 up
sudo ip route add default via 10.0.0.1
```

- **netstat, ss**
    - Show open ports, connections, listening services.
    - *Example:*

```
netstat -tuln
ss -tulnp                 # More modern, detailed info
```

- **ping, traceroute, mtr**
    - Test connectivity and network path.
    - *Example:*

```
ping 8.8.8.8
traceroute github.com
mtr -c 10 google.com
```

- **tcpdump, wireshark**
    - Packet capture and network forensics.
    - *Example:*

```
sudo tcpdump -i eth0 port 80
wireshark &
```

- **nmap**
    - Scan for open ports, services, vulnerabilities.
    - *Example:*

```
nmap -sS -T4 192.168.1.0/24
nmap -A target.example.com
```

- **arp / ip neigh**
    - View and manage ARP tables.
    - *Example:*

```
arp -a
ip neigh show
```

- **whois / dig / nslookup**
    - DNS, domain, and network info queries.
    - *Example:*

```
whois example.com
dig A google.com
nslookup github.com
```


## 6. Log \& Event Management

- **journalctl**
    - Systemd log review (system and services).
    - *Example:*

```
journalctl -xe                 # Show recent errors
journalctl -u ssh              # Logs for sshd service
```

- **/var/log/***
    - Default log directory; review with `less`, `cat`, `grep`, etc.
    - *Example:*

```
less /var/log/auth.log
grep 'sudo' /var/log/auth.log  # Find all sudo usage
tail -f /var/log/syslog
```

- **eventlogadm**
    - For event log management (mainly Samba).
    - *Example:*

```
sudo eventlogadm -o dump "Application"
```

- **last, lastb, who, w**
    - Show recent logins, failed logins, current users.
    - *Example:*

```
last           # Successful logins
lastb          # Failed login attempts
who
w
```


## 7. Security Auditing \& Hardening

- **chkrootkit / rkhunter**
    - Scan for rootkits and suspicious activity.
    - *Example:*

```
sudo chkrootkit
sudo rkhunter --check
```

- **auditd / ausearch / aureport**
    - Audit system events, track changes and suspicious actions.
    - *Example:*

```
sudo auditctl -l
sudo ausearch -x /usr/bin/passwd   # Show passwd usage events
sudo aureport --failed             # Failed actions audit report
```

- **lynis**
    - All-in-one security audit tool.
    - *Example:*

```
sudo lynis audit system
```

- **find (privesc risk)**
    - Find SUID/SGID files used for privilege escalation.
    - *Example:*

```
find / -perm /4000 -type f 2>/dev/null
```

- **passwd -l / -u**
    - Lock or unlock user accounts.
    - *Example:*

```
sudo passwd -l olduser   # Lock user
sudo passwd -u alice     # Unlock user
```

- **iptables / ufw / firewalld**
    - Configure and view firewall status/rules.
    - *Example:*

```
sudo iptables -L -n -v      # List firewall rules
sudo ufw status             # Common on Ubuntu
sudo firewall-cmd --list-all
```


## 8. Integrity \& Forensics

- **md5sum / sha256sum**
    - Calculate file hashes for integrity checks.
    - *Example:*

```
sha256sum /usr/bin/bash
```

- **strings / hexdump**
    - Inspect binaries for embedded strings or view hex representation.
    - *Example:*

```
strings /usr/bin/ssh
hexdump -C /bin/ls | less
```

- **diff / cmp**
    - Compare files for differences.
    - *Example:*

```
diff file1.conf file2.conf
cmp -l file1.bin file2.bin
```


## 9. Package \& Patch Management

- **apt / yum / dnf / zypper / pacman**
    - Install, update, audit packages and patches.
    - *Example:*

```
sudo apt update && sudo apt upgrade
sudo yum list installed
sudo dnf check-update
```


## 10. Miscellaneous Helpers

- **date**
    - View/set system date and time.
    - *Example:*

```
date
sudo date -s "2025-07-27 10:00:00"
```

- **crontab / at**
    - Schedule and review automated jobs.
    - *Example:*

```
crontab -l
at 18:00
```

- **history**
    - Review command history.
    - *Example:*

```
history | grep passwd
```

- **sudo !!**
    - Rerun previous command as sudo.
    - *Example:*

```
sudo !!
```


These commands, tools, and utilities form the backbone of security analysis, incident response, and daily administration for Linux systems. Combined with user and permission audits, process and network monitoring, log review, patching, and security tools, they empower analysts to effectively secure and investigate Linux environments[^4_1][^4_2][^4_3][^4_4][^4_5][^4_6][^4_7][^4_8][^4_9][^4_10][^4_11][^4_12][^4_13][^4_14][^4_15].

<div style="text-align: center">⁂</div>

[^4_1]: https://sternumiot.com/iot-blog/linux-security-hardrining-19-best-practices-with-linux-commands/

[^4_2]: https://socradar.io/bash-commands-for-cti/

[^4_3]: https://www.webasha.com/blog/top-100-most-useful-linux-commands-with-examples-usage-and-output-for-beginners-and-advanced-users

[^4_4]: https://www.digitalocean.com/community/tutorials/linux-commands

[^4_5]: https://www.geeksforgeeks.org/linux-unix/linux-security-command-cheat-sheet/

[^4_6]: https://earthly.dev/blog/linux-network-commands/

[^4_7]: https://www.linkedin.com/pulse/essential-linux-commands-proccess-management-ubuntu-basic-islam-khedc

[^4_8]: https://hackernoon.com/essential-linux-commands-for-file-and-directory-management

[^4_9]: https://www.redhat.com/de/blog/linux-commands-manage-groups

[^4_10]: https://www.tutorialspoint.com/unix_commands/eventlogadm.htm

[^4_11]: https://dev.to/ekurtovic/linux-security-checkup-comprehensive-guide-to-quick-audit-essentials-ljm

[^4_12]: https://phoenixnap.com/kb/linux-network-commands

[^4_13]: https://blog.devops.dev/linux-mastery-03-deep-dive-into-process-management-3ebb6de3a4f9?gi=79631e6d1e57

[^4_14]: https://daily.dev/blog/linux-user-groups-and-permissions-guide

[^4_15]: https://www.youtube.com/watch?v=d6BUnrKY2FI

[^4_16]: windows_commands_for_security_analyst__1753531615.pdf

[^4_17]: https://tuxcare.com/blog/linux-security-tools/

[^4_18]: https://stackify.com/15-essential-kali-linux-commands-ethical-hackers-need-to-know/

[^4_19]: https://www.geeksforgeeks.org/linux-unix/file-management-in-linux/

[^4_20]: https://www.ibm.com/docs/en/fsmmn?topic=history-lsevtlog

[^4_21]: https://www.kali.org/tools/

