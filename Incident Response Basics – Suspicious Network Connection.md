# **Incident Response Basics – Suspicious Network Connection**

---

## 🎯 **Objective**

Investigate and respond to a **suspicious outbound network connection** from a Linux machine. This simulates beaconing behavior or data exfiltration. Students will learn to inspect open connections, trace source processes, and mitigate threats.

---

---



## 📘 **Why It Matters**

Attackers often use hidden outbound connections to communicate with command-and-control (C2) servers. Detecting and cutting off these connections is essential for SOC and IR teams.

---

## 🔁 **Incident Response Process (NIST SP 800-61 Rev. 2)**

| **Phase** | **Description** |
|----------|-----------------|
| **1. Preparation** | Ensure `netstat`, `ss`, and `lsof` are installed. Enable auditd/network logging. |
| **2. Detection and Analysis** | Identify unexpected remote connections and associated processes. |
| **3. Containment, Eradication, and Recovery** | Kill the process, investigate binary, block destination IP. |
| **4. Post-Incident Activity** | Document findings, improve firewall rules, configure monitoring tools. |

---

## ⚠️ **Scenario: Unexpected Outbound Connection Detected**

A Linux system shows an active connection to an unknown IP `45.13.220.98:443`, not related to any known services.

---

## 🛠️ **Lab Setup**

### **System Requirements**
- Ubuntu/Kali Linux system
- Internet access
- Tools: `curl`, `netstat` or `ss`, `lsof`

### **Simulate Suspicious Connection**
```bash
nohup bash -c 'while true; do curl http://45.13.220.98/ping >/dev/null 2>&1; sleep 30; done' &
```

🧪Step-by-Step Investigation
### Step 1: Detect Active Network Connections
```
netstat -plant
# or
ss -plant
```
Look for a suspicious IP such as 45.13.220.98:443.

Here 
-p	Show the PID and program name of the connection
-l	Show only listening sockets
-a	Show all connections and listening ports
-n	Show numeric addresses (don’t resolve hostnames or port names)
-t	Show only TCP connections

### Step 2: Identify the Responsible Process
Get the PID from netstat or ss output

Investigate:

```
ps aux | grep 45.13.220.98
```
### Step 3: Containment & Eradication
- Kill the process:

```
kill <PID>
# or
pkill curl
```
- Block the IP using UFW:

```
ufw deny out to 45.13.220.98
```
### Step 4: Post-Incident Activity
Document:
- What process initiated the connection?
- Remote IP and port?
- Binary path used?

Recommendations:
- Implement egress filtering
- Deploy IDS/IPS solutions
- Monitor outbound connections and unusual traffic
