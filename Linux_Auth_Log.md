Splunk Log Analysis & Dashboarding: Unauthorized Linux Auditd Activity
🎯 Objective:

Analyze and categorize Linux Auditd logs, specifically focusing on SYSCALL_DENIED (standard permission denials) and AVC_DENIED (Mandatory Access Control denials) events.

Quantify the scope of the attempted breach, identify key targets related to persistence and privilege escalation, and measure the efficacy of security controls.

Develop actionable queries and visualizations for a Splunk dashboard to provide security teams with continuous monitoring of unauthorized activity.


🎯 Auditd Log Analysis and Key Queries:

1️⃣ Triage: Overall Scope and Active Users
    Quantifies all permission denial events and identifies the most frequent offenders.

 ```
    index="auth_log" (event_type=SYSCALL_DENIED OR event_type=AVC_DENIED) | stats count AS Total_Denied_Events
 ```

<img width="1920" height="883" alt="Screenshot (118)" src="https://github.com/user-attachments/assets/e14ad845-8412-4ff3-ba5c-865c67344690" />


Aim: Identify the Top 10 Most Targeted Files to understand the most sought-after resources, providing a clear map of the attacker's interest (e.g., SSH keys, configuration files).


2️⃣ Reconnaissance & Credential Theft
    Focuses on files used to enumerate system users, hosts, or steal credentials.

```
   index="auth_log" (SYSCALL_DENIED OR AVC_DENIED) path IN ("/etc/passwd", "/etc/hosts", "/etc/shadow") | stats count by path, uid, process
```

<img width="1920" height="875" alt="Screenshot (119)" src="https://github.com/user-attachments/assets/75d1c9ca-fa10-4516-9d06-883a2d4b7540" />


Aim: Identify users and processes attempting to perform initial discovery and data theft techniques against critical system files.


3️⃣ Evasion and Persistence Tactics
    Identifies attempts to maintain access (persistence) or cover tracks (evasion).


```
  index="auth_log" (SYSCALL_DENIED OR AVC_DENIED) path IN ("/var/log/auth.log", "/var/log/syslog", "/root/.bash_history")
```

<img width="1920" height="1080" alt="Screenshot (120)" src="https://github.com/user-attachments/assets/4c9979b4-601e-4155-ab39-7fd6c9bb742e" />

Aim: Detect actions characteristic of the Execution or Command and Control phases, specifically denial attempts against files used for task scheduling, adding users, or downloading payloads.


------------------------------------------------------------------------------------------------------------------------------------------------------------------


🖥️ Dashboard Visualizations: Unauthorized Access Incident


The following panels were developed to provide security analysts with real-time visibility into the scale, priority, and source of the unauthorized access attempts.


1️⃣ Attack Timeline: Density of Denial Events
    Shows the temporal distribution of all unauthorized actions to identify attack windows.

```
index="auth_log" (event_type=SYSCALL_DENIED OR event_type=AVC_DENIED) 
| timechart span=1h count AS Denied_Events
```
<img width="1885" height="649" alt="image" src="https://github.com/user-attachments/assets/a572f814-405e-4e3b-8a0f-38b223ad9c58" />


Aim: Identify spikes in activity, pin-pointing the hours or minutes when the attacker was most active on the system. This visualization helps set the incident's official timeframe.






















    















    

