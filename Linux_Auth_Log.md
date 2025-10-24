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
