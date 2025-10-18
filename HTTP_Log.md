Splunk Log Analysis & Dashboarding

🎯 Objective: 

🔹Analyze and Visualize HTTP log, detect anomalies and unusual traffic.
🔹Build interactive dashboards for better visibility and insights.

🎯HTTP Log Analysis and Key Queries:


1️⃣ Top Source IPs by HTTP Requests
: Which source IPs generated the most HTTP requests?

```
     index="http_lab" source="http.json" host="GODSPEED" sourcetype="_json"
     | stats count by id.orig_h
     | sort -count

 ```
<img width="1920" height="883" alt="Screenshot (102)" src="https://github.com/user-attachments/assets/7f680dcd-e83d-47ec-b26f-89943e321870" />


Aim: Identify the most active clients communicating with the server, helping spot heavy users or potential attackers.



2️⃣ Most Common HTTP Methods
: What HTTP methods are most commonly used?

```
index="http_lab" source="http.json" host="GODSPEED" sourcetype="_json"
| stats count by method
| sort -count

```
<img width="1920" height="871" alt="Screenshot (96)" src="https://github.com/user-attachments/assets/3af8dcdf-0362-45d4-8936-342dbc4006de" />

Aim: Understand which HTTP operations (GET, POST, etc.) dominate the traffic and detect abnormal usage patterns.


3️⃣ Suspicious HTTP Requests
: Which IPs triggered suspicious HTTP activity (sqlmap, curl, botnet, etc.)?
```
index="http_lab" source="http.json" host="GODSPEED" sourcetype="_json" event_type="Suspicious*"
| stats count by id.orig_h, user_agent, uri
| sort -count

```
<img width="1920" height="897" alt="Screenshot (97)" src="https://github.com/user-attachments/assets/cc6bf398-80f2-47e7-aaa9-04f5f73c6f9e" />



4️⃣ Large Data Transfers
: Which IPs were involved in unusually large HTTP responses?

```
index="http_lab" source="http.json" host="GODSPEED" sourcetype="_json" event_type="Large Transfer"
| stats sum(resp_body_len) as total_bytes by id.orig_h, id.resp_h
| sort -total_bytes

```
<img width="1920" height="887" alt="Screenshot (98)" src="https://github.com/user-attachments/assets/ef36d9a6-10f4-4441-8f79-52167480c62e" />

Aim: Identify clients or servers involved in large data transfers, which could signal data exfiltration or heavy file downloads.


5️⃣ Suspicious User Agents
: Which non-browser tools accessed the server?

```
index="http_lab" source="http.json" host="GODSPEED" sourcetype="_json"
| where like(user_agent,"%sqlmap%") OR like(user_agent,"%curl%") OR like(user_agent,"%python%") OR like(user_agent,"%botnet%")
| stats count by user_agent, id.orig_h

```
<img width="1920" height="883" alt="Screenshot (99)" src="https://github.com/user-attachments/assets/0954f089-1eb0-4b68-8ae2-15dab683c53d" />


6️⃣ Possible Web Shell / Sensitive File Access
: Did any clients attempt to access files like /shell.php or /etc/passwd?



```
index="http_lab" source="http.json" host="GODSPEED" sourcetype="_json"
| search uri="/shell.php" OR uri="/etc/passwd"
| stats count by id.orig_h, uri, user_agent

```
<img width="1920" height="891" alt="Screenshot (100)" src="https://github.com/user-attachments/assets/6b076eae-b4c9-4632-af5b-a09852085ef3" />


Aim: Identify attempts to access critical files that could indicate exploitation or reconnaissance activity.


🔐 10️⃣ Potential Compromise Detection
: Which IPs have a mix of “Large Transfer” and “Suspicious Uri” or “Suspicious Agent” — possibly indicating data exfiltration?

```
index="http_lab" source="http.json" host="GODSPEED" sourcetype="_json"
| stats values(event_type) as activities by id.orig_h
| search activities="Large Transfer" AND (activities="Suspicious Uri" OR activities="Suspicious Agent")

```
<img width="1920" height="880" alt="Screenshot (101)" src="https://github.com/user-attachments/assets/c4079411-12d6-4c10-804a-49dbf00817e1" />


Aim: Detect IPs showing multiple suspicious behaviors, which may indicate a compromise or ongoing data theft.


















