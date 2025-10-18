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

-----------------------------------------------------------------------------------------------------------------------------------------------------------------


🧠 HTTP Threat Hunting & Analysis Dashboard (Splunk)

This project focuses on building an interactive Splunk dashboard for analyzing HTTP request logs and detecting potential web-based threats such as data exfiltration, suspicious tools, and abnormal HTTP methods.
The dataset used (http.json) contains simulated HTTP events, including standard and suspicious activity.

The goal of this part of the project is to simulate a SOC-style investigation using HTTP traffic data and visualize insights like:

👨‍💻 Top active source hosts

📡 Large file transfers

⚠️ Suspicious user agents (e.g., sqlmap, curl, botnet-checker)

💾 Sensitive URI access (like /shell.php or /etc/passwd)

🧩 HTTP error analysis

⏱️ Timeline of events by type

The end result is a Splunk dashboard that enables real-time web threat visibility.

⚙️ Dataset Description

Filename: http.json
Fields:
| Field           | Description                                                 |
| --------------- | ----------------------------------------------------------- |
| `ts`            | Timestamp of the request                                    |
| `id.orig_h`     | Source IP (client)                                          |
| `id.resp_h`     | Destination IP (server)                                     |
| `method`        | HTTP Method (GET, POST, PUT, DELETE, etc.)                  |
| `uri`           | Requested URI path                                          |
| `status_code`   | HTTP Response Code                                          |
| `user_agent`    | User-Agent string                                           |
| `resp_body_len` | Size of response body in bytes                              |
| `event_type`    | Categorization (Standard, Suspicious, Large Transfer, etc.) |


🧰 Tools Used

Splunk Enterprise — for log ingestion, query analysis, and dashboard creation

JSON-formatted HTTP logs — sample dataset for testing and visualization

Dashboard Studio — for modern, interactive dashboard design

Step 1: Create a New Dashboard

Go to Dashboards → Create New Dashboard

Name it: HTTP Threat Hunting Dashboard

Choose Dashboard Studio (recommended) for modern visuals

Click Create


Step 2: Add Panels and Queries

Each panel represents a key insight derived from the log data.
Below are the main queries and visualization recommendations:

```
index=http_lab sourcetype=_json
| stats count by id.orig_h
| sort -count

```

<img width="1873" height="604" alt="image" src="https://github.com/user-attachments/assets/72309fd5-763a-4e73-9da5-f55136ad3e90" />

```
index=http_lab sourcetype=_json
| stats count by method

```

<img width="1873" height="668" alt="image" src="https://github.com/user-attachments/assets/95e8718e-e4eb-49ed-9995-4d72449d75dd" />

```
index=http_lab sourcetype=_json event_type="Suspicious Agent"
| stats count by user_agent, id.orig_h
| sort -count

```

<img width="1878" height="411" alt="image" src="https://github.com/user-attachments/assets/32d01a66-8366-440b-a4fc-c305f6ac35f9" />

```
index=http_lab sourcetype=_json event_type="Large Transfer"
| stats sum(resp_body_len) as total_bytes by id.orig_h
| eval total_MB=round(total_bytes/1024/1024,2)
| sort - total_MB

```

<img width="1879" height="655" alt="image" src="https://github.com/user-attachments/assets/13817a51-f277-44c9-9d49-6acdee694e97" />

```
index=http_lab sourcetype=_json
| stats values(event_type) as activities by id.orig_h
| search activities="Large Transfer" AND (activities="Suspicious Uri" OR activities="Suspicious Agent")

```

<img width="1881" height="805" alt="image" src="https://github.com/user-attachments/assets/af8b7b56-446a-4323-8bdb-fb507b6e45dc" />

```
index=http_lab sourcetype=_json
| eval error_type=case(status_code>=500,"Server Error",status_code>=400,"Client Error",true(),"OK")
| stats count by error_type

```

<img width="1880" height="512" alt="image" src="https://github.com/user-attachments/assets/df5b6ee0-204b-459a-b059-38a41aae263c" />

```
index=http_lab sourcetype=_json event_type="Suspicious Uri"
| stats count by uri, id.orig_h

```

<img width="1882" height="427" alt="image" src="https://github.com/user-attachments/assets/7b179ca2-6612-4d2a-90b5-e342d4ef17ab" />

```
index=http_lab sourcetype=_json
| stats count by event_type
| sort -count

```

<img width="1876" height="712" alt="image" src="https://github.com/user-attachments/assets/0e131807-4060-4ecd-9f40-bb47133d2c0a" />





















