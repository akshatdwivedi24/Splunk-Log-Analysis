# 🧠 Day 1: Ingest and Analyze SSH Logs in Splunk

## 🎯 Objective  
The goal of Day 1 is to learn how to ingest SSH logs into Splunk, analyze failed and successful authentication attempts, and visualize SSH activity through a structured dashboard. This forms the foundation for understanding event correlation and security monitoring within Splunk.

---

## ⚙️ Steps to Upload SSH Log into Splunk

1. Go to **Splunk Web → Settings → Add Data**  
2. Choose **Upload** and select the file: `synthetic_zeek_ssh.json`  
3. Set **Source Type:** `json` (or create a new one named `zeek:ssh`)  
4. Select or create an **Index:** `ssh_lab`  
5. Complete the upload and verify that data is indexed successfully  

<img width="1920" height="882" alt="SSH_Log Uploaded" src="https://github.com/user-attachments/assets/c4d41ce3-1b25-43e1-b009-3ff53b251a8d" />
 

---

## 🔍 Lab Tasks  

Below are the SPL (Search Processing Language) queries used to perform basic analysis on the uploaded SSH log dataset.  

### ✅ Task 1: List the Top 10 Endpoints with Failed SSH Login Attempts  

```spl
source="SSH_Log.json" host="GODSPEED" index="ssh_lab" sourcetype="_json" auth_success="false" | head 10
```
<img width="1920" height="884" alt="First 10 Failed Login" src="https://github.com/user-attachments/assets/86d1e649-d2c9-4b72-be28-50ffdecacf51" />


Explanation:
This query filters events where authentication was unsuccessful (auth_success="false") and lists the first 10 results. It helps identify IPs or users repeatedly failing to log in — potential indicators of brute-force or unauthorized attempts.


✅ Task 2: Find the Total Number of SSH Connections
```
source="SSH_Log.json" host="GODSPEED" index="ssh_lab" sourcetype="_json" | stats count as total_ssh_connections
```
<img width="1920" height="873" alt="Total SSH Connections" src="https://github.com/user-attachments/assets/d9435495-3755-4f36-b27f-01f14a99a672" />



Explanation:
This command counts all SSH events in the dataset, providing the total number of connection attempts (both successful and failed).

✅ Task 3: Count All Event Types Observed in Logs

```
source="SSH_Log.json" host="GODSPEED" index="ssh_lab" sourcetype="_json" | stats count by event_type

```
<img width="1920" height="877" alt="Event_type" src="https://github.com/user-attachments/assets/a8ce2b99-916d-4cc2-9722-6cfd9a83e68f" />



Explanation:
This query groups and counts events by their event_type, helping you identify the distribution of SSH events — such as successful, failed, no-auth, and multiple-failed sessions.

✅ Task 4: Create a Splunk Dashboard

🎯 Objective

Build a Splunk Dashboard using the uploaded SSH logs to visualize and monitor:

Source IP Addresses

Destination IP Addresses

Number of Failed SSH Logins

Number of Successful SSH Logins

Source-to-Destination IP Relationships


🛠️ Step-by-Step Dashboard Creation
📊 Step 1 – Source IP Count (Bar Chart)
```
source="SSH_Log.json" host="GODSPEED" index="ssh_lab" sourcetype="_json" 
| stats count by id.orig_h 
| rename id.orig_h as "Source IP" 
| sort - count
```
<img width="1920" height="867" alt="Screenshot (83)" src="https://github.com/user-attachments/assets/81c7b044-5d95-4e17-8cad-a15ce241d2b2" />


Purpose: Displays which source IPs are initiating SSH connections most frequently.
Visualization: Bar Chart
Panel Title: “Top Source IPs”


📊 Step 2 – Destination IP Count (Bar Chart)

```
source="SSH_Log.json" host="GODSPEED" index="ssh_lab" sourcetype="_json" 
| stats count by id.resp_h 
| rename id.resp_h as "Destination IP" 
| sort - count
```
<img width="1920" height="875" alt="Screenshot (87)" src="https://github.com/user-attachments/assets/3f300880-c706-467e-93a5-259e4642729b" />


Purpose: Highlights which systems are being targeted or accessed most often.
Visualization: Bar Chart
Panel Title: “Top Destination IPs”

📈 Step 3 – Failed SSH Login Count (Single Value)

```
source="SSH_Log.json" host="GODSPEED" index="ssh_lab" sourcetype="_json" auth_success="false" 
| stats count as "Failed SSH Logins"
```
<img width="1920" height="874" alt="Screenshot (86)" src="https://github.com/user-attachments/assets/48553e7d-c415-4802-b377-47783afaed71" />


Purpose: Displays the total number of failed authentication attempts, crucial for detecting brute-force or unauthorized login patterns.
Visualization: Single Value
Panel Title: “Total Failed SSH Logins”


📈 Step 4 – Successful SSH Login Count (Single Value)
```
source="SSH_Log.json" host="GODSPEED" index="ssh_lab" sourcetype="_json" auth_success="true" 
| stats count as "Successful SSH Logins"
```
<img width="1920" height="867" alt="Screenshot (85)" src="https://github.com/user-attachments/assets/86583d1a-4296-432d-a82d-02f1700a7e7a" />


Purpose: Counts successful SSH logins to understand normal access trends or verify legitimate connections.
Visualization: Single Value
Panel Title: “Total Successful SSH Logins”

📋 Step 5 – Source vs Destination IP Table

```
source="SSH_Log.json" host="GODSPEED" index="ssh_lab" sourcetype="_json" 
| stats count by id.orig_h, id.resp_h 
| rename id.orig_h as "Source IP", id.resp_h as "Destination IP", count as "Total Connections" 
| sort - "Total Connections"

```

<img width="1920" height="875" alt="Screenshot (84)" src="https://github.com/user-attachments/assets/0e54ad1a-cf54-4202-a62a-5bc8d774e85b" />

Purpose: Displays communication mapping between source and destination IPs, showing total SSH connection attempts between each pair.
Visualization: Table
Panel Title: “Source–Destination IP Pairs”


📌 Conclusion

On Day 1, you learned how to:

Ingest SSH logs into Splunk from JSON sources.

Use SPL queries to identify failed and successful authentication attempts.

Analyze SSH traffic volume and event distribution.

Build a multi-panel Splunk dashboard to visualize network activity and potential security anomalies.

This practical exercise establishes the foundation for SOC analysis and incident investigation using Splunk’s Search & Reporting features.

👤 Author: Akshat Dwivedi
Linkedin : https://www.linkedin.com/in/akshat-dwivedi1
