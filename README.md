# 🚀 SOC Automation Project

## Scope 
In this cybersecurity project, I built a cloud-based SOC automation lab to gain hands-on experience with SIEM, SOAR, and case management integration. My goal was to create a fully functional home lab environment that simulates a real-world SOC. I deployed **Wazuh** as the SIEM/XDR, **TheHive** for case management, and **Shuffle** for SOAR automation.  
I configured Wazuh to forward alerts into Shuffle workflows, where I parsed event data and extracted indicators of compromise (IoCs) like SHA256 hashes using regex. I automated the creation of cases in TheHive based on specific alert triggers, enriched IOCs with VirusTotal, and set up email notifications to alert analysts of new incidents. I also generated simulated attack telemetry — including Mimikatz credential dumping and suspicious PowerShell activity — to test the detection and response capabilities of the lab.

---

## 🛠️ Technology Utilized

- **Wazuh**: SIEM/XDR platform for alert detection and forwarding.
- **TheHive**: Case management system for incident tracking.
- **Sysmon**: For Windows telemetry collection
- **Shuffle**: SOAR platform for automating enrichment and analyst notifications.
- **Python** (inside Shuffle): Custom parsing and extraction of SHA256 hashes. 
- **VirusTotal**: Threat intelligence source for file and hash reputation lookups.
- **Bash**: Linux scripting for installation and configuration tasks. 
- **PowerShell**: Windows scripting for telemetry generation and configuration tasks.


## ☁️ Infrastructure/Cloud Environment

- **DigitalOcean**: Deployed Ubuntu servers in the cloud to host Wazuh and TheHive, including secure SSH access and firewall configurations.
- **VirtualBox**: Hosted Windows 10 VM locally for telemetry generation and attack simulation.

---

## 📑 Table of Contents

- [Lab Diagram](#lab-diagram)
- [Installation 🖥️](https://github.com/Danielle-Morris-1/SOC-Automation-Project/tree/main?tab=readme-ov-file#installation-%EF%B8%8F)
- [Configuration ⚙️](https://github.com/Danielle-Morris-1/SOC-Automation-Project/tree/main?tab=readme-ov-file#configuration-%EF%B8%8F)
- [Telemetry Generation & Wazuh Ingestion ⚡](#telemetry-generation--wazuh-ingestion-)
- [Shuffle Workflow 🔄](#shuffle-workflow-)
- [Final Reflection 🧠](#final-reflection-)

---

## Lab Diagram 

I mapped out the **logical data flow** between key components:  
- Windows 10 client  
- Wazuh Manager  
- Shuffle (SOAR)  
- TheHive (Case Management)  
- SOC Analyst (email notifications)

The flow included:  
🔀 Client events → Wazuh → Shuffle → Enrichment (VirusTotal) → TheHive Case → Analyst Notification

 ![image](https://github.com/user-attachments/assets/60a3dec6-40ca-4b25-8c46-bf8206e7794d)
 
<details>
<summary> Click to visualize the lab 📈 </summary>

![image](https://github.com/user-attachments/assets/8490e57e-5659-438f-a369-7d994706f282)

</details>

---

## Installation 🖥️

To set up the lab:

- **Windows 10 VM**: Downloaded ISO → Installed manually on VirtualBox → Installed Sysmon for enhanced telemetry
- **Wazuh Server** (DigitalOcean): Deployed Ubuntu droplet → Secured SSH access → Installed Wazuh 4.7 → Extract Wazuh Credentials
- **TheHive Server**: Another Ubuntu droplet → Secured SSH access → Installed Java, Cassandra, Elasticsearch → Installed TheHive 5 → Default Credentials on port 9000

**Verification of Successful Installation:**  
- Sysmon logs were visible in Event Viewer.
- Successfully logged into Wazuh and TheHive dashboards via their public IP.
![image](https://github.com/user-attachments/assets/fd955544-d7c4-4e88-a5c1-9b7983c7d87e)

---

## Configuration ⚙️

### TheHive
- Updated **Cassandra** and **Elasticsearch** configurations for external access.
- Restarted services and cleared old data to prepare a fresh cluster.
- Fixed file permissions for TheHive directories.
- Updated TheHive's `application.conf` with the right IP and cluster names.

![theHive group created ](https://github.com/user-attachments/assets/8f405abf-fa39-4170-ad8c-00252e340b83)

### Wazuh
- Logged into Wazuh dashboard using credentials from install.
- Installed the Windows Agent on the Windows 10 machine.
- Verified agent status: **Connected and Active**.

By the end of this phase, Wazuh was collecting logs, and TheHive was ready for incoming alerts.

![Wazuh Events in Dashboard](https://github.com/user-attachments/assets/023f04f0-2086-4dc3-875e-944245d5c9fd)

<details>
<summary> More Details </summary>

In this part of the project, I configured both TheHive and Wazuh servers and got them running properly, with a Windows 10 client reporting into Wazuh.

  **1. Cassandra**: First, I configured TheHive by editing Cassandra’s configuration files.
  
  - Opened Cassandra config:
    ```bash
    nano /etc/cassandra/cassandra.yaml

  - Updated:

    cluster_name → Danielle-Test-Cluster
            
    listen_address → Hive's public IP
            
    rpc_address → Hive's public IP
            
    seeds → Hive's public IP

  - Stopped Cassandra:
    ```bash
    systemctl stop cassandra

  - Cleared old data:
    ```bash
    rm -rf /var/lib/cassandra/*

  - Restarted Cassandra:
     ```bash
     systemctl start cassandra
  
  - Verified:
     ```bash
     systemctl status cassandra

 
  <details>
  <summary> ▶️ Show Execution Screenshot </summary>
  
   ![Cassandra Running ](https://github.com/user-attachments/assets/6d7e6e93-bf8d-4d58-ac2b-494c482750c5)
 
  </details>




**2. Elasticsearch**: Next, I configured Elasticsearch by editing its configuration file.

  - Opened Elasticsearch config:
    ```bash
    nano /etc/elasticsearch/elasticsearch.yml

  - Updated:

    cluster.name → thehive
    
    node.name → node-1
    
    network.host → Hive's public IP
    
    http.port → 9200 

    cluster.initial_master_nodes → ["node-1"]

  - Started and enabled:
    ```bash
    systemctl start elasticsearch
    systemctl enable elasticsearch

  - Checked status:
    ```bash
    systemctl status elasticsearch

<details>
<summary> ▶️ Show Execution Screenshot </summary>
  
  ![ElasticSearch Running ](https://github.com/user-attachments/assets/7c1b94ae-e038-4f26-b105-e4140b255a08)

</details>

**3. Prepare File Permissions for TheHive**: I made sure TheHive user had proper access to its required directories. 

  - Checked permissions:
    ```bash
    ls -la /opt/thp
     
 - Changed ownership:
    ```bash
    chown -R thehive:thehive /opt/thp

  <details>
  <summary> ▶️ Show Execution Screenshot </summary>
  
  ![TheHive access control ](https://github.com/user-attachments/assets/30095531-a675-4734-8d6e-ac1339ee3586)

  </details>
  
**4. Configure TheHive**  
  - Edited TheHive configuration:
    ```bash
    nano /etc/thehive/application.conf

  - Updated:
  
    Database host IP → Hive's public IP
      
    Cluster name → Danielle-Test-Cluster
      
    Elasticsearch IP → Hive's public IP
      
    Storage path → /opt/thp
      
    Application base URL → http://<Hive's public IP>:9000

   - Started and enabled:
     ```bash
     systemctl start thehive
     systemctl enable thehive

   - Verified:
      ```bash
      systemctl status thehive

 <details>
  <summary> ▶️ Show Execution Screenshot </summary>

  ![TheHive Running](https://github.com/user-attachments/assets/615459db-ed66-492e-b752-87f5e1cd5087)

 </details>
 
**5. Login to TheHive**
  - Accessed: http://<Hive's public IP>:9000 with the Default Credentials.

  - ⚠️ The authentication **failed**, I checked Elasticsearch to see it was not running properly. I learned to fix it by creating a custom JVM options file for Elasticsearch to limit memory usage if needed, and restarting Elasticsearch.

  - Fixed Elasticsearch memory issues by creating:
    ```bash
    nano /etc/elasticsearch/jvm.options.d/jvm.options

  - Restarted Elasticsearch:
    ```bash
    systemctl restart elasticsearch

**6. Configure Wazuh and Add Windows Agent**
  
  - Retrieved dashboard credentials:
      ```bash
      cat /var/ossec/etc/.wazuh-install-passwords.txt
    
 - Logged into Wazuh dashboard.
    
 - Added new agent:
    
      Clicked "Add agent" → Selected Windows → Entered Wazuh public IP and agent name Danielle.
    
    - Ran copied installation command on Windows (PowerShell as Admin)

    - Verified Windows agent appeared as Active in Wazuh dashboard.

 <details>
  <summary> ▶️ Show Execution Screenshot </summary>
  
![image](https://github.com/user-attachments/assets/204cfe0b-d96d-471c-a512-b9eecb56ea9f)
![image](https://github.com/user-attachments/assets/4416e58e-c22f-4971-96e9-eb0e86c9afa1)

 </details>
 
</details>

---

## Telemetry Generation & Wazuh Ingestion ⚡

Creating telemetry steps and ingest into Wazuh:

- **Sysmon Log Collection**: Modified `ossec.conf` on the Windows agent to capture Sysmon logs by specifying the correct event channel.
- **Simulated Attack**: Disabled Defender by adding an exclusion temporarily → Downloaded and ran **Mimikatz** to simulate credential dumping.
  
  ![image](https://github.com/user-attachments/assets/216cc76e-6b5d-4ed8-a417-36b90f4ce322)

- **Detection Challenges**:  
  Initially, no custom Wazuh rules triggered alerts on Mimikatz execution.
- **Enhanced Logging**:
  - Enabled `logall` and `logall_json` in Wazuh Manager for complete archiving.
  - Configured Filebeat to ingest archived logs.
  - Created a new index (`wazuh-archives-*`) to view the data.
    ![image](https://github.com/user-attachments/assets/398062ed-7bbe-471e-b339-7d6a61f076c4)



- **Custom Wazuh Rule**:  
  - Added a new high-severity rule matching Mimikatz process creation in `local_rules.xml` targeting the "original file name" field from Sysmon event ID 1 (process creation).
  - This rule was given a custom ID (rule ID 100002), assigned a high severity (15), and tagged with the MITRE ATT&CK tactic T1003 (Credential Dumping).
 
    ![Local rules for mimikatz](https://github.com/user-attachments/assets/22f1a3a0-984d-4b05-8b2e-2df5e4542058)


- **Validation**:  
  - Executed renaming the Mimikatz binary (`testing.exe`).
  - Confirmed Wazuh alerted based on internal metadata, not filename alone.
   ![mimikatz detected by rule ](https://github.com/user-attachments/assets/c411142e-bf1c-4d81-bd59-1cc4d64a9d3a)
    
<details>
<summary> More Details </summary>
  
First, I backed up the Wazuh agent’s configuration file (`ossec.conf`) on the Windows 10 machine. I made a backup copy (`ossec.conf.backup`) in case I needed to revert changes.

Next, I modified the Wazuh agent configuration to ingest Sysmon logs, which are critical for detailed event monitoring. Using the Windows Event Viewer, I located the correct channel name (`Microsoft-Windows-Sysmon/Operational`) and edited `ossec.conf` to add a `<localfile>` block for this channel. I restarted the Wazuh Agent service so the new settings would take effect.

With Sysmon logs being collected, I prepared for testing by downloading **Mimikatz** — a well-known tool for credential extraction. To avoid automatic deletion, I temporarily disabled **Windows Defender** (by excluding the Downloads folder) and then extracted the Mimikatz zip file.

I launched an administrative PowerShell session, navigated to the extracted folder, and executed `mimikatz.exe`.

![image](https://github.com/user-attachments/assets/2af373e3-fa38-4edb-881a-471afdddfcfc)

Initially, I checked the Wazuh dashboard for any alerts related to Mimikatz; however, because no specific detection rules were triggered yet, events did not immediately appear.

To capture all activity, I adjusted the Wazuh manager’s configuration by setting `logall` and `logall_json` to `"yes"` in its `ossec.conf` file, ensuring all events would be archived — not just those matching existing rules. I restarted the Wazuh manager service to apply the changes.

To make archived logs searchable, I edited the `filebeat.yml` file to enable archive ingestion (`archives.enabled: true`) and restarted the Filebeat service.

In the Wazuh dashboard, I created a new index pattern (`wazuh-archives-*`) to access archived events. Using the **Discover** section, I searched the archives for "mimikatz" events.

To improve detection, I created a custom Wazuh rule. Through the dashboard, I added a new rule in `local_rules.xml` targeting the "original file name" field from Sysmon event ID 1 (process creation). This rule was given a custom ID (rule ID `100002`), assigned a high severity (`15`), and tagged with the MITRE ATT&CK tactic `T1003` (Credential Dumping). I then restarted the Wazuh manager service to activate the rule.

 ![image](https://github.com/user-attachments/assets/9f273b83-6706-4432-b313-18658e0d5e4e)

Finally, I tested the custom rule by executing **Mimikatz** again — this time renaming the executable to `testing.exe` to confirm that the detection was based on the internal metadata, not the file name. After refreshing the Wazuh dashboard, I verified that the new custom alert appeared, successfully detecting the Mimikatz activity even with the file renamed.

![mimikatz](https://github.com/user-attachments/assets/2adb05dd-a1c9-4ffd-967a-d3f9297f49af)

</details>

---

## Shuffle Workflow 🔄

I moved on to setting up Shuffle to automate alert processing and notification.

![image](https://github.com/user-attachments/assets/12dff7bc-9980-45ae-a943-bf1379d5bd41)

### Key Steps:

1. **Webhook Setup**: Created a Shuffle webhook to receive Wazuh alerts.

      ![image](https://github.com/user-attachments/assets/509ec506-c7b6-422c-ad3b-71eeae91e721)


3. **Regex/Python Parsing**:  
   - Extracted SHA256 hashes manually inside Shuffle using a small Python script after regex challenges.
     ![image](https://github.com/user-attachments/assets/01e9fa4e-e616-43c6-a825-7d573910c659)

4. **VirusTotal Enrichment**:
   - Integrated API key into Shuffle.
   - Queried VirusTotal for SHA256 hash reports, retrieving "malicious" counts.

     ![image](https://github.com/user-attachments/assets/e211dc55-8c23-457d-9a47-5874188e7180)

5. **TheHive Alert Creation**:
   - Forked and modified TheHive Shuffle app for compatibility.
   - Parsed alert fields: **description, summary, command line, process ID, user**.

     ![image](https://github.com/user-attachments/assets/6947942b-a94f-49b3-93d9-1a0af77cc0d2)
     
6. **Email Notification**:
   - Set subject ("Mimikatz Detected"), included UTC timestamp, alert details, and host information.
   - Successfully received structured emails confirming detection!
     ![image](https://github.com/user-attachments/assets/8647f0a0-0342-4bc4-899c-9da573dcd9b5)


<details>
<summary> More Details </summary>

In this part of the lab, I moved onto connecting **Shuffle** (SOAR platform) with both **TheHive** and **VirusTotal**, setting up the workflow to automatically enrich alerts and notify analysts.

First, I created a **webhook trigger** inside Shuffle so it could receive alerts from Wazuh. After creating the webhook, I edited my Wazuh manager's integration configuration to send specific alerts (those matching rule ID `100002` — the custom Mimikatz detection rule) to the new webhook URL. Once that was done, I triggered a **Mimikatz** event on the Windows client to confirm that Wazuh alerts were reaching Shuffle properly.

Next, I built the initial workflow inside Shuffle. The planned flow was:

  Wazuh Alert via Webhook → Extract SHA256 Hash → Query VirusTotal → Create Alert in TheHive → Send Email Notification to Analyst


Before enrichment could happen, I needed to parse the correct **SHA256** hash out of the alert. The hash values were bundled together with labels like `sha1=`, `sha256=`, etc., so I couldn’t just send the whole string to VirusTotal.

At first, I tried using **regex** inside Shuffle’s **Regex Capture Group** feature to pull the SHA256 value directly, but Shuffle’s regex engine had trouble reliably parsing the `Agent Group` field. To solve this, I wrote a small **Python** script inside Shuffle to manually extract the `sha256` value from the incoming event JSON. After that was working, I was able to use regex to correctly pull the `Agent Group`.

![Python Success](https://github.com/user-attachments/assets/ca8d90dc-83b7-4811-84f3-84fac35c81dc)

With parsing in place, I moved on to **VirusTotal enrichment**. After setting up VirusTotal inside Shuffle by copying my API key, I was able to successfully pull data, including the `malicious` count for hash lookups.

![image](https://github.com/user-attachments/assets/bedfaf29-65ea-4e81-833a-4e867c194274)

To connect Shuffle to **TheHive**, I had to fork and edit the **TheHive app** inside Shuffle to make it compatible with the specific instance I was using. After setting up the connection, I configured the alert fields to parse key details from the execution arguments. 

Before testing, I temporarily modified the **cloud firewall settings** (on DigitalOcean) to allow inbound traffic on port `9000` — the port where my TheHive instance was running. Once configured, I reran the Shuffle workflow. Checking inside TheHive, the alert was successfully created with all the populated fields: `description`, `summary`, `process ID`, `command line`, and `user` information — making it very analyst-friendly for rapid triage.

Moving into the **email** portion, the video demonstrated how to configure sending an email by entering any valid recipient address. For the message setup, the subject line was set to `"Mimikatz detected"`, a timestamp was included by pulling the **UTC time** from the execution arguments, and additional details like the `alert title` and `computer name` were added to provide context about where the detection occurred.

After saving the updated workflow and rerunning it, the email was successfully received, containing the subject, time, title, and host information.


</details>

> **Tip 💡:** Opening port `9000` on TheHive server’s firewall was critical for successful integration with Shuffle.

---

## Final Reflection 🧠

Building this project from the ground up gave me a deeper understanding of how SOC ecosystems operate beyond theory. It showed me the importance of clear planning, problem-solving under pressure, and the power of automation in making security operations more efficient. Along the way, I strengthened my understanding of **SIEM**, **SOAR**, and **case management** technologies — but even more importantly, I built the mindset needed to keep adapting and learning in the cybersecurity field. 

Finishing this project leaves me excited and motivated to take on even more complex challenges ahead. 🌟

---

