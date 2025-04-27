# 🚀 SOC Automation Project

## Scope 🔍
In this cybersecurity project, I built a cloud-based SOC automation lab to gain hands-on experience with SIEM, SOAR, and case management integration. My goal was to create a fully functional home lab environment that simulates a real-world SOC. I deployed **Wazuh** as the SIEM/XDR, **TheHive** for case management, and **Shuffle** for SOAR automation.  
I configured Wazuh to forward alerts into Shuffle workflows, where I parsed event data and extracted indicators of compromise (IoCs) like SHA256 hashes using regex. I automated the creation of cases in TheHive based on specific alert triggers, enriched IOCs with VirusTotal, and set up email notifications to alert analysts of new incidents. I also generated simulated attack telemetry — including Mimikatz credential dumping and suspicious PowerShell activity — to test the detection and response capabilities of the lab.

---

## 🛠️ Technology Utilized

- **Wazuh**: SIEM/XDR platform for alert detection and forwarding.
- **TheHive**: Case management system for incident tracking and triage.
- **Shuffle**: SOAR platform for automating enrichment and analyst notifications.
- **VirusTotal**: Threat intelligence source for file and hash reputation lookups.
- **Python** (inside Shuffle): Custom parsing and extraction of SHA256 hashes.

## ☁️ Infrastructure/Cloud Environment

- **DigitalOcean**: Deployed Ubuntu servers in the cloud to host Wazuh and TheHive, including secure SSH access and firewall configurations.
- **VirtualBox**: Hosted Windows 10 VM locally for telemetry generation and attack simulation.

---

## 📑 Table of Contents

- [Lab Diagram](#lab-diagram)
- [Installation 🖥️](#installation-)
- [Configuration ⚙️](#configuration-)
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
✅ Client events → Wazuh → Shuffle → Enrichment (VirusTotal) → TheHive Case → Analyst Notification.

<details>
<summary>🗺️ Click to visualize the flow</summary>

**
</details>

---

## Installation 🖥️

To set up the lab:

- **Windows 10 VM**: Downloaded ISO → Installed manually on VirtualBox → Installed Sysmon for enhanced telemetry.  
- **Wazuh Server** (DigitalOcean): Deployed Ubuntu droplet → Secured SSH access → Installed Wazuh 4.7 → Extract Wazuh Credentials
- **TheHive Server**: Another Ubuntu droplet → Secured SSH access → Installed Java, Cassandra, Elasticsearch → Installed TheHive 5 → Default Credentials on port 9000

**Verification of Successful Installation:**  
- Sysmon logs were visible in Event Viewer.
- Successfully logged into Wazuh and TheHive dashboards via their public IP.

---

## Configuration ⚙️

### TheHive
- Updated **Cassandra** and **Elasticsearch** configurations for external access.
- Restarted services and cleared old data to prepare a fresh cluster.
- Fixed file permissions for TheHive directories.
- Updated TheHive's `application.conf` with the right IP and cluster names.

![TheHive Running](https://github.com/user-attachments/assets/615459db-ed66-492e-b752-87f5e1cd5087)
![theHive group created ](https://github.com/user-attachments/assets/8f405abf-fa39-4170-ad8c-00252e340b83)

### Wazuh
- Logged into Wazuh dashboard using credentials from install.
- Installed the Windows Agent on the Windows 10 machine.
- Verified agent status: **Connected and Active**.

By the end of this phase, Wazuh was collecting logs, and TheHive was ready for incoming alerts.

![Wazuh Events in Dashboard](https://github.com/user-attachments/assets/023f04f0-2086-4dc3-875e-944245d5c9fd)

---

## Telemetry Generation & Wazuh Ingestion ⚡

Creating telemetry steps and ingest into Wazuh:

- **Sysmon Log Collection**: Modified `ossec.conf` on the Windows agent to capture Sysmon logs by specifying the correct event channel.
- **Simulated Attack**: Disabled Defender exclusions temporarily → Downloaded and ran **Mimikatz** to simulate credential dumping.
- **Detection Challenges**:  
  Initially, no custom Wazuh rules triggered alerts on Mimikatz execution.
- **Enhanced Logging**:
  - Enabled `logall` and `logall_json` in Wazuh Manager for complete archiving.
  - Configured Filebeat to ingest archived logs.
  - Created a new index (`wazuh-archives-*`) to view the data.
- **Custom Wazuh Rule**:  
  - Added a new high-severity rule matching Mimikatz process creation in `local_rules.xml` targeting the "original file name" field from Sysmon event ID 1 (process creation).
  - This rule was given a custom ID (rule ID 100002), assigned a high severity (15), and tagged with the MITRE ATT&CK tactic T1003 (Credential Dumping).
 
    ![Local rules for mimikatz](https://github.com/user-attachments/assets/22f1a3a0-984d-4b05-8b2e-2df5e4542058)

    ![mimikatz detected by rule ](https://github.com/user-attachments/assets/c411142e-bf1c-4d81-bd59-1cc4d64a9d3a)

- **Validation**:  
  - Executed renaming the Mimikatz binary (`testing.exe`).
  - Confirmed Wazuh alerted based on internal metadata, not filename alone. ![mimikatz](https://github.com/user-attachments/assets/2adb05dd-a1c9-4ffd-967a-d3f9297f49af)

<details>
<summary> Click to expand detailed explanation </summary>
  
First, I backed up the Wazuh agent’s configuration file (`ossec.conf`) on the Windows 10 machine. I made a backup copy (`ossec.conf.backup`) in case I needed to revert changes.

Next, I modified the Wazuh agent configuration to ingest Sysmon logs, which are critical for detailed event monitoring. Using the Windows Event Viewer, I located the correct channel name (`Microsoft-Windows-Sysmon/Operational`) and edited `ossec.conf` to add a `<localfile>` block for this channel. I restarted the Wazuh Agent service so the new settings would take effect.

With Sysmon logs being collected, I prepared for testing by downloading **Mimikatz** — a well-known tool for credential extraction. To avoid automatic deletion, I temporarily disabled **Windows Defender** (by excluding the Downloads folder) and then extracted the Mimikatz zip file.

I launched an administrative PowerShell session, navigated to the extracted folder, and executed `mimikatz.exe`.

Initially, I checked the Wazuh dashboard for any alerts related to Mimikatz; however, because no specific detection rules were triggered yet, events did not immediately appear.

To capture all activity, I adjusted the Wazuh manager’s configuration by setting `logall` and `logall_json` to `"yes"` in its `ossec.conf` file, ensuring all events would be archived — not just those matching existing rules. I restarted the Wazuh manager service to apply the changes.

To make archived logs searchable, I edited the `filebeat.yml` file to enable archive ingestion (`archives.enabled: true`) and restarted the Filebeat service.

In the Wazuh dashboard, I created a new index pattern (`wazuh-archives-*`) to access archived events. Using the **Discover** section, I searched the archives for "mimikatz" events.

To improve detection, I created a custom Wazuh rule. Through the dashboard, I added a new rule in `local_rules.xml` targeting the "original file name" field from Sysmon event ID 1 (process creation). This rule was given a custom ID (rule ID 100002), assigned a high severity (`15`), and tagged with the MITRE ATT&CK tactic `T1003` (Credential Dumping). I then restarted the Wazuh manager service to activate the rule.

 ![image](https://github.com/user-attachments/assets/9f273b83-6706-4432-b313-18658e0d5e4e)

Finally, I tested the custom rule by executing **Mimikatz** again — this time renaming the executable to `testing.exe` to confirm that the detection was based on the internal metadata, not the file name. After refreshing the Wazuh dashboard, I verified that the new custom alert appeared, successfully detecting the Mimikatz activity even with the file renamed.

</details>

---

## Shuffle Workflow 🔄

I moved on to setting up Shuffle to automate alert processing and notification.

![image](https://github.com/user-attachments/assets/12dff7bc-9980-45ae-a943-bf1379d5bd41)

### Key Steps:

1. **Webhook Setup**: Created a Shuffle webhook to receive Wazuh alerts.


   ![Wazuh Mimikatz detected in Shuffle ](https://github.com/user-attachments/assets/c5271647-ff4e-43a7-9080-452aeabd3f86)

3. **Regex/Python Parsing**:  
   - Extracted SHA256 hashes manually inside Shuffle using a small Python script after regex challenges.
     ![image](https://github.com/user-attachments/assets/8325d8cc-e9be-42f8-85cf-f656b30bfe76)

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

<details>
<summary>Click to expand detailed workflow explanation</summary>

In this part of the lab, I moved onto connecting **Shuffle** (SOAR platform) with both **TheHive** and **VirusTotal**, setting up the workflow to automatically enrich alerts and notify analysts.

First, I created a **webhook trigger** inside Shuffle so it could receive alerts from Wazuh. After creating the webhook, I edited my Wazuh manager's integration configuration to send specific alerts (those matching rule ID `100002` — the custom Mimikatz detection rule) to the new webhook URL. Once that was done, I triggered a **Mimikatz** event on the Windows client to confirm that Wazuh alerts were reaching Shuffle properly.

Next, I built the initial workflow inside Shuffle. The planned flow was:

  Wazuh Alert via Webhook → Extract SHA256 Hash → Query VirusTotal → Create Alert in TheHive → Send Email Notification to Analyst


Before enrichment could happen, I needed to parse the correct **SHA256** hash out of the alert. The hash values were bundled together with labels like `sha1=`, `sha256=`, etc., so I couldn’t just send the whole string to VirusTotal.

At first, I tried using **regex** inside Shuffle’s **Rex Capture Group** feature to pull the SHA256 value directly, but Shuffle’s regex engine had trouble reliably parsing the `Agent Group` field. To solve this, I wrote a small **Python** script inside Shuffle to manually extract the `sha256` value from the incoming event JSON. After that was working, I was able to use regex to correctly pull the `Agent Group`.

With parsing in place, I moved on to **VirusTotal enrichment**. After setting up VirusTotal inside Shuffle by copying my API key, I was able to successfully pull data, including the `malicious` count for hash lookups.

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

