# Intrusion detection network security monitoring with Security Onion

Goal: enhance network security by utilizing Security Onion for intrusion detection and monitoring, focusing on alert triage, threat hunting, and detection engineering to identify and mitigate malicious activities effectively.

I installed and configured 
- Securuty Onion
- Windows 10
- Kali Linux
  
Attack simulation

![{31FA8E29-0770-4EB3-82CD-6AEEAF4B85E4}](https://github.com/user-attachments/assets/dc575218-44e9-45a1-9403-ed1e10de929a)
Before simulating an attack security onion should be ON and tcpdump also ON and capturing packets.

Using my Kali Linux machine, I conducted network discovery with the following commands:
- sudo netdiscover -r 192.168.100.0/24
- sudo nmap -sC -sV -Pn -A -T4 192.168.100.131

The scan showed that port 22/tcp is open. Based on the information, I assume the target is running a Windows OS, so any exploit should be crafted for Windows.

  Additionally, DNS enumeration revealed a user named John, and I was able to identify his email.

  To proceed with creating the exploit, I will:

  Launch the Social-Engineer Toolkit (SET) using sudo setoolkit

  Create a payload with option 4.

  ![Screenshot_2024-10-31_15_11_43](https://github.com/user-attachments/assets/e33d2de5-37f0-4445-b239-a0257a56820e)


To proceed with the phishing attack, I will use Emkei's Fake Mailer (https://emkei.cz/) to send an email to John. The email will contain an attachment with the malicious payload crafted to exploit the Windows environment identified earlier.
![{CD9E2DA5-D5B6-425C-94A1-D7812873DBB8}](https://github.com/user-attachments/assets/9f260263-ba03-411e-b663-c86b133f8779)

When John (on a Windows 10 machine) clicks the link in the phishing email, the malicious payload executes, giving the attacker control over the victim's machine.

When John clicked the malicious link, Security Onion generated an alert due to suspicious network activity from his Windows 10 machine. The IDS flagged this as potentially malicious, identifying abnormal traffic directed to the attacker’s Kali Linux machine. This alert highlights Security Onion’s effectiveness in detecting and reporting compromised systems. 
![{1B360952-5049-499A-968F-0456E513C04A}](https://github.com/user-attachments/assets/28631e68-778d-45e8-b75e-704df47fff98)

I opened a red bell alert labeled “...file download HTTP” in Security Onion, then drilled down for detailed information on the event. Following this, I closed the open port on the firewall and deleted the malicious payload from John’s machine.

I conducted alert triage by reviewing and dismissing false positives, then created a case for confirmed threats. Using Suricata for alert details, Zeek for metadata analysis, and VirusTotal for further insights into the malicious files, I gathered evidence to support the investigation.

Threat Hunting: Threat hunting involves proactively searching for suspicious behavior within the logs and data accumulated in Security Onion. The goal is to identify problematic events that may not be captured by existing alert signatures. By analyzing this data, threat hunters can uncover hidden threats, enhance situational awareness, and respond to potential security incidents before they escalate.

Detection Engineering: Detection engineering focuses on refining and tuning rules to improve the accuracy and effectiveness of intrusion detection systems. Tools like Suricata are used to create and adjust rules for identifying threats, while Yara is employed to detect malicious files based on specific patterns. Additionally, Sigma rules can be implemented to search for indicators of compromise (IoCs) across log files, ensuring a robust defense against evolving threats.

