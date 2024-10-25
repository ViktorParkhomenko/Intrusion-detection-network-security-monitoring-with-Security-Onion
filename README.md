# Intrusion detection network security monitoring with Security Onion

Goal: enhance network security by utilizing Security Onion for intrusion detection and monitoring, focusing on alert triage, threat hunting, and detection engineering to identify and mitigate malicious activities effectively.

1. I installed and configured 
- securuty onion
- windows 7
- kali linux 
2. attack simulation
   ![{31FA8E29-0770-4EB3-82CD-6AEEAF4B85E4}](https://github.com/user-attachments/assets/dc575218-44e9-45a1-9403-ed1e10de929a)
- make sure security onion is on and tcpdump also on and capturing packets.
- lounch linux
  sudo netdiscovery -r 10.0.2.0/24 - windows 7
  sudo nmap -sC -sV -Pn -A -T4 10.0.2.4
  22/tcp open
based on info provided i assum its run windows os, so i should make exploit based on windows  
- from dns enumeration i identified one user called john and i know his email
- to make exploit run
  sudo setoolkit
  i need te create payload
  set payload option 2
  set fishing email https://emkei.cz/ to john with attached malitious payload 
 ![{0BDFAC70-4DE8-4286-8C9F-F65588D021C5}](https://github.com/user-attachments/assets/acd44282-1efe-4d50-bb58-e47a9447850d)
  - on a John's machine click on that link
  - after that attacker took a control on a victim machine.
    3. On a Alert section suspicious scans 
![{1B360952-5049-499A-968F-0456E513C04A}](https://github.com/user-attachments/assets/28631e68-778d-45e8-b75e-704df47fff98)
  -  open one of the red bell alert "...file download HTTP" than drilldown 

close that open port and delete payload. 



  
Alert triage and case creation. Dismiss false positives. Tools Suricata (alerts), Zeek (metadata), VurusTotal (details about malicious files)



Threat Hunting: Threat hunting involves proactively searching for suspicious behavior within the logs and data accumulated in Security Onion. The goal is to identify problematic events that may not be captured by existing alert signatures. By analyzing this data, threat hunters can uncover hidden threats, enhance situational awareness, and respond to potential security incidents before they escalate.

Detection Engineering: Detection engineering focuses on refining and tuning rules to improve the accuracy and effectiveness of intrusion detection systems. Tools like Suricata are used to create and adjust rules for identifying threats, while Yara is employed to detect malicious files based on specific patterns. Additionally, Sigma rules can be implemented to search for indicators of compromise (IoCs) across log files, ensuring a robust defense against evolving threats.

