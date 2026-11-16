# AWS-Splunk-Threat-Detection
Simulated brute-force attack detection and incident response using AWS CloudTrail, EC2, and Splunk SIEM. Mapped to the MITRE ATT&amp;CK framework.
#  AWS Cloud Security & Splunk SIEM: Brute-Force Authentication Detection

## Executive Summary
This project demonstrates the end-to-end configuration of an AWS cloud security monitoring environment and the active detection of brute-force authentication attacks using Splunk. By leveraging AWS CloudTrail, Amazon GuardDuty, and EC2 system logs, this lab simulates an external attack vector, captures the resulting telemetry, and utilizes custom Search Processing Language (SPL) queries to identify and alert on the malicious activity. 

This repository serves as a showcase of cloud infrastructure monitoring, log aggregation, and threat detection aligned with industry-standard frameworks.

##  Tools & Technologies Used
* **Cloud Infrastructure:** AWS (EC2, S3, IAM, CloudTrail, GuardDuty)
* **SIEM & Log Analytics:** Splunk Enterprise, Search Processing Language (SPL)
* **Operating Systems:** Linux (Ubuntu)
* **Security Frameworks:** MITRE ATT&CK Framework
* **Endpoint Security:** Wazuh (Conceptual integration for EDR)

##  MITRE ATT&CK Mapping
| Tactic | Technique | ID | Description |
|---|---|---|---|
| **Credential Access** | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Adversaries may guess passwords to gain access to accounts. |
| **Initial Access** | Valid Accounts: Cloud Accounts | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Adversaries may compromise cloud accounts to gain access to the environment. |

##  Architecture & Telemetry Flow
1. **Target Environment:** An AWS EC2 instance running Linux is exposed to simulate a vulnerable web server or jump box.
2. **Log Generation:** `auth.log` (Linux) records failed/successful SSH login attempts. AWS CloudTrail monitors IAM and console activity, while GuardDuty scans for unexpected network behavior.
3. **Log Aggregation:** Logs are forwarded via Splunk Universal Forwarder and AWS S3 buckets into the Splunk Indexer.
4. **Detection & Alerting:** Splunk parses the data, where custom SPL dashboards and alerts detect velocity thresholds indicative of a brute-force attack.

##  Methodology & Attack Simulation
### Phase 1: Infrastructure Provisioning
* Deployed an AWS EC2 Linux instance with a purposely permissive Security Group (temporarily allowing SSH from specific testing IPs).
* Configured AWS CloudTrail to log API activity to a secure S3 bucket.
* Applied strict IAM policies with least-privilege access for the logging roles.

### Phase 2: Attack Simulation
* Utilized a testing machine to launch a simulated SSH dictionary attack against the EC2 instance using Hydra/Nmap scripts.
* Generated intentionally noisy authentication failures to test SIEM ingestion thresholds.

### Phase 3: Detection with Splunk (SPL)
To detect the brute-force activity, the following SPL query was constructed to flag an IP address attempting more than 10 failed logins within a 5-minute window:

```spl
index=aws_ec2_logs sourcetype=linux_secure action=failure
| stats count by src_ip, user
| where count > 10
| eval Threat_Level="High", Mitigation="Block IP at AWS Security Group or WAF"
| table src_ip, user, count, Threat_Level, Mitigation
| sort - count
