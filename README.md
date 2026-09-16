# SOC Investigation Labs

A practical security operations portfolio covering alert triage, detection engineering, threat hunting, incident response, cloud security, identity security, malware triage, and SOC automation.

Each project is designed around a clear analyst problem. Most projects include synthetic telemetry, a detection or analysis engine, MITRE ATT&CK context, a command line entry point, and a structured report.

## New projects

| Project | Focus |
| --- | --- |
| [Identity Threat Detector](identity_threat_detector) | MFA push fatigue, risky OAuth consent, token replay, and legacy authentication |
| [SaaS Account Takeover Detector](saas_account_takeover_detector) | Correlated identity, mailbox, file, and administrative abuse |
| [Security Telemetry Health Monitor](security_telemetry_health_monitor) | Silent log sources, ingestion delay, parser failure, schema drift, retention, and clock skew |

## Project index

### Detection engineering and SIEM

* [Detection as Code](detection_as_code)
* [Detection Maturity Scorecard](detection_maturity_scorecard)
* [IDS Signature Engine](ids_signature_engine)
* [Log Correlation Engine](log_correlation_engine)
* [Mini SIEM Platform](mini_siem_platform)
* [SIEM Log Parser](siem_log_parser)
* [SIEM Rule Validator](siem_rule_validator)
* [SOC Automation Engine](soc_automation_engine)
* [Splunk SPL Detection Library](splunk_spl_detection_library)
* [Distributed Pentesting Detection Engineering](distributed_pentesting_detection_engineering)

### Identity and Active Directory

* [Identity Threat Detector](identity_threat_detector)
* [Active Directory Attack Detector](active_directory_attack_detector)
* [Active Directory Health Auditor](ad_health_auditor)
* [Attack Path Graph](attack_path_graph)
* [AWS IAM Auditor](aws_iam_auditor)
* [Brute Force Detector](brute_force_detector)
* [Credential Stuffing Detector](credential_stuffing_detector)
* [Impossible Travel Detector](impossible_travel_detector)
* [Kerberoasting Detector](kerberoasting_detector)
* [Password Policy Analyser](password_policy_analyser)
* [Privilege Escalation Detector](privilege_escalation_detector)
* [UEBA Insider Threat Detector](ueba_insider_threat_detector)
* [Zero Trust Policy Auditor](zero_trust_policy_auditor)

### Cloud, container, API, and SaaS security

* [API Security Tester](api_security_tester)
* [Attack Surface Mapper](attack_surface_mapper)
* [AWS Security Automation](aws_security_automation)
* [Cloud Credential Abuse Detector](cloud_credential_abuse)
* [Cloud Misconfiguration Scanner](cloud_misconfiguration_scanner)
* [Container Security Scanner](container_security_scanner)
* [Crypto Exchange Security Monitor](crypto_exchange_security_monitor)
* [Kubernetes Runtime Detector](k8s_runtime_detector)
* [SaaS Account Takeover Detector](saas_account_takeover_detector)
* [Serverless Security Analyzer](serverless_security_analyzer)
* [Supply Chain Detector](supply_chain_detector)

### Endpoint, malware, and ransomware

* [EDR Log Analyser](edr_log_analyser)
* [LOLBAS Detector](lolbas_detector)
* [Malware File Reputation Scanner](malware_file_reputation_scanner)
* [Malware Hash Scanner](malware_hash_scanner)
* [Memory Injection Detector](memory_injection_detector)
* [Ransomware Behaviour Detector](ransomware_behaviour_detector)
* [Ransomware Early Warning](ransomware_early_warning)
* [Static Malware Triage](static_malware_triage)

### Network, DNS, and command and control

* [Beaconing Detector](beaconing_detector)
* [C2 Jitter Analyzer](c2_jitter_analyzer)
* [DNS Exfiltration Detector](dns_exfil_detector)
* [DNS Security Monitor](dns_security_monitor)
* [Firewall Rule Auditor](firewall_rule_auditor)
* [Lateral Movement Tracker](lateral_movement_tracker)
* [Network Anomaly Detector](network_anomaly_detector)
* [Network Baseline Detector](network_baseline_detector)
* [Recon Detector](recon_detector)

### Threat intelligence, email, and adversary tracking

* [Dark Web Threat Monitor](darkweb_threat_monitor)
* [Honeypot Attacker Profiler](honeypot_attacker_profiler)
* [Phishing Email Analyser](phishing_email_analyser)
* [Phishing Infrastructure Detector](phishing_infra_detector)
* [Threat Campaign Tracker](threat_campaign_tracker)
* [Threat Intel Enrichment](threat_intel_enrichment)
* [Threat Intel Matcher](threat_intel_matcher)

### Incident response, hunting, and SOC operations

* [Alert Fatigue Optimizer](alert_fatigue_optimizer)
* [Digital Forensics Artifact Collector](digital_forensics_artifact_collector)
* [Incident Severity Engine](incident_severity_engine)
* [Incident Timeline](incident_timeline)
* [Incident Timeline Reconstructor](incident_timeline_reconstructor)
* [Insider Threat Detector](insider_threat_detector)
* [Log Tampering Detector](log_tampering_detector)
* [Patch Compliance Tracker](patch_compliance_tracker)
* [Posture Dashboard](posture_dashboard)
* [Security Awareness Tracker](security_awareness_tracker)
* [Security Telemetry Health Monitor](security_telemetry_health_monitor)
* [SOAR Decision Engine](soar_decision_engine)
* [SOAR Playbook Engine](soar_playbook_engine)
* [SOC Metrics Dashboard](soc_metrics_dashboard)
* [Threat Hunt Framework](threat_hunt_framework)
* [Threat Hunt Hypothesis Builder](threat_hunt_hypothesis)
* [Threat Hunting Workbook](threat_hunting_workbook)
* [Vulnerability Triage Engine](vulnerability_triage_engine)

## Quick start

Most projects use only the Python standard library.

```bash
cd identity_threat_detector
python main.py
```

Projects with external dependencies include their own `requirements.txt`. Development and repository tests use:

```bash
python -m pip install -r requirements_dev.txt
python -m pytest
```

## Repository quality

The automated suite validates JSON fixtures, exercises every command line entry point with its bundled sample data, checks the safe condition evaluator, and verifies Mini SIEM API defaults. GitHub Actions runs the suite on every push and pull request.

All projects are production structured demonstrations built with synthetic data. Before operational use, connect trusted telemetry, tune thresholds to the environment, add organization specific response procedures, and validate detections against representative benign and malicious activity.

## License

Released under the [MIT License](LICENSE).
