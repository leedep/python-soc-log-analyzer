# python-soc-log-analyzer
A Python-based SOC log analyzer for parsing security logs, detecting suspicious activities, scoring risks, and generating alert reports.
# Python-based SOC Log Analyzer

A lightweight Security Operations Center (SOC) log analysis tool built with Python.  
It parses and normalizes security logs, detects suspicious activities using rule-based correlation, assigns risk scores, and generates alert reports to support SOC analysts in security monitoring and incident triage.

---

## Project Overview

SOC teams often need to review large volumes of security logs from authentication systems, web servers, firewalls, and intrusion detection systems.  
This project aims to simulate a simplified SOC log analysis workflow by using Python to identify suspicious activities such as brute-force attacks, privileged account logins, web attack attempts, and abnormal network behavior.

The goal of this project is not to replace a full SIEM platform, but to demonstrate how security logs can be parsed, normalized, analyzed, and converted into actionable alerts.

---

## Features

- Parse Linux authentication logs
- Normalize raw logs into structured security events
- Detect brute-force login attempts
- Detect suspicious privileged account logins
- Assign risk scores based on event severity and behavior patterns
- Generate CSV and JSON alert reports
- Provide sample logs and sample outputs for testing
- Designed with modular parsers and detection rules for future expansion

---

## Detection Scenarios

| Detection Rule | Description | Severity |
|---|---|---|
| Brute Force Attack | Detects repeated failed login attempts from the same source IP within a short time window | High |
| Suspicious Admin Login | Detects successful login attempts to privileged accounts such as root, admin, or administrator | Medium |
| Repeated Authentication Failure | Identifies high-frequency failed login events | Medium |
| Web Attack Attempt | Detects suspicious URL patterns such as SQL injection, XSS, or directory traversal | High |
| Port Scan Behavior | Detects one source IP connecting to multiple ports in a short period | High |

---

## Project Architecture

```text
                Raw Logs
                   |
                   v
        +----------------------+
        |      Log Parsers     |
        | auth / web / firewall|
        +----------------------+
                   |
                   v
        +----------------------+
        |  Event Normalization |
        +----------------------+
                   |
                   v
        +----------------------+
        |   Detection Engine   |
        | rules + correlation  |
        +----------------------+
                   |
                   v
        +----------------------+
        | Risk Scoring Module  |
        +----------------------+
                   |
                   v
        +----------------------+
        | Reports / Dashboard  |
        | CSV / JSON / charts  |
        +----------------------+
