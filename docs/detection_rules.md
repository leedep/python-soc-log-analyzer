# Detection Rules

This document explains the detection rules used in the Python-based SOC Log Analyzer.

---

## 1. Brute Force Attack Detection

### Detection Logic

If the same source IP generates **5 or more failed login attempts within 5 minutes**, the analyzer raises a **high-severity brute-force alert**.

### Security Rationale

Repeated failed login attempts from the same IP address may indicate password guessing, credential stuffing, or automated brute-force activity.

### Fields Used

- `timestamp`
- `source_ip`
- `username`
- `event_type`
- `status`

### Example Alert

```json
{
  "alert_type": "Brute Force Attack",
  "source_ip": "192.168.1.50",
  "severity": "High",
  "risk_score": 80,
  "description": "192.168.1.50 generated 5 failed login attempts within 5 minutes."
}
````

---

## 2. Suspicious Admin Login Detection

### Detection Logic

If a successful login is made to a privileged account such as `root`, `admin`, or `administrator`, the analyzer raises a **medium-severity alert**.

### Security Rationale

Privileged account logins are high-value events in SOC monitoring. A successful login to an administrative account may require further investigation, especially when it comes from an unfamiliar source IP.

### Fields Used

* `timestamp`
* `source_ip`
* `username`
* `event_type`
* `status`

### Example Alert

```json
{
  "alert_type": "Suspicious Admin Login",
  "source_ip": "203.0.113.10",
  "username": "admin",
  "severity": "Medium",
  "risk_score": 60,
  "description": "Successful login to privileged account 'admin' from 203.0.113.10."
}
```

````

