ADMIN_ACCOUNTS = {"root", "admin", "administrator"}


def detect_suspicious_admin_login(events: list[dict]) -> list[dict]:
    alerts = []

    for event in events:
        if (
            event["event_type"] == "successful_login"
            and event["username"].lower() in ADMIN_ACCOUNTS
        ):
            alerts.append(
                {
                    "alert_type": "Suspicious Admin Login",
                    "source_ip": event["source_ip"],
                    "username": event["username"],
                    "severity": "Medium",
                    "risk_score": 60,
                    "description": (
                        f"Successful login to privileged account "
                        f"'{event['username']}' from {event['source_ip']}."
                    ),
                    "timestamp": event["timestamp"],
                }
            )

    return alerts
