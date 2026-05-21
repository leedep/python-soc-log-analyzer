from collections import defaultdict
from datetime import timedelta


def detect_brute_force(
    events: list[dict],
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[dict]:
    failed_logins_by_ip = defaultdict(list)
    alerts = []

    for event in events:
        if event["event_type"] == "failed_login":
            failed_logins_by_ip[event["source_ip"]].append(event)

    for ip, login_events in failed_logins_by_ip.items():
        login_events.sort(key=lambda event: event["timestamp"])

        for i in range(len(login_events)):
            window_start = login_events[i]["timestamp"]
            window_end = window_start + timedelta(minutes=window_minutes)

            events_in_window = [
                event
                for event in login_events
                if window_start <= event["timestamp"] <= window_end
            ]

            if len(events_in_window) >= threshold:
                alerts.append(
                    {
                        "alert_type": "Brute Force Attack",
                        "source_ip": ip,
                        "severity": "High",
                        "risk_score": 80,
                        "description": (
                            f"{ip} generated {len(events_in_window)} failed login attempts "
                            f"within {window_minutes} minutes."
                        ),
                        "first_seen": window_start,
                        "last_seen": events_in_window[-1]["timestamp"],
                    }
                )
                break

    return alerts
