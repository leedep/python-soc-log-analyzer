from parsers.auth_parser import parse_auth_log
from detection.brute_force import detect_brute_force
from detection.suspicious_login import detect_suspicious_admin_login


def print_alerts(alerts: list[dict]) -> None:
    for alert in alerts:
        print(f"[{alert['severity']}] {alert['alert_type']}")
        print(f"Source IP: {alert.get('source_ip', 'N/A')}")
        print(f"Risk Score: {alert.get('risk_score', 'N/A')}")
        print(f"Description: {alert.get('description', 'N/A')}")

        if "first_seen" in alert:
            print(f"First Seen: {alert['first_seen']}")

        if "last_seen" in alert:
            print(f"Last Seen: {alert['last_seen']}")

        if "timestamp" in alert:
            print(f"Timestamp: {alert['timestamp']}")

        print("-" * 60)


def main() -> None:
    log_file = "data/sample_auth.log"

    events = parse_auth_log(log_file)

    brute_force_alerts = detect_brute_force(events)
    admin_login_alerts = detect_suspicious_admin_login(events)

    all_alerts = brute_force_alerts + admin_login_alerts

    print("SOC Log Analysis Completed.")
    print(f"Total events parsed: {len(events)}")
    print(f"Total alerts generated: {len(all_alerts)}")
    print()

    print_alerts(all_alerts)


if __name__ == "__main__":
    main()
