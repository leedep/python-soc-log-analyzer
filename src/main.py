from parsers.auth_parser import parse_auth_log
from detection.brute_force import detect_brute_force


def main() -> None:
    log_file = "data/sample_auth.log"

    events = parse_auth_log(log_file)
    alerts = detect_brute_force(events)

    print("SOC Log Analysis Completed.")
    print(f"Total events parsed: {len(events)}")
    print(f"Total alerts generated: {len(alerts)}")
    print()

    for alert in alerts:
        print(f"[{alert['severity']}] {alert['alert_type']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Risk Score: {alert['risk_score']}")
        print(f"Description: {alert['description']}")
        print(f"First Seen: {alert['first_seen']}")
        print(f"Last Seen: {alert['last_seen']}")
        print("-" * 60)


if __name__ == "__main__":
    main()
