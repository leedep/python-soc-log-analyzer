import re
from datetime import datetime

def parse_linux_auth_line(line):
    failed_pattern = r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)"
    success_pattern = r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)"

    failed_match = re.search(failed_pattern, line)
    success_match = re.search(success_pattern, line)

    if failed_match:
        timestamp, username, source_ip = failed_match.groups()

        return {
            "timestamp": normalize_linux_timestamp(timestamp),
            "source": "linux_auth",
            "event_type": "login_failed",
            "username": username,
            "source_ip": source_ip,
            "destination_ip": None,
            "status": "failed",
            "action": None,
            "request_method": None,
            "url": None,
            "status_code": None,
            "severity": "medium",
            "raw_message": line.strip()
        }

    if success_match:
        timestamp, username, source_ip = success_match.groups()

        return {
            "timestamp": normalize_linux_timestamp(timestamp),
            "source": "linux_auth",
            "event_type": "login_success",
            "username": username,
            "source_ip": source_ip,
            "destination_ip": None,
            "status": "success",
            "action": None,
            "request_method": None,
            "url": None,
            "status_code": None,
            "severity": "low",
            "raw_message": line.strip()
        }

    return None


def normalize_linux_timestamp(timestamp):
    current_year = datetime.now().year
    full_timestamp = f"{current_year} {timestamp}"
    dt = datetime.strptime(full_timestamp, "%Y %b %d %H:%M:%S")
    return dt.strftime("%Y-%m-%d %H:%M:%S")
