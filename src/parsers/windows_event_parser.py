import re

def parse_windows_event_line(line):
    pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) EventID=(\d+) AccountName=(\w+) IpAddress=(\d+\.\d+\.\d+\.\d+)"

    match = re.search(pattern, line)

    if not match:
        return None

    timestamp, event_id, username, source_ip = match.groups()

    if event_id == "4625":
        event_type = "login_failed"
        status = "failed"
        severity = "medium"
    elif event_id == "4624":
        event_type = "login_success"
        status = "success"
        severity = "low"
    else:
        event_type = "windows_event"
        status = "unknown"
        severity = "low"

    return {
        "timestamp": timestamp,
        "source": "windows_event",
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "destination_ip": None,
        "status": status,
        "action": None,
        "request_method": None,
        "url": None,
        "status_code": None,
        "severity": severity,
        "raw_message": line.strip()
    }
