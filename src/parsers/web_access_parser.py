import re
from datetime import datetime

def parse_web_access_line(line):
    pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?) \+\d+\] "(\w+) (.*?) HTTP/.*?" (\d+) \d+'

    match = re.search(pattern, line)

    if not match:
        return None

    source_ip, timestamp, method, url, status_code = match.groups()

    status_code = int(status_code)

    if status_code >= 400:
        status = "failed"
        action = "deny"
        severity = "medium"
    else:
        status = "success"
        action = "allow"
        severity = "low"

    return {
        "timestamp": normalize_web_timestamp(timestamp),
        "source": "web_access",
        "event_type": "web_access",
        "username": None,
        "source_ip": source_ip,
        "destination_ip": None,
        "status": status,
        "action": action,
        "request_method": method,
        "url": url,
        "status_code": status_code,
        "severity": severity,
        "raw_message": line.strip()
    }


def normalize_web_timestamp(timestamp):
    dt = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S")
    return dt.strftime("%Y-%m-%d %H:%M:%S")
