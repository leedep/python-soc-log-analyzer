import re
from datetime import datetime


FAILED_LOGIN_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*Failed password for (?P<username>\w+) from (?P<ip>[\d\.]+)"
)

ACCEPTED_LOGIN_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*Accepted password for (?P<username>\w+) from (?P<ip>[\d\.]+)"
)


def parse_timestamp(data: dict, year: int = 2026) -> datetime:
    time_string = f"{year} {data['month']} {data['day']} {data['time']}"
    return datetime.strptime(time_string, "%Y %b %d %H:%M:%S")


def parse_auth_log(file_path: str, year: int = 2026) -> list[dict]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            failed_match = FAILED_LOGIN_PATTERN.search(line)
            accepted_match = ACCEPTED_LOGIN_PATTERN.search(line)

            if failed_match:
                data = failed_match.groupdict()
                events.append(
                    {
                        "timestamp": parse_timestamp(data, year),
                        "source_ip": data["ip"],
                        "username": data["username"],
                        "event_type": "failed_login",
                        "status": "failure",
                        "raw_message": line.strip(),
                    }
                )

            elif accepted_match:
                data = accepted_match.groupdict()
                events.append(
                    {
                        "timestamp": parse_timestamp(data, year),
                        "source_ip": data["ip"],
                        "username": data["username"],
                        "event_type": "successful_login",
                        "status": "success",
                        "raw_message": line.strip(),
                    }
                )

    return events
