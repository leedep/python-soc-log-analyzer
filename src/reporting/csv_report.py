import csv
from pathlib import Path


def save_alerts_to_csv(alerts: list[dict], output_file: str) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not alerts:
        print("No alerts generated. CSV report was not created.")
        return

    fieldnames = sorted(set().union(*(alert.keys() for alert in alerts)))

    with open(output_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"CSV report saved to: {output_file}")
