
#!/usr/bin/env python3

"""
KaliSOC - Windows Threat Detection Engine
Analyzes Chainsaw JSON output for suspicious
PowerShell CLM-related registry modifications.
"""

import json
import argparse
from pathlib import Path


def load_events(filepath):
    """Load JSON event data."""
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        raise SystemExit(f"[ERROR] File not found: {filepath}")
    except json.JSONDecodeError as error:
        raise SystemExit(f"[ERROR] Invalid JSON: {error}")


def extract_records(data):
    """Handle event records stored in lists or nested objects."""
    if isinstance(data, list):
        for item in data:
            yield from extract_records(item)

    elif isinstance(data, dict):
        if isinstance(data.get("Event"), dict):
            yield data
        elif isinstance(data.get("System"), dict):
            yield {"Event": data}
        else:
            for value in data.values():
                yield from extract_records(value)


def analyze_events(data):
    """Identify potentially suspicious registry modifications."""

    alerts = []
    records = list(extract_records(data))

    for record in records:
        event = record.get("Event", {})
        system = event.get("System", {})
        event_data = event.get("EventData", {})

        event_id = str(system.get("EventID", ""))
        target = str(event_data.get("TargetObject", ""))
        event_type = str(event_data.get("EventType", ""))

        # Detect modifications involving the CLM-related registry value.
        if (
            event_id in {"12", "13", "14"}
            and "__pslockdownpolicy" in target.lower()
        ):
            alert = {
                "alert_id": f"KSOC-{len(alerts) + 1:03d}",
                "detection": "PowerShell CLM-related registry modification",
                "severity": "Medium",
                "confidence": "Low - requires validation",
                "status": "Requires investigation",
                "event_id": event_id,
                "event_type": event_type,
                "timestamp": system.get(
                    "TimeCreated_attributes", {}
                ).get("SystemTime", event_data.get("UtcTime", "")),
                "computer": system.get("Computer", "Unknown"),
                "process": event_data.get("Image", "Unknown"),
                "process_id": event_data.get("ProcessId", "Unknown"),
                "process_guid": event_data.get("ProcessGuid", ""),
                "target_object": target,
                "user_sid": system.get(
                    "Security_attributes", {}
                ).get("UserID", "Unknown"),
                "description": (
                    "A registry event involving __PSLockdownPolicy "
                    "was identified. Validate surrounding activity "
                    "and Windows security configuration."
                )
            }

            alerts.append(alert)

    return records, alerts


def main():
    parser = argparse.ArgumentParser(
        description="KaliSOC Windows threat detection engine"
    )

    parser.add_argument(
        "--input",
        default=str(
            Path.home()
            / "KaliSOC/output/powershell-clm-events.json"
        ),
        help="Input Chainsaw JSON file"
    )

    parser.add_argument(
        "--output",
        default=str(
            Path.home() / "KaliSOC/output/alerts.json"
        ),
        help="Output alert JSON file"
    )

    args = parser.parse_args()

    print("\n========== KaliSOC Detection Engine ==========\n")

    data = load_events(args.input)
    records, alerts = analyze_events(data)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"[+] Events loaded: {len(records)}")
    print(f"[+] Alerts generated: {len(alerts)}")
    print(f"[+] Output saved: {output_path}")

    if alerts:
        print("\n[!] Potentially suspicious activity detected!")

        for alert in alerts:
            print(f"\nAlert ID : {alert['alert_id']}")
            print(f"Severity : {alert['severity']}")
            print(f"Process  : {alert['process']}")
            print(f"Activity : {alert['event_type']}")
            print(f"Target   : {alert['target_object']}")
            print(f"Status   : {alert['status']}")

    else:
        print("\n[+] No matching events detected.")

    print("\n==============================================\n")


if __name__ == "__main__":
    main()
