
#!/usr/bin/env python3

"""
KaliSOC Sigma Importer

Converts Chainsaw Sigma hunt results into the
normalized JSON format used by KaliSOC.
"""

import argparse
import json
import re

from pathlib import Path


BASE = Path.home() / "KaliSOC"

DEFAULT_INPUT = BASE / "output/sigma-official-hunt.json"
DEFAULT_OUTPUT = BASE / "output/sigma-alerts.json"


SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
    "unknown": "Not classified",
}


def load_records(filepath):

    if not filepath.is_file():
        raise FileNotFoundError(
            f"Sigma result file not found: {filepath}"
        )

    with filepath.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(
            "Expected Chainsaw results to be a JSON array."
        )

    return data


def extract_mitre(tags):

    techniques = []

    for tag in tags:

        match = re.fullmatch(
            r"attack\.(t\d{4}(?:\.\d{3})?)",
            str(tag).strip(),
            re.IGNORECASE
        )

        if match:
            techniques.append(match.group(1).upper())

    return list(dict.fromkeys(techniques))


def normalize_record(record, index):

    document = record.get("document", {})

    data = document.get("data", {})

    event = data.get("Event", {})

    event_data = event.get("EventData", {})

    system = event.get("System", {})

    if not isinstance(event_data, dict):
        event_data = {}

    if not isinstance(system, dict):
        system = {}

    rule_name = record.get(
        "name", "Unknown Sigma detection"
    )

    sigma_level = str(
        record.get("level", "unknown")
    ).lower()

    severity = SEVERITY_MAP.get(
        sigma_level, "Not classified"
    )

    tags = record.get("tags", [])

    if not isinstance(tags, list):
        tags = []

    techniques = extract_mitre(tags)

    process = event_data.get("Image", "")

    command_line = event_data.get(
        "CommandLine", ""
    )

    computer = system.get(
        "Computer", "Unknown"
    )

    event_id = system.get(
        "EventID", ""
    )

    timestamp = (
        record.get("timestamp")
        or system.get(
            "TimeCreated_attributes", {}
        ).get("SystemTime", "")
    )

    source_path = document.get("path", "")

    return {

        "alert_id": f"KSOC-SIGMA-{index:04d}",

        "source": "Sigma/Chainsaw",

        "detection": rule_name,

        "severity": severity,

        "sigma_level": sigma_level,

        "confidence": (
            "Sigma rule match; analyst validation required"
        ),

        "status": "Requires analyst investigation",

        "event_id": str(event_id),

        "timestamp": timestamp,

        "computer": computer,

        "process": process,

        "process_id": event_data.get(
            "ProcessId", ""
        ),

        "process_guid": event_data.get(
            "ProcessGuid", ""
        ),

        "parent_process": event_data.get(
            "ParentImage", ""
        ),

        "parent_process_guid": event_data.get(
            "ParentProcessGuid", ""
        ),

        "user": event_data.get(
            "User",
            system.get(
                "Security_attributes", {}
            ).get("UserID", "Unknown")
        ),

        "target_object": event_data.get(
            "TargetObject", ""
        ),

        "target": (
            event_data.get("TargetUserName")
            or event_data.get("TargetObject")
            or ""
        ),

        "command_line_preview": str(
            command_line
        )[:1000],

        "description": (
            f"Sigma detection matched: {rule_name}"
        ),

        "sigma_rule_id": record.get("id", ""),

        "sigma_status": record.get(
            "status", "unknown"
        ),

        "mitre_attack": techniques,

        "sigma_tags": tags,

        "references": record.get(
            "references", []
        ),

        "authors": record.get(
            "authors", []
        ),

        "falsepositives": record.get(
            "falsepositives", []
        ),

        "source_log": Path(
            source_path
        ).name if source_path else "Unknown"

    }


def main():

    parser = argparse.ArgumentParser(
        description="KaliSOC Sigma Results Importer"
    )

    parser.add_argument(
        "--input",
        default=str(DEFAULT_INPUT)
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT)
    )

    args = parser.parse_args()

    input_path = Path(args.input).expanduser()

    output_path = Path(args.output).expanduser()

    print("\n========== KaliSOC Sigma Importer ==========\n")

    try:

        raw_records = load_records(input_path)

        normalized = []

        skipped = 0

        for index, record in enumerate(
            raw_records, start=1
        ):

            if not isinstance(record, dict):
                skipped += 1
                continue

            if not isinstance(
                record.get("document"), dict
            ):
                skipped += 1
                continue

            normalized.append(
                normalize_record(record, index)
            )

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with output_path.open(
            "w", encoding="utf-8"
        ) as file:

            json.dump(
                normalized,
                file,
                indent=4
            )

        print(f"[+] Sigma matches loaded: {len(raw_records)}")
        print(f"[+] Normalized records: {len(normalized)}")
        print(f"[+] Skipped records: {skipped}")
        print(f"[+] Output: {output_path}")

        print("\n============================================\n")

    except (
        OSError,
        ValueError,
        json.JSONDecodeError
    ) as error:

        raise SystemExit(f"[ERROR] {error}")


if __name__ == "__main__":
    main()
