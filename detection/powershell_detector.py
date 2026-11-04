
#!/usr/bin/env python3

import json
import re
import argparse
from pathlib import Path


def load_events(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError("Expected a JSON array of Windows events")

    return data


def detect_threats(events):

    alerts = []

    for record in events:

        event = record.get("Event", {})
        system = event.get("System", {})
        data = event.get("EventData", {})

        if str(system.get("EventID", "")) != "1":
            continue

        image = str(data.get("Image", ""))
        command = str(data.get("CommandLine", ""))
        parent = str(data.get("ParentImage", ""))
        user = str(data.get("User", ""))

        if "powershell" not in image.lower():
            continue

        cmd = command.lower()

        findings = []

        # Rule 1: Remote download and execution
        downloads = [
            "downloadfile",
            "downloadstring",
            "start-bitstransfer"
        ]

        has_download = any(x in cmd for x in downloads)
        has_remote_url = bool(
            re.search(r"https?://", cmd)
        )

        has_execution = any(
            x in cmd for x in [
                "invoke-expression",
                "iex(",
                "iex ",
            ]
        )

        if has_download and has_remote_url:
            findings.append({
                "name": "Remote payload download",
                "severity": "High",
                "mitre": ["T1105", "T1059.001"],
                "confidence": "Medium"
            })

        if has_download and has_execution:
            findings.append({
                "name": "Download and execute pattern",
                "severity": "High",
                "mitre": ["T1105", "T1059.001"],
                "confidence": "High"
            })

        # Rule 2: Credential harvesting indicators
        if (
            "promptforcredential" in cmd
            and "getnetworkcredential" in cmd
        ):
            findings.append({
                "name": "Suspicious credential prompt",
                "severity": "High",
                "mitre": ["T1056"],
                "confidence": "High"
            })

        # Rule 3: Hidden PowerShell execution
        hidden = bool(
            re.search(
                r"-w(?:indowstyle)?\s+hidden",
                cmd
            )
        )

        no_profile = bool(
            re.search(r"-nop(?:rofile)?\b", cmd)
        )

        noninteractive = bool(
            re.search(r"-noni(?:nteractive)?\b", cmd)
        )

        if hidden and no_profile and noninteractive:
            findings.append({
                "name": "Hidden PowerShell execution",
                "severity": "High",
                "mitre": ["T1059.001"],
                "confidence": "Medium"
            })

        # Rule 4: Encoded/compressed command indicators
        encoded = bool(
            re.search(
                r"-(?:enc|encodedcommand)\b",
                cmd
            )
        ) or "frombase64string" in cmd

        compressed = (
            "gzipstream" in cmd
            or "compressionmode" in cmd
        )

        if encoded and compressed:
            findings.append({
                "name": "Encoded and compressed PowerShell",
                "severity": "High",
                "mitre": ["T1027", "T1059.001"],
                "confidence": "Medium"
            })

        # Generate an alert for every matching detection
        for finding in findings:

            alerts.append({
                "alert_id": f"KSOC-PS-{len(alerts)+1:03d}",
                "detection": finding["name"],
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "mitre_attack": finding["mitre"],
                "timestamp": data.get("UtcTime", ""),
                "computer": system.get("Computer", "Unknown"),
                "process": image,
                "parent_process": parent,
                "user": user,
                "process_guid": data.get("ProcessGuid", ""),
                "command_line_preview": command[:300],
                "status": "Requires investigation"
            })

    return alerts


def main():

    parser = argparse.ArgumentParser(
        description="KaliSOC PowerShell Threat Detector"
    )

    parser.add_argument(
        "--input",
        default=str(
            Path.home() /
            "KaliSOC/output/process-creation-events.json"
        )
    )

    parser.add_argument(
        "--output",
        default=str(
            Path.home() /
            "KaliSOC/output/powershell-alerts.json"
        )
    )

    args = parser.parse_args()

    print("\n========== KaliSOC PowerShell Detector ==========\n")

    events = load_events(args.input)
    alerts = detect_threats(events)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"[+] Events analyzed: {len(events)}")
    print(f"[+] PowerShell alerts: {len(alerts)}")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['alert_id']} - "
            f"{alert['detection']}"
        )

    print(f"\n[+] Saved: {output}")
    print("\n=================================================\n")


if __name__ == "__main__":
    main()
