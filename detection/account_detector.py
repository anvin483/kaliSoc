
#!/usr/bin/env python3

import json
from pathlib import Path

BASE = Path.home() / "KaliSOC"

USER_FILE = BASE / "output/account-creation-events.json"
COMPUTER_FILE = BASE / "output/computer-account-events.json"
OUTPUT_FILE = BASE / "output/account-alerts.json"


def load_events(filepath):

    if not filepath.exists():
        print(f"[!] File not found: {filepath}")
        return []

    with filepath.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array: {filepath}")

    return data


def analyze_user_account(record):

    event = record.get("Event", {})
    system = event.get("System", {})
    data = event.get("EventData", {})

    target = str(data.get("TargetUserName", "")).strip()
    sam = str(data.get("SamAccountName", "")).strip()

    suspicious_name = target == "$" or sam == "$"

    return {
        "event_id": 4720,
        "category": "User Account Creation",
        "detection": (
            "Unusual bare-dollar account name"
            if suspicious_name
            else "User account created"
        ),
        "severity": "Medium" if suspicious_name else "Informational",
        "confidence": "Low" if suspicious_name else "High",
        "timestamp": system.get(
            "TimeCreated_attributes", {}
        ).get("SystemTime", ""),
        "computer": system.get("Computer", ""),
        "account": target,
        "domain": data.get("TargetDomainName", ""),
        "created_by": data.get("SubjectUserName", ""),
        "creator_sid": data.get("SubjectUserSid", ""),
        "target_sid": data.get("TargetSid", ""),
        "status": "Requires investigation" if suspicious_name
                  else "Recorded",
        "mitre_attack": ["T1136.002"] if suspicious_name else []
    }


def analyze_computer_account(record):

    event = record.get("Event", {})
    system = event.get("System", {})
    data = event.get("EventData", {})

    target = str(data.get("TargetUserName", "")).strip()
    group_id = str(data.get("PrimaryGroupId", "")).strip()

    uac_raw = str(data.get("NewUacValue", ""))
    uac_flags = []

    try:
        uac_value = int(uac_raw, 0)

        if uac_value & 0x80:
            uac_flags.append(
                "ENCRYPTED_TEXT_PASSWORD_ALLOWED"
            )

    except ValueError:
        pass

    group_description = {
        "515": "Domain Computers",
        "516": "Domain Controllers",
        "521": "Read-only Domain Controllers"
    }.get(group_id, "Other / Unknown")

    findings = [
        "Computer account created",
        f"Primary group: {group_description}"
    ]

    if target.endswith("$"):
        findings.append("Expected computer-account naming format")

    if uac_flags:
        findings.append(
            "Review UAC configuration: " + ", ".join(uac_flags)
        )

    return {
        "event_id": 4741,
        "category": "Computer Account Creation",
        "detection": "Computer account created",
        "severity": "Informational",
        "confidence": "High - event data recorded",
        "timestamp": system.get(
            "TimeCreated_attributes", {}
        ).get("SystemTime", ""),
        "computer": system.get("Computer", ""),
        "account": target,
        "domain": data.get("TargetDomainName", ""),
        "dns_hostname": data.get("DnsHostName", ""),
        "primary_group_id": group_id,
        "primary_group": group_description,
        "created_by": data.get("SubjectUserName", ""),
        "creator_sid": data.get("SubjectUserSid", ""),
        "creator_logon_id": data.get("SubjectLogonId", ""),
        "target_sid": data.get("TargetSid", ""),
        "uac_value": uac_raw,
        "uac_flags": uac_flags,
        "findings": findings,
        "status": "Verify creator authorization and host inventory",
        "mitre_attack": []
    }


def main():

    print("\n========== KaliSOC Account Detector ==========\n")

    user_events = load_events(USER_FILE)
    computer_events = load_events(COMPUTER_FILE)

    alerts = []

    for record in user_events:
        alerts.append(analyze_user_account(record))

    for record in computer_events:
        alerts.append(analyze_computer_account(record))

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"[+] User events: {len(user_events)}")
    print(f"[+] Computer events: {len(computer_events)}")
    print(f"[+] Total records: {len(alerts)}")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['category']} - "
            f"{alert['account']}"
        )

    print(f"\n[+] Report saved: {OUTPUT_FILE}")
    print("\n==============================================\n")


if __name__ == "__main__":
    main()

