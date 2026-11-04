
#!/usr/bin/env python3

import json
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import pandas as pd

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
)

BASE = Path.home() / "KaliSOC"
OUTPUT = BASE / "output"
REPORTS = BASE / "reports"

SOURCES = {
    "CLM Registry": OUTPUT / "alerts.json",
    "PowerShell Detection": OUTPUT / "powershell-alerts.json",
    "Account Monitoring": OUTPUT / "account-alerts.json",
    "Sigma Detection": OUTPUT / "sigma-alerts.json",
}

SEVERITY_ORDER = {
    "Informational": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def safe_text(value):
    """Escape user/log content for PDF paragraphs."""
    if value is None:
        return "Not available"

    value = str(value)

    if not value.strip():
        return "Not available"

    return escape(value).replace("\n", "<br/>")


def load_records():

    records = []
    source_summary = {}

    for module, filepath in SOURCES.items():

        if not filepath.exists():
            source_summary[module] = "Missing"
            continue

        try:
            with filepath.open("r", encoding="utf-8") as file:
                data = json.load(file)

            if not isinstance(data, list):
                source_summary[module] = "Invalid JSON"
                continue

            source_summary[module] = len(data)

            for index, alert in enumerate(data, start=1):

                if not isinstance(alert, dict):
                    continue

                computer = str(
                    alert.get("computer", "Unknown")
                )

                process_guid = str(
                    alert.get("process_guid", "")
                ).strip()

                event_id = str(
                    alert.get("event_id", "")
                )

                timestamp = str(
                    alert.get("timestamp", "")
                )

                target = str(
                    alert.get("target_object")
                    or alert.get("target_sid")
                    or alert.get("account")
                    or ""
                )

                # Group only when a process GUID is available.
                if process_guid:

                    event_key = f"{computer}|{process_guid}"

                else:

                    event_key = (
                        f"{module}|{computer}|{event_id}|"
                        f"{timestamp}|{target}|{index}"
                    )

                mitre = alert.get("mitre_attack", [])

                if not isinstance(mitre, list):
                    mitre = [str(mitre)] if mitre else []

                records.append({
                    "event_key": event_key,
                    "alert_id": alert.get(
                        "alert_id", f"{module}-{index}"
                    ),
                    "module": module,
                    "detection": alert.get(
                        "detection", "Unknown"
                    ),
                    "severity": alert.get(
                        "severity", "Informational"
                    ),
                    "confidence": alert.get(
                        "confidence", "Not specified"
                    ),
                    "timestamp": timestamp,
                    "computer": computer,
                    "actor": (
                        alert.get("user")
                        or alert.get("created_by")
                        or alert.get("creator_sid")
                        or "Unknown"
                    ),
                    "process": alert.get("process", ""),
                    "target": target,
                    "event_id": event_id,
                    "process_guid": process_guid,
                    "mitre": mitre,
                    "status": alert.get(
                        "status", "Requires investigation"
                    ),
                    "evidence": (
                        alert.get("command_line_preview")
                        or alert.get("description")
                        or " | ".join(
                            alert.get("findings", [])
                        )
                    )
                })

        except (OSError, json.JSONDecodeError) as error:

            source_summary[module] = f"Read error: {error}"

    return records, source_summary


def group_records(records):

    groups = defaultdict(list)

    for record in records:
        groups[record["event_key"]].append(record)

    return list(groups.values())


def create_report(output_path):

    records, sources = load_records()

    groups = group_records(records)

    if not records:
        raise SystemExit(
            "[ERROR] No security records available."
        )

    generated = datetime.now(timezone.utc)

    high = sum(
        r["severity"] == "High" for r in records
    )

    medium = sum(
        r["severity"] == "Medium" for r in records
    )

    critical = sum(
        r["severity"] == "Critical" for r in records
    )

    informational = sum(
        r["severity"] == "Informational" for r in records
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=27,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#163A5F"),
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#163A5F"),
        spaceBefore=14,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="SmallText",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11
    ))

    styles.add(ParagraphStyle(
        name="EvidenceText",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
        wordWrap="CJK"
    ))

    story = []

    story.append(Paragraph(
        "KaliSOC Security Investigation Report",
        styles["ReportTitle"]
    ))

    story.append(Paragraph(
        "Windows Threat Hunting and Digital Forensics",
        styles["Heading3"]
    ))

    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph(
        f"Generated: {generated.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        styles["Normal"]
    ))

    story.append(Paragraph(
        "Report classification: Internal - Investigation Data",
        styles["Normal"]
    ))

    story.append(HRFlowable(
        width="100%",
        color=colors.HexColor("#163A5F"),
        thickness=1
    ))

    story.append(Paragraph(
        "1. Executive Summary",
        styles["SectionHeading"]
    ))

    summary_data = [
        ["Metric", "Result"],
        ["Detection records", str(len(records))],
        ["Correlated event groups", str(len(groups))],
        ["High severity matches", str(high)],
        ["Medium severity matches", str(medium)],
        ["Critical severity matches", str(critical)],
        ["Informational matches", str(informational)]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[90 * mm, 70 * mm]
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#163A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#EFF4F8")])
    ]))

    story.append(summary_table)

    story.append(Paragraph(
        "2. Data Sources",
        styles["SectionHeading"]
    ))

    source_data = [["Module", "Records"]]

    for name, count in sources.items():
        source_data.append([name, str(count)])

    source_table = Table(
        source_data,
        colWidths=[90 * mm, 70 * mm]
    )

    source_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#163A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#EFF4F8")])
    ]))

    story.append(source_table)

    story.append(Paragraph(
        "3. Investigation Findings",
        styles["SectionHeading"]
    ))

    for number, group in enumerate(groups, start=1):

        first = group[0]

        severity = max(
            [r["severity"] for r in group],
            key=lambda s: SEVERITY_ORDER.get(s, 0)
        )

        detections = list(dict.fromkeys(
            r["detection"] for r in group
        ))

        modules = list(dict.fromkeys(
            r["module"] for r in group
        ))

        mitre = list(dict.fromkeys(
            technique
            for r in group
            for technique in r["mitre"]
        ))

        story.append(Paragraph(
            f"Finding {number}: {safe_text(' + '.join(detections))}",
            styles["Heading3"]
        ))

        fields = [
            ["Field", "Value"],
            ["Severity", severity],
            ["Confidence", ", ".join(
                dict.fromkeys(r["confidence"] for r in group)
            )],
            ["Computer", first["computer"]],
            ["Timestamp", first["timestamp"]],
            ["Event ID", ", ".join(
                dict.fromkeys(r["event_id"] for r in group)
            )],
            ["Actor", ", ".join(
                dict.fromkeys(r["actor"] for r in group)
            )],
            ["Process", first["process"] or "Not available"],
            ["Target", first["target"] or "Not available"],
            ["Modules", ", ".join(modules)],
            ["Detection matches", str(len(group))],
            ["MITRE references", ", ".join(mitre) or "Not mapped"],
            ["Investigation status", ", ".join(
                dict.fromkeys(r["status"] for r in group)
            )]
        ]

        field_table = Table(
            [
                [
                    Paragraph(
                        f"<b>{safe_text(row[0])}</b>",
                        styles["SmallText"]
                    ),
                    Paragraph(
                        safe_text(row[1]),
                        styles["SmallText"]
                    )
                ]
                for row in fields
            ],
            colWidths=[43 * mm, 117 * mm]
        )

        field_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1),
             colors.HexColor("#F2F5F8")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5)
        ]))

        story.append(field_table)
        story.append(Spacer(1, 3 * mm))

        for match in group:

            if match["evidence"]:

                story.append(Paragraph(
                    f"<b>Evidence - {safe_text(match['alert_id'])}:</b>",
                    styles["SmallText"]
                ))

                story.append(Paragraph(
                    safe_text(match["evidence"][:1000]),
                    styles["EvidenceText"]
                ))

                story.append(Spacer(1, 2 * mm))

        story.append(Spacer(1, 5 * mm))

    story.append(Paragraph(
        "4. Analyst Assessment and Limitations",
        styles["SectionHeading"]
    ))

    limitations = [
        "This report is generated from historical forensic JSON data.",
        "Detection matches are rule-based indicators and are not "
        "proof of compromise.",
        "Correlated event groups use computer name and Process GUID "
        "when available. Records without a Process GUID are kept "
        "separate.",
        "Missing logs, incomplete telemetry and false positives may "
        "affect findings.",
        "MITRE ATT&CK references are candidate mappings supplied "
        "by detection rules and require analyst validation.",
        "This report does not perform automated containment or "
        "remediation."
    ]

    for item in limitations:
        story.append(Paragraph(
            f"- {safe_text(item)}",
            styles["SmallText"]
        ))
        story.append(Spacer(1, 2 * mm))

    def footer(canvas, document):

        canvas.saveState()

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)

        canvas.drawString(
            20 * mm,
            12 * mm,
            "KaliSOC - Security Investigation Report"
        )

        canvas.drawRightString(
            190 * mm,
            12 * mm,
            f"Page {document.page}"
        )

        canvas.restoreState()

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title="KaliSOC Security Investigation Report",
        author="KaliSOC"
    )

    document.build(
        story,
        onFirstPage=footer,
        onLaterPages=footer
    )

    print("\n========== KaliSOC PDF Reporter ==========\n")
    print(f"[+] Detection records: {len(records)}")
    print(f"[+] Correlated groups: {len(groups)}")
    print(f"[+] PDF report created: {output_path}")
    print("\n===========================================\n")


def main():

    parser = argparse.ArgumentParser(
        description="Generate a KaliSOC investigation PDF"
    )

    parser.add_argument(
        "--output",
        default=str(
            REPORTS / "KaliSOC_Incident_Report.pdf"
        ),
        help="PDF output path"
    )

    args = parser.parse_args()

    create_report(Path(args.output))


if __name__ == "__main__":
    main()
