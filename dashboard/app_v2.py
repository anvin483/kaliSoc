
import json
import subprocess
import sys

from pathlib import Path
from collections import defaultdict

import pandas as pd
import plotly.express as px
import streamlit as st


# =====================================================
# CONFIGURATION
# =====================================================

BASE = Path.home() / "KaliSOC"
OUTPUT = BASE / "output"
REPORTS = BASE / "reports"

REPORT_SCRIPT = BASE / "detection/report_generator.py"
PDF_PATH = REPORTS / "KaliSOC_Incident_Report.pdf"

FILES = {
    "CLM Registry": OUTPUT / "alerts.json",
    "PowerShell Detection": OUTPUT / "powershell-alerts.json",
    "Account Monitoring": OUTPUT / "account-alerts.json",
}

SEVERITY_ORDER = {
    "Informational": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

MITRE_NAMES = {
    "T1059.001": "PowerShell",
    "T1105": "Ingress Tool Transfer",
    "T1056": "Input Capture",
    "T1027": "Obfuscated Files or Information",
    "T1136.002": "Domain Account",
}


# =====================================================
# DATA LOADING
# =====================================================

def load_alerts():

    records = []
    sources = {}

    for module, filepath in FILES.items():

        if not filepath.exists():
            sources[module] = "Missing"
            continue

        try:
            with filepath.open("r", encoding="utf-8") as file:
                data = json.load(file)

            if not isinstance(data, list):
                sources[module] = "Invalid JSON"
                continue

            sources[module] = f"{len(data)} records"

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

                # Correlate using computer and Process GUID.
                # Without a GUID, keep each alert separate.
                if process_guid:

                    event_key = f"{computer}|{process_guid}"

                else:

                    event_key = (
                        f"{module}|{computer}|{event_id}|"
                        f"{timestamp}|{target}|"
                        f"{alert.get('alert_id', index)}"
                    )

                mitre = alert.get("mitre_attack", [])

                if not isinstance(mitre, list):
                    mitre = [str(mitre)] if mitre else []

                actor = (
                    alert.get("user")
                    or alert.get("created_by")
                    or alert.get("creator_sid")
                    or alert.get("user_sid")
                    or "Unknown"
                )

                evidence = (
                    alert.get("command_line_preview")
                    or alert.get("description")
                    or " | ".join(alert.get("findings", []))
                    or ""
                )

                records.append({

                    "Alert ID": alert.get(
                        "alert_id", f"{module}-{index}"
                    ),

                    "Event Key": event_key,

                    "Module": module,

                    "Detection": alert.get(
                        "detection", "Unknown"
                    ),

                    "Severity": alert.get(
                        "severity", "Informational"
                    ),

                    "Confidence": alert.get(
                        "confidence", "Not specified"
                    ),

                    "Timestamp": timestamp,

                    "Computer": computer,

                    "Actor": actor,

                    "Process": alert.get("process", ""),

                    "Process GUID": process_guid,

                    "Target": target,

                    "Event ID": event_id,

                    "MITRE": mitre,

                    "Status": alert.get(
                        "status", "Requires investigation"
                    ),

                    "Evidence": evidence,

                })

        except (OSError, json.JSONDecodeError) as error:

            sources[module] = f"Read error: {error}"

    return pd.DataFrame(records), sources


# =====================================================
# INCIDENT CORRELATION
# =====================================================

def correlate_incidents(data):

    if data.empty:
        return pd.DataFrame()

    incidents = []

    for event_key, group in data.groupby("Event Key"):

        severity = max(
            group["Severity"].tolist(),
            key=lambda x: SEVERITY_ORDER.get(x, 0)
        )

        detections = list(
            dict.fromkeys(group["Detection"])
        )

        modules = list(
            dict.fromkeys(group["Module"])
        )

        mitre_ids = list(dict.fromkeys(
            technique
            for items in group["MITRE"]
            for technique in items
        ))

        timestamps = pd.to_datetime(
            group["Timestamp"],
            utc=True,
            errors="coerce"
        ).dropna()

        incidents.append({

            "Event Key": event_key,

            "Timestamp": (
                timestamps.min()
                if not timestamps.empty else pd.NaT
            ),

            "Severity": severity,

            "Detection": " + ".join(detections),

            "Modules": ", ".join(modules),

            "Detection Matches": len(group),

            "Computer": group["Computer"].iloc[0],

            "Process": group["Process"].iloc[0],

            "MITRE IDs": ", ".join(mitre_ids),

            "Alert IDs": ", ".join(group["Alert ID"]),

        })

    return pd.DataFrame(incidents)


# =====================================================
# PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="KaliSOC V2 | Advanced SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =====================================================
# HEADER
# =====================================================

st.title("🛡️ KaliSOC V2")

st.caption(
    "Advanced Windows Threat Hunting | "
    "Security Operations & Incident Investigation"
)

st.markdown("---")


# =====================================================
# DATA REFRESH
# =====================================================

if st.button("🔄 Refresh Security Data"):

    st.rerun()


df, sources = load_alerts()

if df.empty:

    st.warning(
        "No detection records found. "
        "Run your detection modules first."
    )

    st.stop()


# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.title("🛡️ KaliSOC V2")

st.sidebar.caption("SOC Analyst Console")

st.sidebar.subheader("Data Sources")

for name, status in sources.items():

    st.sidebar.write(f"**{name}:** {status}")


st.sidebar.divider()

st.sidebar.subheader("Security Filters")

severity_options = sorted(
    df["Severity"].unique().tolist(),
    key=lambda x: SEVERITY_ORDER.get(x, 0)
)

module_options = sorted(
    df["Module"].unique().tolist()
)

selected_severity = st.sidebar.multiselect(
    "Severity",
    severity_options,
    default=severity_options
)

selected_modules = st.sidebar.multiselect(
    "Detection Module",
    module_options,
    default=module_options
)


# =====================================================
# FILTER DATA
# =====================================================

filtered = df[
    df["Severity"].isin(selected_severity)
    & df["Module"].isin(selected_modules)
].copy()

incidents = correlate_incidents(filtered)


# =====================================================
# SECURITY METRICS
# =====================================================

st.subheader("Security Overview")

total_alerts = len(filtered)

total_incidents = len(incidents)

high = int(
    (filtered["Severity"] == "High").sum()
)

medium = int(
    (filtered["Severity"] == "Medium").sum()
)

critical = int(
    (filtered["Severity"] == "Critical").sum()
)

informational = int(
    (filtered["Severity"] == "Informational").sum()
)

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("Detection Matches", total_alerts)

c2.metric("Unique Event Groups", total_incidents)

c3.metric("High Severity", high)

c4.metric("Medium Severity", medium)

c5.metric("Critical", critical)


st.markdown("---")


# =====================================================
# NAVIGATION TABS
# =====================================================

overview, incident_tab, timeline_tab, mitre_tab, export_tab = st.tabs([

    "📊 Overview",

    "🚨 Incidents",

    "🕒 Timeline",

    "🎯 MITRE ATT&CK",

    "📁 Export",

])


# =====================================================
# TAB 1 - OVERVIEW
# =====================================================

with overview:

    st.subheader("Detection Analytics")

    left, right = st.columns(2)

    with left:

        module_data = (
            filtered["Module"]
            .value_counts()
            .reset_index()
        )

        module_data.columns = ["Module", "Count"]

        fig = px.bar(
            module_data,
            x="Module",
            y="Count",
            text="Count",
            title="Detection Matches by Module",
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with right:

        severity_data = (
            filtered["Severity"]
            .value_counts()
            .reset_index()
        )

        severity_data.columns = ["Severity", "Count"]

        fig = px.pie(
            severity_data,
            names="Severity",
            values="Count",
            hole=0.48,
            title="Severity Distribution",
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    st.markdown("---")

    st.subheader("Latest Security Alerts")

    st.dataframe(

        filtered[[
            "Alert ID",
            "Module",
            "Detection",
            "Severity",
            "Computer",
            "Timestamp",
        ]],

        use_container_width=True,

        hide_index=True,

    )


# =====================================================
# TAB 2 - INCIDENT INVESTIGATION
# =====================================================

with incident_tab:

    st.subheader("Correlated Security Events")

    st.caption(
        "Events sharing a computer and Process GUID "
        "are grouped together. Records without a "
        "Process GUID remain separate."
    )

    if not incidents.empty:

        st.dataframe(

            incidents.drop(columns=["Event Key"]),

            use_container_width=True,

            hide_index=True,

        )

        selected_key = st.selectbox(
            "Select Event Group",
            incidents["Event Key"].tolist()
        )

        details = filtered[
            filtered["Event Key"] == selected_key
        ]

        st.markdown("### Investigation Evidence")

        st.json(
            details.drop(
                columns=["Event Key"]
            ).to_dict(orient="records")
        )

    else:

        st.info("No matching incident groups.")


# =====================================================
# TAB 3 - TIMELINE
# =====================================================

with timeline_tab:

    st.subheader("Security Event Timeline")

    timeline = filtered.copy()

    timeline["_time"] = pd.to_datetime(
        timeline["Timestamp"],
        utc=True,
        errors="coerce"
    )

    timeline = timeline.dropna(
        subset=["_time"]
    )

    if not timeline.empty:

        fig = px.scatter(

            timeline,

            x="_time",

            y="Module",

            color="Severity",

            hover_data=[
                "Detection",
                "Computer",
                "Alert ID",
                "Actor",
            ],

            title="Chronological Security Events",

        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

        st.subheader("Event History")

        st.dataframe(

            timeline.sort_values(
                "_time",
                ascending=False
            )[[
                "Timestamp",
                "Module",
                "Detection",
                "Severity",
                "Computer",
            ]],

            use_container_width=True,

            hide_index=True,

        )

    else:

        st.info("No valid timestamps available.")


# =====================================================
# TAB 4 - MITRE ATT&CK
# =====================================================

with mitre_tab:

    st.subheader("MITRE ATT&CK Mapping")

    st.caption(
        "Candidate technique references from detection rules. "
        "These are not confirmed attack techniques."
    )

    technique_records = []

    for _, row in filtered.iterrows():

        for technique in row["MITRE"]:

            technique_records.append({

                "Technique ID": technique,

                "Technique Name": MITRE_NAMES.get(
                    technique,
                    "Name not configured"
                ),

                "Detection": row["Detection"],

                "Severity": row["Severity"],

                "Computer": row["Computer"],

                "Alert ID": row["Alert ID"],

            })

    if technique_records:

        technique_df = pd.DataFrame(
            technique_records
        )

        st.metric(
            "Technique References",
            len(technique_df)
        )

        st.dataframe(

            technique_df,

            use_container_width=True,

            hide_index=True,

        )

    else:

        st.info("No MITRE ATT&CK references available.")


# =====================================================
# TAB 5 - EXPORT AND PDF REPORT
# =====================================================

with export_tab:

    st.subheader("📄 Security Investigation Reports")

    st.markdown("### PDF Incident Report")

    st.write(
        "Generate a professional PDF report containing "
        "your security findings, evidence, severity and "
        "MITRE ATT&CK references."
    )

    if st.button(
        "📄 Generate / Refresh PDF Report",
        type="primary",
        use_container_width=True,
    ):

        if not REPORT_SCRIPT.exists():

            st.error(
                "PDF report generator was not found:\n"
                f"{REPORT_SCRIPT}"
            )

        else:

            try:

                REPORTS.mkdir(
                    parents=True,
                    exist_ok=True
                )

                with st.spinner(
                    "Generating KaliSOC PDF report..."
                ):

                    result = subprocess.run(

                        [
                            sys.executable,
                            str(REPORT_SCRIPT),
                            "--output",
                            str(PDF_PATH),
                        ],

                        capture_output=True,

                        text=True,

                        timeout=180,

                        check=False,

                    )

                if result.returncode == 0:

                    st.success(
                        "PDF report generated successfully!"
                    )

                    if result.stdout:
                        st.code(result.stdout)

                else:

                    st.error("PDF generation failed.")

                    if result.stderr:
                        st.code(result.stderr)

                    if result.stdout:
                        st.code(result.stdout)

            except subprocess.TimeoutExpired:

                st.error(
                    "PDF generation timed out."
                )

            except OSError as error:

                st.error(
                    f"Unable to generate PDF: {error}"
                )

    st.divider()

    if PDF_PATH.exists():

        st.success(
            "A PDF report is available."
        )

        pdf_bytes = PDF_PATH.read_bytes()

        st.download_button(

            label="⬇️ Download KaliSOC PDF Report",

            data=pdf_bytes,

            file_name="KaliSOC_Incident_Report.pdf",

            mime="application/pdf",

            use_container_width=True,

        )

        st.caption(
            f"Report size: {len(pdf_bytes) / 1024:.1f} KB"
        )

        st.caption(
            "The download contains the latest successfully "
            "generated PDF. Generate a new report after "
            "changing detection data."
        )

    else:

        st.info(
            "Generate a PDF report to enable downloading."
        )

    st.markdown("---")

    st.subheader("📊 CSV Investigation Data")

    if not incidents.empty:

        incident_csv = incidents.drop(
            columns=["Event Key"]
        ).to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(

            label="Download Incident Report CSV",

            data=incident_csv,

            file_name="KaliSOC_Incidents.csv",

            mime="text/csv",

        )

    alert_csv = filtered.drop(
        columns=["Event Key", "MITRE"]
    ).to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(

        label="Download Detection Records CSV",

        data=alert_csv,

        file_name="KaliSOC_Alerts.csv",

        mime="text/csv",

    )


# =====================================================
# FOOTER
# =====================================================

st.markdown("---")

st.caption(
    "KaliSOC V2 | Windows Threat Hunting | "
    "Digital Forensics | Incident Investigation"
)

st.caption(
    "Data source: Historical forensic datasets. "
    "Detection matches require analyst validation."
)
