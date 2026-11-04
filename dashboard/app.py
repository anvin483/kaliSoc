
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


BASE = Path.home() / "KaliSOC"
OUTPUT = BASE / "output"

FILES = {
    "CLM Registry": OUTPUT / "alerts.json",
    "PowerShell Detection": OUTPUT / "powershell-alerts.json",
    "Account Monitoring": OUTPUT / "account-alerts.json",
}


def load_alert_file(path):
    if not path.exists():
        return [], "Missing"

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, list):
            return [], "Invalid format"

        return data, f"{len(data)} records"

    except (OSError, json.JSONDecodeError):
        return [], "Read error"


def normalize_alert(alert, module, index):

    mitre = alert.get("mitre_attack", [])

    if not isinstance(mitre, list):
        mitre = [str(mitre)] if mitre else []

    target = (
        alert.get("target_object")
        or alert.get("account")
        or alert.get("dns_hostname")
        or ""
    )

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
        or alert.get("status", "")
    )

    return {
        "Alert ID": alert.get(
            "alert_id", f"{module}-{index}"
        ),
        "Module": module,
        "Detection": alert.get("detection", "Unknown"),
        "Severity": alert.get("severity", "Informational"),
        "Confidence": alert.get("confidence", "Not specified"),
        "Timestamp": alert.get("timestamp", ""),
        "Computer": alert.get("computer", "Unknown"),
        "Actor": actor,
        "Process": alert.get("process", ""),
        "Target": target,
        "Event ID": str(alert.get("event_id", "")),
        "MITRE ATT&CK": ", ".join(mitre),
        "Status": alert.get("status", "Requires investigation"),
        "Evidence": str(evidence),
    }


# ---------------- APPLICATION ----------------

st.set_page_config(
    page_title="KaliSOC | Security Operations Center",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ KaliSOC")
st.caption("Windows Threat Hunting & Security Monitoring Platform")

st.markdown("---")

all_alerts = []
file_status = {}

for module, path in FILES.items():

    records, status = load_alert_file(path)
    file_status[module] = status

    for index, alert in enumerate(records, start=1):
        all_alerts.append(
            normalize_alert(alert, module, index)
        )


st.sidebar.title("KaliSOC Controls")
st.sidebar.caption("Local Security Monitoring")

st.sidebar.subheader("Data Sources")

for module, status in file_status.items():
    st.sidebar.write(f"**{module}:** {status}")

if not all_alerts:
    st.warning(
        "No alert records found. Run the detection modules first."
    )
    st.stop()


df = pd.DataFrame(all_alerts)

# ---------------- FILTERS ----------------

st.sidebar.divider()
st.sidebar.subheader("Filters")

severity_options = sorted(df["Severity"].unique().tolist())
module_options = sorted(df["Module"].unique().tolist())

selected_severities = st.sidebar.multiselect(
    "Severity",
    severity_options,
    default=severity_options,
)

selected_modules = st.sidebar.multiselect(
    "Detection Module",
    module_options,
    default=module_options,
)

filtered = df[
    df["Severity"].isin(selected_severities)
    & df["Module"].isin(selected_modules)
].copy()


# ---------------- METRICS ----------------

st.subheader("Security Overview")

total = len(filtered)
high = int((filtered["Severity"] == "High").sum())
medium = int((filtered["Severity"] == "Medium").sum())
info = int(
    (filtered["Severity"] == "Informational").sum()
)

c1, c2, c3, c4 = st.columns(4)

c1.metric("Detection Records", total)
c2.metric("High Severity", high)
c3.metric("Medium Severity", medium)
c4.metric("Informational", info)

st.markdown("---")


# ---------------- CHARTS ----------------

st.subheader("Detection Analytics")

left, right = st.columns(2)

with left:

    module_counts = (
        filtered["Module"]
        .value_counts()
        .reset_index()
    )

    module_counts.columns = ["Module", "Count"]

    fig = px.bar(
        module_counts,
        x="Module",
        y="Count",
        title="Detection Records by Module",
        text="Count",
    )

    st.plotly_chart(fig, use_container_width=True)


with right:

    severity_counts = (
        filtered["Severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = ["Severity", "Count"]

    fig = px.pie(
        severity_counts,
        names="Severity",
        values="Count",
        title="Severity Distribution",
        hole=0.45,
    )

    st.plotly_chart(fig, use_container_width=True)


st.markdown("---")


# ---------------- ALERT TABLE ----------------

st.subheader("Security Alerts")

display_columns = [
    "Alert ID",
    "Module",
    "Detection",
    "Severity",
    "Timestamp",
    "Computer",
    "Status",
]

st.dataframe(
    filtered[display_columns],
    use_container_width=True,
    hide_index=True,
)


# ---------------- ALERT INVESTIGATION ----------------

st.markdown("---")
st.subheader("Alert Investigation")

if not filtered.empty:

    selected_id = st.selectbox(
        "Select an alert to investigate",
        filtered["Alert ID"].tolist(),
    )

    selected = filtered[
        filtered["Alert ID"] == selected_id
    ].iloc[0]

    a, b = st.columns(2)

    with a:
        st.write("**Detection:**", selected["Detection"])
        st.write("**Severity:**", selected["Severity"])
        st.write("**Confidence:**", selected["Confidence"])
        st.write("**Computer:**", selected["Computer"])
        st.write("**Timestamp:**", selected["Timestamp"])

    with b:
        st.write("**Actor:**", selected["Actor"])
        st.write("**Process:**", selected["Process"])
        st.write("**Target:**", selected["Target"])
        st.write("**Windows Event ID:**", selected["Event ID"])
        st.write("**MITRE ATT&CK:**", selected["MITRE ATT&CK"])

    st.info(f"Investigation status: {selected['Status']}")

    with st.expander("View evidence details"):
        st.code(selected["Evidence"] or "No additional evidence")

else:
    st.info("No records match the selected filters.")


# ---------------- EXPORT ----------------

st.markdown("---")
st.subheader("Export Investigation Data")

csv_data = filtered.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Security Alerts CSV",
    data=csv_data,
    file_name="KaliSOC_security_alerts.csv",
    mime="text/csv",
)

st.caption(
    "KaliSOC | Local Threat Hunting and Digital Forensics"
)
