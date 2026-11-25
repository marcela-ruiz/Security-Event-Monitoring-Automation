import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

from security_analyzer import load_events
from detection_engine import detect_threats

BASE_DIR = Path(__file__).resolve().parent

st.set_page_config(
    page_title="Security Operations Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Dashboard styling
st.markdown("""
<style>
[data-testid="stMetric"] {
    background-color: rgba(100, 116, 139, 0.10);
    border: 1px solid rgba(100, 116, 139, 0.30);
    padding: 16px;
    border-radius: 10px;
}
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Security Operations Dashboard")
st.caption("Security Event Monitoring & Incident Response Automation")

# Dataset selection
st.sidebar.header("Monitoring Controls")

datasets = {
    "Simulated Security Events":
        BASE_DIR / "data" / "demo_security_events.csv"
}

real_file = BASE_DIR / "data" / "security_events.csv"

if real_file.exists():
    datasets["Real Windows Security Events"] = real_file

selected_dataset = st.sidebar.selectbox(
    "Select Dataset",
    list(datasets.keys())
)

events = load_events(datasets[selected_dataset])

if events.empty:
    st.warning("No valid security events found.")
    st.stop()

if selected_dataset == "Simulated Security Events":
    st.info("Demonstration mode — using synthetic security events.")
else:
    st.info("Local analysis mode — using exported Windows security logs.")

# Date filters
min_date = events["TimeCreated"].min().date()
max_date = events["TimeCreated"].max().date()

date_range = st.sidebar.date_input(
    "Monitoring Period",
    value=(min_date, max_date),
    min_value=min_date,
    max_value=max_date
)

if len(date_range) != 2:
    st.warning("Select a complete date range.")
    st.stop()

period_events = events[
    (events["TimeCreated"].dt.date >= date_range[0]) &
    (events["TimeCreated"].dt.date <= date_range[1])
].copy()

# Event category filters
event_types = sorted(events["EventType"].unique())

selected_types = st.sidebar.multiselect(
    "Event Categories",
    event_types,
    default=event_types
)

filtered = period_events[
    period_events["EventType"].isin(selected_types)
].copy()

# Detection uses all events within the selected period
alerts = detect_threats(period_events)

# Key performance indicators
total = len(filtered)
successful = int((filtered["Id"] == 4624).sum())
failed = int((filtered["Id"] == 4625).sum())
privileged = int((filtered["Id"] == 4672).sum())

attempts = successful + failed
failure_rate = failed / attempts * 100 if attempts else 0

st.subheader("Security Monitoring Overview")

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("Total Events", f"{total:,}")
c2.metric("Successful Logons", f"{successful:,}")
c3.metric("Failed Logons", f"{failed:,}")
c4.metric("Privileged Logons", f"{privileged:,}")
c5.metric("Failure Rate", f"{failure_rate:.2f}%")

st.divider()

# Security alert overview
st.subheader("Threat Detection Summary")

severity_counts = alerts["Severity"].value_counts()

a1, a2, a3, a4 = st.columns(4)

a1.metric("🔴 High", int(severity_counts.get("High", 0)))
a2.metric("🟠 Medium", int(severity_counts.get("Medium", 0)))
a3.metric("🟡 Low", int(severity_counts.get("Low", 0)))
a4.metric("🔵 Informational",
          int(severity_counts.get("Informational", 0)))

if severity_counts.get("High", 0) > 0:
    st.warning(
        "High-severity security indicators detected. "
        "Further investigation is recommended."
    )
else:
    st.success(
        "No high-severity indicators detected by the current rules."
    )

st.caption(
    "Detection rules evaluate all events in the selected date "
    "range, regardless of the event category filter."
)

st.divider()

# Security visualizations
st.subheader("Security Event Analytics")

left, right = st.columns(2)

with left:
    distribution = (
        filtered["EventType"]
        .value_counts()
        .rename_axis("Event")
        .reset_index(name="Count")
    )

    fig = px.bar(
        distribution,
        x="Count",
        y="Event",
        orientation="h",
        text="Count",
        title="Security Event Distribution",
        color_discrete_sequence=["#38BDF8"],
        template="plotly_dark"
    )

    fig.update_layout(
        yaxis={"categoryorder": "total ascending"},
        showlegend=False,
        height=400
    )

    st.plotly_chart(fig, use_container_width=True)

with right:
    authentication = pd.DataFrame({
        "Result": ["Successful", "Failed"],
        "Count": [successful, failed]
    })

    if attempts:
        fig = px.pie(
            authentication,
            names="Result",
            values="Count",
            hole=0.65,
            title="Authentication Activity",
            color="Result",
            color_discrete_map={
                "Successful": "#22C55E",
                "Failed": "#EF4444"
            },
            template="plotly_dark"
        )

        fig.update_layout(height=400)

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No authentication events in the current selection.")

# Event activity timeline
st.subheader("Security Event Activity Timeline")

if not filtered.empty:
    timeline = (
        filtered.set_index("TimeCreated")
        .resample("1h")
        .size()
        .reset_index(name="Events")
    )

    fig = px.area(
        timeline,
        x="TimeCreated",
        y="Events",
        color_discrete_sequence=["#38BDF8"],
        template="plotly_dark"
    )

    fig.update_layout(
        xaxis_title="Timestamp",
        yaxis_title="Event Count",
        height=350
    )

    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No events match the selected filters.")

st.divider()

# Automated security alerts
st.subheader("Automated Security Alerts")

if not alerts.empty:
    severity_order = {
        "High": 0,
        "Medium": 1,
        "Low": 2,
        "Informational": 3
    }

    alerts = alerts.assign(
        Priority=alerts["Severity"].map(severity_order)
    ).sort_values(
        ["Priority", "Timestamp"],
        ascending=[True, False]
    ).drop(columns="Priority").reset_index(drop=True)

    st.dataframe(
        alerts,
        use_container_width=True,
        hide_index=True
    )

    st.download_button(
        label="Download Security Alert Report",
        data=alerts.to_csv(index=False).encode("utf-8"),
        file_name="security_alert_report.csv",
        mime="text/csv"
    )

    # Individual incident investigation
    st.subheader("Incident Investigation")

    alert_options = [
        f"{row['Severity']} | {row['Alert']} | {row['Timestamp']}"
        for _, row in alerts.iterrows()
    ]

    selected_alert = st.selectbox(
        "Select an alert to investigate",
        range(len(alert_options)),
        format_func=lambda i: alert_options[i]
    )

    incident = alerts.iloc[selected_alert]

    with st.container(border=True):
        st.markdown(f"### {incident['Alert']}")

        i1, i2, i3 = st.columns(3)

        i1.metric("Severity", incident["Severity"])
        i2.metric("Related Events", int(incident["EventCount"]))
        i3.metric("MITRE ATT&CK", incident["MITRE"])

        st.write("**Timestamp:**", incident["Timestamp"])
        st.write("**Recommended Response:**")
        st.write(incident["Recommendation"])

else:
    st.success("No alerts generated by the current detection rules.")

st.divider()

# Raw security event records
st.subheader("Security Event Records")

st.dataframe(
    filtered.sort_values("TimeCreated", ascending=False),
    use_container_width=True,
    hide_index=True
)

# Sidebar dataset information
st.sidebar.divider()
st.sidebar.subheader("Dataset Information")

st.sidebar.write(f"Total Records: {len(events):,}")
st.sidebar.write(f"Filtered Records: {len(filtered):,}")
st.sidebar.write("Detection Rules: 6")
st.sidebar.write(f"Start: {events['TimeCreated'].min()}")
st.sidebar.write(f"End: {events['TimeCreated'].max()}")

st.divider()

st.caption(
    "Security Event Monitoring & Incident Response Automation | "
    "Python • Pandas • Streamlit • Plotly"
)

st.caption(
    "Rule-based alerts represent potential security indicators, "
    "not confirmed compromises. Analysis uses exported event "
    "records rather than live monitoring or automated containment."
)
