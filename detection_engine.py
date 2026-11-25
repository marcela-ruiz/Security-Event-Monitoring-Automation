import pandas as pd
from security_analyzer import load_events

ALERT_COLUMNS = [
    "Timestamp", "Alert", "Severity",
    "EventCount", "MITRE", "Recommendation"
]


def detect_threats(events):
    """Evaluate security events against detection rules."""

    alerts = []

    def add_alert(timestamp, name, severity,
                  count, mitre, recommendation):

        alerts.append({
            "Timestamp": timestamp,
            "Alert": name,
            "Severity": severity,
            "EventCount": count,
            "MITRE": mitre,
            "Recommendation": recommendation
        })

    # Rule 1: Repeated failed authentication
    failed = events[events["Id"] == 4625].copy()
    failed = failed.sort_values("TimeCreated")

    if not failed.empty:
        failures = failed.set_index("TimeCreated")
        counts = failures["Id"].rolling("5min").count()

        if counts.max() >= 5:
            add_alert(
                counts.idxmax(),
                "Potential Brute-Force Activity",
                "High",
                int(counts.max()),
                "T1110",
                "Review affected accounts and source IP addresses."
            )
        else:
            add_alert(
                failed["TimeCreated"].max(),
                "Failed Authentication Activity",
                "Low",
                len(failed),
                "Not established",
                "Review authentication context for anomalies."
            )

    # Rule 2: Privileged logon monitoring
    privileged = events[events["Id"] == 4672]

    if not privileged.empty:
        add_alert(
            privileged["TimeCreated"].max(),
            "Privileged Logon Activity",
            "Informational",
            len(privileged),
            "Not established",
            "Verify that privileged activity is authorized."
        )

    # Rule 3: Account creation
    created = events[events["Id"] == 4720]

    for _, event in created.iterrows():
        add_alert(
            event["TimeCreated"],
            "New User Account Created",
            "Medium",
            1,
            "T1136 (potential)",
            "Verify account creation authorization."
        )

    # Rule 4: Account deletion
    deleted = events[events["Id"] == 4726]

    for _, event in deleted.iterrows():
        add_alert(
            event["TimeCreated"],
            "User Account Deleted",
            "Medium",
            1,
            "Not established",
            "Review account deletion authorization."
        )

    # Rule 5: Account lockout
    locked = events[events["Id"] == 4740]

    for _, event in locked.iterrows():
        add_alert(
            event["TimeCreated"],
            "Account Lockout Detected",
            "Medium",
            1,
            "Not established",
            "Investigate repeated authentication failures."
        )

    # Rule 6: Security audit log clearing
    cleared = events[events["Id"] == 1102]

    for _, event in cleared.iterrows():
        add_alert(
            event["TimeCreated"],
            "Security Audit Log Cleared",
            "High",
            1,
            "T1070.001 (potential)",
            "Investigate log clearing and preserve evidence."
        )

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


if __name__ == "__main__":

    events = load_events()
    alerts = detect_threats(events)

    print("=" * 65)
    print("AUTOMATED SECURITY DETECTION ENGINE")
    print("=" * 65)

    print(f"\nEvents Analyzed: {len(events):,}")
    print("Detection Rules Evaluated: 6")
    print(f"Alerts Generated: {len(alerts)}")

    print("\nSECURITY ALERTS")
    print("-" * 65)

    if alerts.empty:
        print("No alerts generated.")
    else:
        for _, alert in alerts.iterrows():
            print(f"\nAlert: {alert['Alert']}")
            print(f"Severity: {alert['Severity']}")
            print(f"Related Events: {alert['EventCount']}")
            print(f"MITRE ATT&CK: {alert['MITRE']}")
            print(f"Recommendation: {alert['Recommendation']}")

    print("\nDetection analysis completed successfully.")
    print("=" * 65)
