import pandas as pd
from pathlib import Path

# Project file paths
BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "security_events.csv"

# Windows security event classifications
EVENT_TYPES = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Account Logoff",
    4648: "Explicit Credential Logon",
    4672: "Special Privileges Assigned",
    4720: "User Account Created",
    4726: "User Account Deleted",
    4740: "Account Locked Out",
    1102: "Security Audit Log Cleared"
}


def load_events(data_file=DATA_FILE):
    """Load and prepare Windows security events."""
    events = pd.read_csv(data_file)

    events["TimeCreated"] = pd.to_datetime(
    events["TimeCreated"],
    format="mixed",
    errors="coerce"
    )

    events["Id"] = pd.to_numeric(
        events["Id"], errors="coerce"
    )

    events = events.dropna(subset=["TimeCreated", "Id"])
    events["Id"] = events["Id"].astype(int)

    events["EventType"] = (
        events["Id"].map(EVENT_TYPES).fillna("Other")
    )

    return events.sort_values("TimeCreated")


def analyze_events(events):
    """Calculate security monitoring statistics."""
    total = len(events)
    successful = int((events["Id"] == 4624).sum())
    failed = int((events["Id"] == 4625).sum())
    privileged = int((events["Id"] == 4672).sum())
    explicit = int((events["Id"] == 4648).sum())

    attempts = successful + failed
    failure_rate = failed / attempts * 100 if attempts else 0

    print("=" * 60)
    print("SECURITY EVENT MONITORING & INCIDENT RESPONSE")
    print("=" * 60)

    print("\nSECURITY EVENT SUMMARY")
    print("-" * 60)
    print(f"Total Security Events:       {total:,}")
    print(f"Successful Logons:           {successful:,}")
    print(f"Failed Logons:               {failed:,}")
    print(f"Privileged Logons:           {privileged:,}")
    print(f"Explicit Credential Events:  {explicit:,}")
    print(f"Logon Failure Rate:          {failure_rate:.2f}%")

    print("\nEVENT DISTRIBUTION")
    print("-" * 60)
    print(events["EventType"].value_counts().to_string())

    print("\nMONITORING PERIOD")
    print("-" * 60)
    print(f"Start: {events['TimeCreated'].min()}")
    print(f"End:   {events['TimeCreated'].max()}")

    print("\nAnalysis completed successfully.")
    print("=" * 60)


if __name__ == "__main__":
    security_events = load_events()
    analyze_events(security_events)
