import pandas as pd
import random
from pathlib import Path
from datetime import datetime, timedelta

random.seed(42)

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = BASE_DIR / "data" / "demo_security_events.csv"

events = []
start = datetime(2026, 11, 1, 8, 0, 0)


def add_event(timestamp, event_id):
    events.append({
        "TimeCreated": timestamp,
        "Id": event_id,
        "LevelDisplayName": "Information",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "RecordId": len(events) + 1
    })


# Scenario 1: Normal system activity
for i in range(1000):
    timestamp = start + timedelta(minutes=i * 2)

    event_id = random.choices(
        [4624, 4634, 4672, 4648],
        weights=[50, 15, 30, 5]
    )[0]

    add_event(timestamp, event_id)


# Scenario 2: Potential brute-force activity
incident_start = start + timedelta(hours=8)

for i in range(25):
    add_event(
        incident_start + timedelta(seconds=i * 10),
        4625
    )


# Scenario 3: Suspicious authentication sequence
add_event(incident_start + timedelta(minutes=5), 4624)
add_event(incident_start + timedelta(minutes=6), 4672)


# Scenario 4: Account management activity
add_event(incident_start + timedelta(minutes=8), 4720)
add_event(incident_start + timedelta(minutes=10), 4740)
add_event(incident_start + timedelta(minutes=12), 4726)


# Scenario 5: Security audit log clearing
add_event(incident_start + timedelta(minutes=15), 1102)


# Export simulated security events
df = pd.DataFrame(events)
df = df.sort_values("TimeCreated").reset_index(drop=True)

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(OUTPUT_FILE, index=False)

print("=" * 60)
print("SIMULATED SECURITY EVENT DATASET")
print("=" * 60)

print(f"Total Events Generated: {len(df):,}")
print("\nEvent Distribution:")
print(df["Id"].value_counts().sort_index().to_string())

print("\nSimulated Security Scenarios:")
print("1. Normal system activity")
print("2. Potential brute-force activity")
print("3. Suspicious authentication sequence")
print("4. Account management activity")
print("5. Security audit log clearing")

print("\nDataset generated successfully.")
print(f"Output: {OUTPUT_FILE.name}")
print("=" * 60)
