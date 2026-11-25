import unittest
import pandas as pd
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_engine import detect_threats


def create_events(event_ids, interval=30):
    """Generate simulated Windows security events."""
    return pd.DataFrame({
        "Id": event_ids,
        "TimeCreated": pd.date_range(
            start="2026-01-01 09:00:00",
            periods=len(event_ids),
            freq=f"{interval}s"
        )
    })


class TestDetectionEngine(unittest.TestCase):

    def test_01_normal_logon(self):
        events = create_events([4624])
        alerts = detect_threats(events)
        self.assertTrue(alerts.empty)

    def test_02_single_failed_logon(self):
        events = create_events([4625])
        alerts = detect_threats(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts.iloc[0]["Severity"], "Low")

    def test_03_brute_force(self):
        events = create_events([4625] * 5)
        alerts = detect_threats(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts.iloc[0]["Severity"], "High")
        self.assertEqual(alerts.iloc[0]["MITRE"], "T1110")

    def test_04_privileged_logon(self):
        events = create_events([4672])
        alerts = detect_threats(events)
        self.assertEqual(
            alerts.iloc[0]["Severity"], "Informational"
        )

    def test_05_account_creation(self):
        events = create_events([4720])
        alerts = detect_threats(events)
        self.assertEqual(alerts.iloc[0]["Severity"], "Medium")
        self.assertEqual(
            alerts.iloc[0]["Alert"], "New User Account Created"
        )

    def test_06_account_deletion(self):
        events = create_events([4726])
        alerts = detect_threats(events)
        self.assertEqual(alerts.iloc[0]["Severity"], "Medium")
        self.assertEqual(
            alerts.iloc[0]["Alert"], "User Account Deleted"
        )

    def test_07_account_lockout(self):
        events = create_events([4740])
        alerts = detect_threats(events)
        self.assertEqual(alerts.iloc[0]["Severity"], "Medium")

    def test_08_audit_log_clearing(self):
        events = create_events([1102])
        alerts = detect_threats(events)
        self.assertEqual(alerts.iloc[0]["Severity"], "High")
        self.assertEqual(
            alerts.iloc[0]["MITRE"], "T1070.001 (potential)"
        )

    def test_09_separated_failed_logons(self):
        events = create_events([4625] * 5, interval=360)
        alerts = detect_threats(events)
        self.assertFalse(
            (alerts["Severity"] == "High").any()
        )

    def test_10_below_brute_force_threshold(self):
        events = create_events([4625] * 4)
        alerts = detect_threats(events)
        self.assertFalse(
            (alerts["Severity"] == "High").any()
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
