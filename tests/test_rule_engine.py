import unittest
from src.rule_engine import RuleEngine

class RuleEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = RuleEngine()
        cls.logs = cls.engine.load_logs()
        cls.rules = cls.engine.load_rules()
        cls.result = cls.engine.process_logs(cls.logs)

    def test_five_configured_detectors(self):
        self.assertEqual(self.result["summary"]["detectors"], 5)

    def test_positive_brute_force_detected(self):
        self.assertTrue(any(a["rule_id"] == "R001" and a["user"] == "attacker" for a in self.result["alerts"]))

    def test_spread_out_failed_logins_do_not_trigger_brute_force(self):
        self.assertFalse(any(a["rule_id"] == "R001" and a["user"] == "slow-user" for a in self.result["alerts"]))

    def test_enumeration_requires_distinct_event_types(self):
        self.assertTrue(any(a["rule_id"] == "R002" and a["user"] == "recon-user" for a in self.result["alerts"]))
        self.assertFalse(any(a["rule_id"] == "R002" and a["user"] == "repeat-user" for a in self.result["alerts"]))

    def test_unusual_ip_detected_for_successful_login(self):
        self.assertTrue(any(a["rule_id"] == "R003" and a["user"] == "remote-user" for a in self.result["alerts"]))

    def test_approved_automation_excluded_from_privilege_alert(self):
        self.assertFalse(any(a["rule_id"] == "R004" and a["user"] == "approved-automation" for a in self.result["alerts"]))

    def test_sensitive_bucket_detected_and_excluded_bucket_ignored(self):
        self.assertTrue(any(a["rule_id"] == "R005" and a["user"] == "analyst" for a in self.result["alerts"]))
        self.assertFalse(any(a["rule_id"] == "R005" and a["user"] == "demo-user" for a in self.result["alerts"]))

    def test_timeline_window_uses_events_within_configured_period(self):
        alert = next(a for a in self.result["alerts"] if a["rule_id"] == "R001" and a["user"] == "attacker")
        self.assertEqual(len(alert["matched_events"]), 5)

if __name__ == "__main__":
    unittest.main()
