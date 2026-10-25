"""Config-driven rule engine for Cloud IDS educational sample events."""
from __future__ import annotations
import json
from collections import defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def parse_time(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except (TypeError, ValueError):
        return None


class RuleEngine:
    """Loads events and YAML rules, then runs explicitly dispatched detectors."""
    def __init__(self, log_file=None, rules_file=None):
        self.log_file = Path(log_file) if log_file else ROOT / "data" / "sample_logs.json"
        self.rules_file = Path(rules_file) if rules_file else ROOT / "rules" / "rules.yaml"

    def load_logs(self):
        with self.log_file.open(encoding="utf-8") as f:
            logs = json.load(f)
        if not isinstance(logs, list) or any(not isinstance(x, dict) for x in logs):
            raise ValueError("The log file must contain a JSON list of event objects.")
        required = {"eventName", "eventTime", "user", "sourceIP", "response"}
        for i, event in enumerate(logs):
            missing = required - event.keys()
            if missing:
                raise ValueError(f"Log entry {i} is missing required fields: {', '.join(sorted(missing))}")
        return logs

    def load_rules(self):
        with self.rules_file.open(encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        rules = config.get("rules") if isinstance(config, dict) else None
        if not isinstance(rules, list):
            raise ValueError("rules.yaml must contain a 'rules' list.")
        for rule in rules:
            if not isinstance(rule, dict) or not all(k in rule for k in ("id", "name", "severity", "type", "condition")):
                raise ValueError("Every rule needs id, name, severity, type, and condition fields.")
            if rule["type"] not in {"brute_force", "enumeration", "unusual_access", "privilege_escalation", "sensitive_access"}:
                raise ValueError(f"Unsupported detector type: {rule['type']}")
        return rules

    @staticmethod
    def _base_alert(rule, events, reason):
        first = min(events, key=lambda e: parse_time(e["eventTime"]) or datetime.min.replace(tzinfo=timezone.utc))
        last = max(events, key=lambda e: parse_time(e["eventTime"]) or datetime.min.replace(tzinfo=timezone.utc))
        return {
            "rule_id": rule["id"], "rule": rule["name"], "severity": rule["severity"],
            "mitre_attack": rule.get("mitre_attack", "Not specified"),
            "recommendation": rule.get("recommendation", "Review the event."),
            "user": first.get("user", "unknown"), "source_ip": first.get("sourceIP", "unknown"),
            "event_name": first.get("eventName", "unknown"), "timestamp": first.get("eventTime", "unknown"),
            "reason": reason, "matched_events": sorted(events, key=lambda e: parse_time(e["eventTime"]) or datetime.min.replace(tzinfo=timezone.utc)),
            "window_start": first.get("eventTime", "unknown"), "window_end": last.get("eventTime", "unknown"),
        }

    @staticmethod
    def _find_actor_bursts(events, count, window_minutes):
        """Return each actor's sliding-window bursts meeting the required event count."""
        by_actor = defaultdict(list)
        for event in events:
            when = parse_time(event.get("eventTime"))
            if when:
                by_actor[event.get("user", "unknown")].append((when, event))
        bursts = []
        from datetime import timedelta
        window = timedelta(minutes=float(window_minutes))
        for actor, pairs in by_actor.items():
            pairs.sort(key=lambda pair: pair[0])
            left = 0
            for right, (end_time, _) in enumerate(pairs):
                while left <= right and end_time - pairs[left][0] > window:
                    left += 1
                candidate = [event for _, event in pairs[left:right + 1]]
                if len(candidate) >= int(count):
                    # Keep only the first minimal qualifying window for each ending event.
                    bursts.append((actor, candidate[-int(count):]))
        # Deduplicate identical event-id sets, as overlapping windows can otherwise repeat.
        unique = {}
        for actor, burst in bursts:
            key = (actor, tuple(e.get("event_id", id(e)) for e in burst))
            unique[key] = (actor, burst)
        return list(unique.values())

    def _detect_brute_force(self, rule, logs):
        c = rule["condition"]
        candidates = [e for e in logs if e.get("eventName") == c.get("eventName", "ConsoleLogin") and e.get("response") == c.get("response", "Failure")]
        results = []
        for actor, burst in self._find_actor_bursts(candidates, c.get("count", 5), c.get("time_window_minutes", 5)):
            results.append(self._base_alert(rule, burst, f"Actor {actor} had {len(burst)} failed login attempts within {c.get('time_window_minutes', 5)} minutes (threshold: {c.get('count', 5)})."))
        return results

    def _detect_enumeration(self, rule, logs):
        c = rule["condition"]
        candidates = [e for e in logs if e.get("eventName") not in {"ConsoleLogin", "GetObject", "PutObject"}]
        results = []
        for actor, burst in self._find_actor_bursts(candidates, c.get("count", 4), c.get("time_window_minutes", 10)):
            distinct = {e.get("eventName") for e in burst}
            if len(distinct) >= int(c.get("min_distinct_event_types", 3)):
                results.append(self._base_alert(rule, burst, f"Actor {actor} performed {len(distinct)} distinct event types within {c.get('time_window_minutes', 10)} minutes: {', '.join(sorted(distinct))}."))
        return results

    def _detect_unusual_access(self, rule, logs):
        c = rule["condition"]
        trusted = [ip_network(x, strict=False) for x in c.get("trusted_cidrs", [])]
        results = []
        for event in logs:
            if event.get("eventName") != c.get("eventName", "ConsoleLogin") or event.get("response") != "Success":
                continue
            try:
                address = ip_address(event.get("sourceIP", ""))
            except ValueError:
                continue
            if trusted and not any(address in network for network in trusted):
                results.append(self._base_alert(rule, [event], f"Successful login from {address}, which is outside the configured trusted CIDR ranges."))
        return results

    def _detect_privilege_escalation(self, rule, logs):
        c = rule["condition"]
        event_names = set(c.get("event_names", []))
        excluded = set(c.get("excluded_actors", []))
        return [self._base_alert(rule, [e], f"Event {e['eventName']} can change identity privileges or access permissions.")
                for e in logs if e.get("eventName") in event_names and e.get("user") not in excluded and e.get("response") == "Success"]

    def _detect_sensitive_access(self, rule, logs):
        c = rule["condition"]
        event_names, sensitive = set(c.get("event_names", [])), set(c.get("sensitive_buckets", []))
        excluded_buckets, excluded_actors = set(c.get("excluded_buckets", [])), set(c.get("excluded_actors", []))
        results = []
        for event in logs:
            bucket = event.get("bucket", event.get("resource", ""))
            if event.get("eventName") in event_names and bucket in sensitive and bucket not in excluded_buckets and event.get("user") not in excluded_actors and event.get("response") == "Success":
                results.append(self._base_alert(rule, [event], f"Successful {event['eventName']} event accessed configured sensitive bucket '{bucket}'."))
        return results

    def process_logs(self, logs=None):
        logs = self.load_logs() if logs is None else logs
        rules = self.load_rules()
        detector_map = {
            "brute_force": self._detect_brute_force,
            "enumeration": self._detect_enumeration,
            "unusual_access": self._detect_unusual_access,
            "privilege_escalation": self._detect_privilege_escalation,
            "sensitive_access": self._detect_sensitive_access,
        }
        alerts = []
        for rule in rules:
            alerts.extend(detector_map[rule["type"]](rule, logs))
        alerts.sort(key=lambda a: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(a["severity"].upper(), 4), a["timestamp"]))
        alert_event_ids = {e.get("event_id") for a in alerts for e in a["matched_events"]}
        return {"alerts": alerts, "summary": {"events": len(logs), "alerts": len(alerts), "detectors": len(rules), "unmatched_events": len(logs) - len(alert_event_ids)}}
