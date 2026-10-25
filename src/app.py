from flask import Flask, render_template
from src.rule_engine import RuleEngine

app = Flask(__name__, template_folder="../templates")
engine = RuleEngine()


def build_timeline(alert):
    events = alert.get("matched_events", [])
    if not events:
        return []
    from src.rule_engine import parse_time
    times = [parse_time(e.get("eventTime")) for e in events]
    valid = [t for t in times if t is not None]
    if not valid:
        return [{"event": e, "position": 0} for e in events]
    start, end = min(valid), max(valid)
    span = (end - start).total_seconds()
    output = []
    for event in events:
        t = parse_time(event.get("eventTime"))
        pos = 0 if t is None or span == 0 else round((t - start).total_seconds() / span * 100)
        output.append({"event": event, "position": pos})
    return output


@app.route("/")
def dashboard():
    result = engine.process_logs()
    for alert in result["alerts"]:
        alert["timeline"] = build_timeline(alert)
    return render_template("dashboard.html", **result)


@app.route("/health")
def health():
    return {"status": "ok", "service": "Cloud IDS demo"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
