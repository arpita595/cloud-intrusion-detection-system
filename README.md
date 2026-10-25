# Cloud Intrusion Detection System (Cloud IDS)

A reconstructed educational project based on the supplied project reference document. It analyzes static CloudTrail-style sample events, applies YAML-configured rules, and presents explainable alerts and near-miss examples in a Flask dashboard.

## Project structure

```text
Cloud-IDS/
├── data/sample_logs.json
├── rules/rules.yaml
├── src/app.py
├── src/rule_engine.py
├── templates/dashboard.html
├── tests/test_rule_engine.py
├── requirements.txt
└── README.md
```

## Run in GitHub Codespaces

1. Upload these project files into your repository (or upload this ZIP and extract it in a terminal).
2. Open the repository, click **Code → Codespaces → Create codespace on main**.
3. In the Codespaces terminal, run:
   ```bash
   python -m pip install -r requirements.txt
   python -m unittest discover -s tests -v
   python -m src.app
   ```
4. When Codespaces asks about port **5000**, choose **Open in Browser**.

## Run locally

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m src.app
```
Then visit `http://127.0.0.1:5000`.

## Detection rules

- **Brute force:** configured number of failed logins for one actor inside a sliding time window.
- **Enumeration:** a burst of events from one actor inside a time window, with the configured minimum number of distinct event types.
- **Unusual access:** checks whether source IPs fall within configured trusted CIDR networks.
- **Privilege escalation:** detects configured IAM/permission-changing event types, except approved automation actors.
- **Sensitive access:** detects configured sensitive buckets/resources, except configured exclusions.

## Scope and limitations

This prototype uses a static JSON dataset. It does not connect to AWS, ingest live CloudTrail events, persist alert history, or authenticate dashboard users. The MITRE ATT&CK labels and response recommendations are educational references and should be checked against the exact deployment context. This is a reconstructed implementation, not recovered original source code. Do not describe sample data as live cloud telemetry.
