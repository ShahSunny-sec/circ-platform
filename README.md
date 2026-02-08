![CI](https://github.com/ShahSunny-sec/circ-platform/actions/workflows/ci.yml/badge.svg)

# Cloud Incident Response & Event Correlation Platform

A Python-based platform for **detecting, correlating, and prioritizing cloud security incidents**
using **AWS CloudTrail** and **VPC Flow Logs**.

This project simulates how a **Security Operations Center (SOC)** ingests raw cloud telemetry,
applies detection rules, correlates alerts into incidents, and enriches them with
severity and MITRE-style context.

---

## Why this project exists

Modern cloud environments generate massive volumes of security-relevant events.
This project demonstrates how to:

- Normalize heterogeneous cloud logs
- Detect suspicious activity using rule-based logic
- Correlate multiple alerts into higher-level incidents
- Assign severity and contextual metadata
- Present results in a simple UI for analysts

This is an **educational MVP**, designed to showcase backend logic, data modeling,
and SOC-style workflows — not a production SIEM.

---

## Key features

- CloudTrail & VPC Flow log normalization
- Rule-based detection engine
- Alert → Incident correlation
- Severity scoring and escalation
- MITRE-style tactic/technique mapping
- Streamlit-based analyst UI
- Unit tests and CI with GitHub Actions

---

## Project structure

```text
src/
  circ_platform/        # Core correlation and detection logic
rules/                  # Detection rules
data/samples/            # Sample input logs for demos/tests
ui/                     # Streamlit UI
tests/                  # Unit tests
docs/                   # Architecture notes & screenshots
.github/workflows/       # CI configuration

Installation
Core (library only)
pip install -e .

Development (tests + linting)
pip install -e ".[dev]"

UI (Streamlit dashboard)
pip install -e ".[ui]"

Everything
pip install -e ".[dev,ui,parquet]"

Running the platform
CLI pipeline (example)
circ run \
  --input data/samples \
  --output output/

Streamlit UI
streamlit run ui/app.py

Testing

Run the full test suite:

pytest -q


Lint the codebase:

ruff check .

Screenshots

Screenshots of the UI and incident views are available in docs/images/.

Security notes

No secrets are committed to this repository

Runtime configuration should be provided via environment variables

.env.example documents expected configuration keys

Disclaimer

This project is for learning and demonstration purposes only.
It is not intended for production use.

Author

Sunny Shah
GitHub: https://github.com/ShahSunny-sec