# Cloud Incident Response & Event Correlation Platform (CIRC) — MVP

Local-first incident correlation for AWS telemetry.

Ingest **CloudTrail** + **VPC Flow** logs → normalize into a canonical event model → extract/enrich IOCs → apply **Sigma-like YAML detections** → correlate alerts into **incidents** → export **Parquet/JSON** + triage in **Streamlit**.

---

## What you get

- **Batch pipeline**: ingest → normalize → enrich → detect → correlate → write
- **Portable rules**: YAML detections with severity, MITRE, and triage recommendations
- **Correlation**: time-window clustering + shared entity/IOC overlap + severity escalation controls
- **Investigation-ready artifacts**
  - `events.parquet`, `alerts.parquet`, `incidents.parquet`
  - `incidents.json` (UI-friendly)
  - `dead_letter.jsonl` (bad records)
  - `run_summary.json` (counts + stage timings)
- **Streamlit UI**: incident queue + drill-down + exports

---

## Architecture (workflow)

1. **Ingest**: scan an input directory for supported sources  
2. **Normalize**: convert raw records into a canonical event shape  
3. **Enrich**: extract IOCs + attach investigation links (VT / AbuseIPDB)  
4. **Detect**: apply YAML rules to produce alerts  
5. **Correlate**: cluster alerts into incidents (window + overlap)  
6. **Write**: append-only artifacts per run directory  

> Add: `docs/images/architecture.png` (see “README Visuals Checklist” below)

---

## Quickstart

### 1) Install
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
2) Configure
cp config/config.example.yaml config/config.yaml
export CIRC_CONFIG_PATH=config/config.yaml  # optional
3) Run the pipeline
circ run --input data --output output
4) Launch the UI
streamlit run ui/app.py
To open a specific run directory:

export CIRC_OUTPUT_RUN_DIR=output/<run-id>
streamlit run ui/app.py
Demo data
Sample inputs live in data/samples/ (CloudTrail JSONL + VPC Flow CSV).

circ run --input data/samples --output output
streamlit run ui/app.py
Rules
Rules live in rules/*.yaml and include: id, name, severity, log_source, detection logic, MITRE (optional), triage recommendations.

Quality
pytest -q
ruff check .
ruff format .
Screenshots
Place images in docs/images/:

01-incident-queue.png — Incident queue with filters

02-incident-detail.png — Incident overview + rationale

03-alerts-drilldown.png — Alerts + raw event drill-down

04-ioc-links.png — IOC investigation links (VT/AbuseIPDB)


---

## How to Run + Verify

```bash
# 1) install
python -m venv .venv
source .venv/bin/activate
pip install -e .

# 2) generate a run (uses included samples)
circ run --input data/samples --output output

# 3) open UI
streamlit run ui/app.py