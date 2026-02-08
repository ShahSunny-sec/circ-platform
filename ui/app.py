from __future__ import annotations
from pathlib import Path
import json
import os
from typing import Any

import pandas as pd
import streamlit as st

from components import chips, external_ioc_links, link_buttons, severity_pill
from data import DEFAULT_OUTPUT_ROOT, list_runs, load_incidents, load_run_summary, severity_rank
from style import inject_css


def _parse_ts(ts: str) -> pd.Timestamp:
    # incidents.json timestamps are ISO strings; handle best-effort
    return pd.to_datetime(ts, utc=True, errors="coerce")


def _incident_rows(incidents: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for inc in incidents:
        rows.append(
            {
                "incident_id": inc.get("incident_id"),
                "severity": inc.get("severity", "unknown"),
                "alert_count": int(inc.get("alert_count", 0)),
                "time_window_end": inc.get("time_window_end"),
                "time_window_start": inc.get("time_window_start"),
                "summary": inc.get("summary", ""),
            }
        )
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["sev_rank"] = df["severity"].map(severity_rank)
    df["time_window_end_ts"] = df["time_window_end"].map(_parse_ts)
    df = df.sort_values(["sev_rank", "time_window_end_ts"], ascending=[False, False])
    return df


def _alerts_table(incident: dict[str, Any]) -> pd.DataFrame:
    alerts = incident.get("alerts", [])
    rows = []
    for a in alerts:
        rows.append(
            {
                "timestamp": a.get("timestamp"),
                "severity": a.get("severity", "unknown"),
                "rule_id": a.get("rule_id"),
                "rule_name": a.get("rule_name"),
                "source": a.get("source"),
                "entities": ", ".join(a.get("entities", []) or []),
                "iocs": ", ".join(
                    [f"{x.get('type')}:{x.get('value')}" for x in (a.get("iocs") or [])]
                ),
            }
        )
    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp_ts"] = df["timestamp"].map(_parse_ts)
        df = df.sort_values("timestamp_ts", ascending=True).drop(columns=["timestamp_ts"])
    return df


st.set_page_config(page_title="CIRC Platform", layout="wide", page_icon="🛰️")
inject_css()

# ---------- Sidebar: run selection ----------
st.sidebar.markdown("## CIRC Platform")
st.sidebar.caption("Local-first incident correlation for AWS telemetry")

output_root = Path(os.environ.get("CIRC_OUTPUT_ROOT", str(DEFAULT_OUTPUT_ROOT))).resolve()
runs = list_runs(output_root)

if not runs:
    st.sidebar.warning("No runs found. Generate data first: `circ run --input data --output output`")
    st.title("CIRC Platform")
    st.info("Run the pipeline to create artifacts, then reload this page.")
    st.stop()

run_labels = [r.run_id for r in runs]
selected_run_id = st.sidebar.selectbox("Run directory", options=run_labels, index=0)
run_dir = next(r.run_dir for r in runs if r.run_id == selected_run_id)

st.sidebar.markdown("---")
summary = load_run_summary(run_dir)
counts = (summary.get("counts") or {}) if isinstance(summary, dict) else {}

c1, c2 = st.sidebar.columns(2)
with c1:
    st.metric("Events", int(counts.get("events", 0)))
with c2:
    st.metric("Incidents", int(counts.get("incidents", 0)))

st.sidebar.caption(f"Output root: `{output_root}`")
st.sidebar.caption(f"Active run: `{run_dir}`")

# ---------- Header ----------
st.markdown(
    """
<div class="circ-row">
  <h1 style="margin:0">Incident Queue</h1>
  <span class="small-muted">CloudTrail + VPC Flow → detections → correlated incidents</span>
</div>
""",
    unsafe_allow_html=True,
)

# ---------- Load incidents ----------
incidents = load_incidents(run_dir)
if not incidents:
    st.info("No incidents found for this run.")
    st.stop()

inc_df = _incident_rows(incidents)

# ---------- Layout: queue (left) + detail (right) ----------
left, right = st.columns([1.05, 1.25], gap="large")

with left:
    st.markdown("### Filters")

    sev_options = ["critical", "high", "medium", "low"]
    default_sev = ["critical", "high", "medium"]

    sev_filter = st.multiselect("Severity", options=sev_options, default=default_sev)
    q = st.text_input(
        "Search (incident id / summary / rule / entity)",
        value="",
        placeholder="e.g., ConsoleLogin or 203.0.113.10",
    )
    min_alerts = st.slider(
        "Min alerts",
        min_value=1,
        max_value=max(int(inc_df["alert_count"].max()), 1),
        value=1,
    )

    view = inc_df.copy()
    view = view[view["severity"].isin(sev_filter)]
    view = view[view["alert_count"] >= min_alerts]

    if q.strip():
        ql = q.lower().strip()
        keep_ids = set()
        for inc in incidents:
            if ql in str(inc.get("incident_id", "")).lower() or ql in str(inc.get("summary", "")).lower():
                keep_ids.add(inc.get("incident_id"))
                continue
            for a in inc.get("alerts", [])[:50]:
                hay = " ".join(
                    [
                        str(a.get("rule_id", "")),
                        str(a.get("rule_name", "")),
                        " ".join(a.get("entities", []) or []),
                        " ".join([f"{x.get('type')}:{x.get('value')}" for x in (a.get("iocs") or [])]),
                    ]
                ).lower()
                if ql in hay:
                    keep_ids.add(inc.get("incident_id"))
                    break
        view = view[view["incident_id"].isin(list(keep_ids))]

    st.markdown("### Queue")
    if view.empty:
        st.info("No incidents match your filters.")
        st.stop()

    st.dataframe(
        view[["incident_id", "severity", "alert_count", "time_window_end", "summary"]],
        use_container_width=True,
        hide_index=True,
    )

    selected_id = st.selectbox(
        "Open incident",
        options=view["incident_id"].tolist(),
        index=0,
        help="Select an incident to view the full context on the right.",
        key="incident_select",
    )

incident = next((x for x in incidents if x.get("incident_id") == selected_id), None)
if not incident:
    st.stop()

with right:
    st.markdown("### Incident Detail")

    k1, k2, k3 = st.columns([0.9, 1.0, 1.4])
    with k1:
        st.markdown('<div class="circ-kpi">', unsafe_allow_html=True)
        st.caption("Severity")
        severity_pill(str(incident.get("severity", "unknown")))
        st.markdown("</div>", unsafe_allow_html=True)
    with k2:
        st.markdown('<div class="circ-kpi">', unsafe_allow_html=True)
        st.caption("Alerts")
        st.markdown(
            f"<div style='font-size:28px; font-weight:700'>{int(incident.get('alert_count', 0))}</div>",
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)
    with k3:
        st.markdown('<div class="circ-kpi">', unsafe_allow_html=True)
        st.caption("Time window (UTC)")
        st.markdown(
            f"<div style='font-weight:600'>{incident.get('time_window_start')} → {incident.get('time_window_end')}</div>",
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")

    tabs = st.tabs(["Overview", "Alerts", "Entities & IOCs", "MITRE", "Artifacts"])

    with tabs[0]:
        st.markdown("#### Summary")
        st.write(incident.get("summary", "—"))

        st.markdown("#### Why grouped?")
        st.json(incident.get("rationale", {}), expanded=False)

        st.markdown("#### Alert timeline")
        alerts_df = _alerts_table(incident)
        if not alerts_df.empty:
            tmp = alerts_df.copy()
            tmp["timestamp"] = pd.to_datetime(tmp["timestamp"], utc=True, errors="coerce")
            tmp = tmp.dropna(subset=["timestamp"])
            tmp["minute"] = tmp["timestamp"].dt.floor("min")
            chart = tmp.groupby(["minute", "severity"]).size().unstack(fill_value=0)
            st.area_chart(chart)
        else:
            st.caption("—")

    with tabs[1]:
        st.markdown("#### Alerts in this incident")
        alerts = incident.get("alerts", [])
        alerts_df = _alerts_table(incident)
        st.dataframe(alerts_df, use_container_width=True, hide_index=True)

        st.markdown("#### Raw event drill-down")
        if not alerts:
            st.caption("—")
        else:
            idx = st.number_input(
                "Alert index", min_value=0, max_value=len(alerts) - 1, value=0, step=1
            )
            selected_alert = alerts[int(idx)]
            st.markdown("**Rule**")
            st.code(f"{selected_alert.get('rule_id')} — {selected_alert.get('rule_name')}")
            st.markdown("**Raw event**")
            st.json(selected_alert.get("raw_event", {}), expanded=False)

    with tabs[2]:
        st.markdown("#### Shared entities")
        chips([str(x) for x in (incident.get("shared_entities") or [])])

        st.markdown("#### Shared IOCs")
        shared_iocs = incident.get("shared_iocs") or []
        if not shared_iocs:
            st.caption("—")
        else:
            for i in shared_iocs:
                t = str(i.get("type", "ioc"))
                v = str(i.get("value", ""))
                st.markdown('<div class="circ-card">', unsafe_allow_html=True)
                st.markdown(
                    f"<div style='font-weight:650'>{t}: <span style='opacity:0.85'>{v}</span></div>",
                    unsafe_allow_html=True,
                )
                link_buttons(external_ioc_links(t, v))
                st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("#### IOCs observed in alerts")
        observed = []
        for a in incident.get("alerts", []):
            for i in a.get("iocs", []) or []:
                observed.append((str(i.get("type", "ioc")), str(i.get("value", ""))))

        if not observed:
            st.caption("—")
        else:
            seen = set()
            for t, v in observed:
                key = (t, v)
                if key in seen or not v:
                    continue
                seen.add(key)
                st.markdown('<div class="circ-card">', unsafe_allow_html=True)
                st.markdown(
                    f"<div style='font-weight:650'>{t}: <span style='opacity:0.85'>{v}</span></div>",
                    unsafe_allow_html=True,
                )
                link_buttons(external_ioc_links(t, v))
                st.markdown("</div>", unsafe_allow_html=True)

    with tabs[3]:
        st.markdown("#### MITRE techniques (from detections)")
        mitre = incident.get("mitre_techniques") or []
        if not mitre:
            st.caption("—")
        else:
            for m in mitre:
                st.markdown('<div class="circ-card">', unsafe_allow_html=True)
                st.write(m)
                st.markdown("</div>", unsafe_allow_html=True)

    with tabs[4]:
        st.markdown("#### Download incident bundle")
        export_json = json.dumps(incident, indent=2, default=str).encode("utf-8")
        st.download_button(
            "Download incident JSON",
            data=export_json,
            file_name=f"{incident.get('incident_id', 'incident')}.json",
            use_container_width=True,
        )

        alerts_df = _alerts_table(incident)
        export_csv = alerts_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download alert timeline CSV",
            data=export_csv,
            file_name=f"{incident.get('incident_id', 'incident')}_timeline.csv",
            use_container_width=True,
        )

        st.markdown("#### Run artifacts")
        st.caption("Generated by `circ run` in the selected run directory.")
        for fname in [
            "events.parquet",
            "alerts.parquet",
            "incidents.parquet",
            "incidents.json",
            "dead_letter.jsonl",
            "run_summary.json",
        ]:
            p = run_dir / fname
            st.markdown(f"- `{fname}`" + ("" if p.exists() else " (missing)"))
