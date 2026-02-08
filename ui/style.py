from __future__ import annotations

import streamlit as st


def inject_css() -> None:
    """Inject a minimal, recruiter-friendly theme (works with Streamlit base theme)."""
    st.markdown(
        """
<style>
/* Layout */
.block-container { padding-top: 2.0rem; padding-bottom: 2.0rem; max-width: 1200px; }
section[data-testid="stSidebar"] { border-right: 1px solid rgba(255,255,255,0.06); }

/* Typography */
h1, h2, h3 { letter-spacing: -0.02em; }
.small-muted { opacity: 0.72; font-size: 0.9rem; }

/* Cards */
.circ-card {
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 14px;
  padding: 14px 14px 12px 14px;
  background: rgba(255,255,255,0.02);
}
.circ-card + .circ-card { margin-top: 10px; }

.circ-kpi {
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 14px;
  padding: 14px;
  background: rgba(255,255,255,0.02);
}

.circ-row { display:flex; gap:10px; flex-wrap: wrap; align-items: center; }
.circ-row > * { margin: 0; }

/* Severity pill */
.sev-pill {
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 12px;
  border: 1px solid rgba(255,255,255,0.10);
  background: rgba(255,255,255,0.03);
}
.sev-dot { width: 8px; height: 8px; border-radius: 999px; background: currentColor; opacity: 0.9; }

/* Chips */
.chip {
  display:inline-flex;
  align-items:center;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 12px;
  border: 1px solid rgba(255,255,255,0.10);
  background: rgba(255,255,255,0.02);
  margin: 0 6px 6px 0;
}

/* Link buttons */
a.circ-link {
  text-decoration: none !important;
  border: 1px solid rgba(255,255,255,0.10);
  padding: 6px 10px;
  border-radius: 10px;
  display:inline-block;
  margin-right: 8px;
  margin-bottom: 8px;
  background: rgba(255,255,255,0.02);
}
a.circ-link:hover { border-color: rgba(255,255,255,0.20); background: rgba(255,255,255,0.04); }

/* Dataframe tweaks */
div[data-testid="stDataFrame"] { border-radius: 14px; overflow: hidden; border: 1px solid rgba(255,255,255,0.08); }

/* Hide Streamlit footer */
footer { visibility: hidden; }
</style>
""",
        unsafe_allow_html=True,
    )
