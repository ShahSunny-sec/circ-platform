from __future__ import annotations

from collections.abc import Iterable
from html import escape

import streamlit as st


def sev_color(sev: str) -> str:
    s = (sev or "").lower()
    if s == "critical":
        return "#ff4d4f"
    if s == "high":
        return "#ff7a45"
    if s == "medium":
        return "#fadb14"
    if s == "low":
        return "#73d13d"
    return "#8c8c8c"


def severity_pill(sev: str) -> None:
    color = sev_color(sev)
    label = (sev or "unknown").upper()
    st.markdown(
        f"""<span class="sev-pill" style="color:{color}"><span class="sev-dot"></span>{escape(label)}</span>""",
        unsafe_allow_html=True,
    )


def chip(text: str) -> None:
    st.markdown(f"""<span class="chip">{escape(text)}</span>""", unsafe_allow_html=True)


def chips(items: Iterable[str], max_items: int = 24) -> None:
    shown = 0
    for it in items:
        if not it:
            continue
        chip(str(it))
        shown += 1
        if shown >= max_items:
            break
    if shown == 0:
        st.caption("—")


def external_ioc_links(ioc_type: str, value: str) -> list[tuple[str, str]]:
    """Return (label, url) pairs."""
    t = (ioc_type or "").lower()
    v = value.strip()
    out: list[tuple[str, str]] = []

    if t in {"ip", "ipv4", "ipv6"}:
        out.append(("AbuseIPDB", f"https://www.abuseipdb.com/check/{v}"))
        out.append(("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{v}"))
    elif t in {"domain", "hostname"}:
        out.append(("VirusTotal", f"https://www.virustotal.com/gui/domain/{v}"))
    elif t in {"url"}:
        out.append(("VirusTotal", f"https://www.virustotal.com/gui/url/{v}"))
    elif t in {"hash", "sha256", "sha1", "md5"}:
        out.append(("VirusTotal", f"https://www.virustotal.com/gui/file/{v}"))

    return out


def link_buttons(links: list[tuple[str, str]]) -> None:
    if not links:
        st.caption("—")
        return
    for label, url in links:
        st.markdown(
            f"""<a class="circ-link" href="{escape(url)}" target="_blank" rel="noopener noreferrer">{escape(label)}</a>""",
            unsafe_allow_html=True,
        )
