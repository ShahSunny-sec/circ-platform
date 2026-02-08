from __future__ import annotations

import json
from collections.abc import Iterable

from .models import IOC, RawEvent
from .utils import extract_iocs_from_text, is_private_ip


def _ioc_type_map(rx_type: str) -> str | None:
    if rx_type == "ipv4":
        return "ip"
    if rx_type == "domain":
        return "domain"
    if rx_type == "sha256":
        return "sha256"
    if rx_type == "url":
        return "url"
    if rx_type == "cve":
        return "cve"
    return None


def enrich_events(events: Iterable[RawEvent]) -> list[RawEvent]:
    out: list[RawEvent] = []
    for ev in events:
        # Entities: prefer flattened fields plus a few raw paths for CloudTrail and VPC
        entities: set[str] = set()
        for v in [ev.source_ip, ev.dest_ip, ev.hostname, ev.username]:
            if v:
                entities.add(str(v))

        # CloudTrail: add roleArn, groupId, trail name where available
        if ev.source == "cloudtrail":
            rp = ev.raw.get("requestParameters") or {}
            for k in ["roleArn", "groupId", "Name", "trailARN"]:
                if rp.get(k):
                    entities.add(str(rp.get(k)))

        # VPC: add interface_id if present
        if ev.source == "vpc_flow":
            if ev.raw.get("interface_id"):
                entities.add(str(ev.raw["interface_id"]))

        # IOC extraction: regex over JSON serialization of raw
        text = json.dumps(ev.raw, sort_keys=True, default=str)
        found = extract_iocs_from_text(text)

        iocs: list[IOC] = []
        for rx_type, value in found:
            t = _ioc_type_map(rx_type)
            if not t:
                continue
            # Drop private IPs as IOCs (still keep as entities)
            if t == "ip" and is_private_ip(value):
                continue
            iocs.append(IOC(type=t, value=value))

        # Deduplicate IOCs
        uniq = {(i.type, i.value) for i in iocs}
        iocs = [IOC(type=t, value=v) for (t, v) in sorted(uniq)]

        ev.entities = sorted(entities)
        ev.iocs = iocs
        out.append(ev)

    return out
