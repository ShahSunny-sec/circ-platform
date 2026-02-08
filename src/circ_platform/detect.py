from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

import yaml

from .models import Alert, DetectionRule, RawEvent, Severity
from .utils import deep_get


def load_rules(rules_dir: Path) -> list[DetectionRule]:
    rules: list[DetectionRule] = []
    for p in sorted(rules_dir.glob("*.yaml")):
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        # map severity string to enum
        raw["severity"] = Severity(str(raw["severity"]).lower())
        rules.append(DetectionRule.model_validate(raw))
    return rules


def _field_value(ev: RawEvent, field: str) -> Any:
    # allow direct normalized fields (source_ip, dest_ip, username, action, bytes, dst_port, etc.)
    if hasattr(ev, field):
        return getattr(ev, field)
    # dotted field paths resolved against raw payload
    return deep_get(ev.raw, field)


def _match_condition(ev: RawEvent, cond) -> bool:
    op = cond.operator
    val = _field_value(ev, cond.field)
    target = cond.value

    if op == "exists":
        return val is not None
    if op == "eq":
        return val == target
    if op == "neq":
        return val != target
    if op == "in":
        return val in (target or [])
    if op == "not_in":
        return val not in (target or [])
    if op == "contains":
        if val is None:
            return False
        s = str(val)
        t = str(target)
        if cond.case_insensitive:
            s, t = s.lower(), t.lower()
        return t in s
    if op == "contains_any":
        if val is None:
            return False
        s = str(val)
        if cond.case_insensitive:
            s = s.lower()
        for item in target or []:
            t = str(item)
            if cond.case_insensitive:
                t = t.lower()
            if t in s:
                return True
        return False
    if op == "startswith":
        if val is None:
            return False
        s = str(val)
        t = str(target)
        if cond.case_insensitive:
            s, t = s.lower(), t.lower()
        return s.startswith(t)
    if op == "not_startswith":
        if val is None:
            return True
        s = str(val)
        t = str(target)
        if cond.case_insensitive:
            s, t = s.lower(), t.lower()
        return not s.startswith(t)
    if op == "endswith":
        if val is None:
            return False
        return str(val).endswith(str(target))
    if op in ["gt", "gte", "lt", "lte"]:
        if val is None:
            return False
        try:
            fv = float(val)
            tv = float(target)
        except Exception:
            return False
        if op == "gt":
            return fv > tv
        if op == "gte":
            return fv >= tv
        if op == "lt":
            return fv < tv
        if op == "lte":
            return fv <= tv
    if op == "regex":
        if val is None:
            return False
        flags = re.IGNORECASE if cond.case_insensitive else 0
        return re.search(str(target), str(val), flags=flags) is not None

    raise ValueError(f"Unsupported operator: {op}")


def _match_rule(ev: RawEvent, rule: DetectionRule) -> bool:
    checks = [_match_condition(ev, c) for c in rule.conditions]
    if rule.logic == "AND":
        return all(checks)
    return any(checks)


def run_detection(events: list[RawEvent], rules: list[DetectionRule]) -> list[Alert]:
    alerts: list[Alert] = []
    for ev in events:
        for rule in rules:
            if _match_rule(ev, rule):
                alerts.append(
                    Alert(
                        alert_id=str(uuid.uuid4()),
                        event_id=ev.event_id,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        timestamp=ev.timestamp,
                        source=ev.source,
                        iocs=ev.iocs,
                        entities=ev.entities,
                        mitre=rule.mitre,
                        tags=sorted(set(ev.tags + rule.tags)),
                        raw_event=ev.raw,
                    )
                )
    return alerts
