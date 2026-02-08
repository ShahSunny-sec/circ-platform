from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def bump_severity(sev: Severity) -> Severity:
    order = [Severity.low, Severity.medium, Severity.high, Severity.critical]
    idx = order.index(sev)
    return order[min(idx + 1, len(order) - 1)]


class IOC(BaseModel):
    type: Literal["ip", "domain", "sha256", "url", "cve"]
    value: str


class MitreMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str


class RawEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source: Literal["cloudtrail", "vpc_flow", "generic"] = "generic"

    # flattened correlation fields (per spec rationale) :contentReference[oaicite:5]{index=5}
    source_ip: str | None = None
    dest_ip: str | None = None
    hostname: str | None = None
    username: str | None = None

    action: str | None = None
    direction: Literal["ingress", "egress", "internal"] | None = None

    # network-ish details
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    bytes: int | None = None

    iocs: list[IOC] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    raw: dict[str, Any] = Field(default_factory=dict)


class RuleCondition(BaseModel):
    field: str
    operator: str
    value: Any = None
    case_insensitive: bool = False


class DetectionRule(BaseModel):
    id: str
    name: str
    description: str
    severity: Severity
    logic: Literal["AND", "OR"] = "AND"
    mitre: list[MitreMapping] = Field(default_factory=list)
    conditions: list[RuleCondition] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    alert_id: str
    event_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    timestamp: datetime
    source: str

    iocs: list[IOC] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)

    mitre: list[MitreMapping] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    raw_event: dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    incident_id: str
    created_at: datetime

    severity: Severity
    alert_count: int

    time_window_start: datetime
    time_window_end: datetime

    alerts: list[Alert] = Field(default_factory=list)

    shared_entities: list[str] = Field(default_factory=list)
    shared_iocs: list[IOC] = Field(default_factory=list)
    mitre_techniques: list[MitreMapping] = Field(default_factory=list)

    tags: list[str] = Field(default_factory=list)
    summary: str
    rationale: dict[str, Any] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
