from __future__ import annotations

import ipaddress
import uuid
from typing import Any

from .models import RawEvent
from .utils import parse_timestamp


def _safe_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        return None


def _is_rfc1918_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return False
        return (
            addr in ipaddress.ip_network("10.0.0.0/8")
            or addr in ipaddress.ip_network("172.16.0.0/12")
            or addr in ipaddress.ip_network("192.168.0.0/16")
        )
    except Exception:
        return False


def normalize_cloudtrail(raw: dict[str, Any]) -> RawEvent:
    event_id = str(uuid.uuid4())
    ts = parse_timestamp(raw.get("eventTime"))

    user = raw.get("userIdentity") or {}
    username = user.get("userName") or user.get("principalId")

    source_ip = raw.get("sourceIPAddress")
    action = raw.get("eventName")

    return RawEvent(
        event_id=event_id,
        timestamp=ts,
        source="cloudtrail",
        source_ip=source_ip,
        username=username,
        action=action,
        raw=raw,
    )


def normalize_vpc_flow(raw: dict[str, Any]) -> RawEvent:
    event_id = str(uuid.uuid4())
    # VPC flow has start/end epoch seconds; use start
    ts = parse_timestamp(raw.get("start"))

    src = raw.get("srcaddr")
    dst = raw.get("dstaddr")

    src_port = _safe_int(raw.get("srcport"))
    dst_port = _safe_int(raw.get("dstport"))
    bytes_ = _safe_int(raw.get("bytes"))
    proto_num = _safe_int(raw.get("protocol"))

    proto = None
    if proto_num == 6:
        proto = "TCP"
    elif proto_num == 17:
        proto = "UDP"
    elif proto_num is not None:
        proto = str(proto_num)

    # Direction heuristic: private->public = egress; public->private = ingress; else internal/unknown
    direction = None
    if src and dst:
        if _is_rfc1918_ipv4(src) and not _is_rfc1918_ipv4(dst):
            direction = "egress"
        elif not _is_rfc1918_ipv4(src) and _is_rfc1918_ipv4(dst):
            direction = "ingress"
        elif _is_rfc1918_ipv4(src) and _is_rfc1918_ipv4(dst):
            direction = "internal"

    action = raw.get("action")

    return RawEvent(
        event_id=event_id,
        timestamp=ts,
        source="vpc_flow",
        source_ip=src,
        dest_ip=dst,
        action=action,
        direction=direction,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        bytes=bytes_,
        raw=raw,
    )


def normalize_record(source: str, raw: dict[str, Any]) -> RawEvent:
    if source == "cloudtrail":
        return normalize_cloudtrail(raw)
    if source == "vpc_flow":
        return normalize_vpc_flow(raw)

    # generic
    event_id = str(uuid.uuid4())
    ts = parse_timestamp(raw.get("timestamp") or raw.get("time") or raw.get("ts"))
    return RawEvent(
        event_id=event_id,
        timestamp=ts,
        source="generic",
        raw=raw,
    )
