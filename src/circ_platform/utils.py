from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


def parse_timestamp(value: Any) -> datetime:
    """
    Accepts:
      - ISO8601 string (with Z or offset)
      - unix epoch seconds (int/str)
      - datetime
    Returns timezone-aware UTC datetime.
    """
    if value is None:
        raise ValueError("timestamp is None")

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        dt = datetime.fromtimestamp(int(value), tz=UTC)
    elif isinstance(value, str):
        s = value.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
    else:
        raise ValueError(f"unsupported timestamp type: {type(value)}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)

    return dt.astimezone(UTC)


def deep_get(obj: dict[str, Any], dotted_path: str) -> Any:
    """
    Resolve dotted paths against a dict: "a.b.c"
    Returns None if any segment missing.
    """
    cur: Any = obj
    for part in dotted_path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
        addr = ipaddress.ip_address(ip)

        # ipaddress.is_private is broader than RFC1918 (it treats TEST-NET as private).
        # For direction heuristics we only want RFC1918 (plus link-local/loopback).
        if addr.is_loopback or addr.is_link_local:
            return True

        if isinstance(addr, IPv4Address):
            rfc1918 = (
                IPv4Network("10.0.0.0/8"),
                IPv4Network("172.16.0.0/12"),
                IPv4Network("192.168.0.0/16"),
            )
            return any(addr in net for net in rfc1918)

        # Minimal IPv6 support: treat ULA as private
        return addr in ipaddress.IPv6Network("fc00::/7")
    except Exception:
        return False


IOC_REGEX = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
    ),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(r"\bhttps?://[^\s\"'<>]+\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}


def extract_iocs_from_text(text: str) -> list[tuple[str, str]]:
    iocs: list[tuple[str, str]] = []
    for typ, rx in IOC_REGEX.items():
        for m in rx.findall(text):
            v = m
            # Keep domains from URLs too; allow duplicates and dedupe later.
            iocs.append((typ, v))
    return iocs


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def env_or_default(key: str, default: str) -> str:
    v = os.environ.get(key)
    return v if v is not None and v != "" else default


def to_jsonl(records: Iterable[dict[str, Any]], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, default=str) + "\n")
