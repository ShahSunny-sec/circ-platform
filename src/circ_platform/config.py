from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .utils import env_or_default


@dataclass(frozen=True)
class AppConfig:
    config_path: Path

    name: str
    timezone: str

    input_dir: Path
    rules_dir: Path
    output_root: Path

    correlation_window_minutes: int
    min_shared_entities: int
    max_alerts_per_incident: int
    severity_escalation_threshold: int

    approved_regions: list[str]

    abuseipdb_base: str
    virustotal_ip_base: str
    virustotal_domain_base: str
    virustotal_hash_base: str


def load_config() -> AppConfig:
    config_path = Path(env_or_default("CIRC_CONFIG_PATH", "config/config.yaml"))
    raw: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    return AppConfig(
        config_path=config_path,
        name=str(raw["app"]["name"]),
        timezone=str(raw["app"]["timezone"]),
        input_dir=Path(raw["paths"]["input_dir"]),
        rules_dir=Path(raw["paths"]["rules_dir"]),
        output_root=Path(raw["paths"]["output_root"]),
        correlation_window_minutes=int(raw["pipeline"]["correlation_window_minutes"]),
        min_shared_entities=int(raw["pipeline"]["min_shared_entities"]),
        max_alerts_per_incident=int(raw["pipeline"]["max_alerts_per_incident"]),
        severity_escalation_threshold=int(raw["pipeline"]["severity_escalation_threshold"]),
        approved_regions=list(raw["org"]["approved_regions"]),
        abuseipdb_base=str(raw["enrichment"]["abuseipdb_base"]),
        virustotal_ip_base=str(raw["enrichment"]["virustotal_ip_base"]),
        virustotal_domain_base=str(raw["enrichment"]["virustotal_domain_base"]),
        virustotal_hash_base=str(raw["enrichment"]["virustotal_hash_base"]),
    )
