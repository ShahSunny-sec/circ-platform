from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from datetime import timedelta

from .models import IOC, Alert, Incident, MitreMapping, Severity, bump_severity
from .utils import utcnow


class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            self.parent[ra] = rb
        elif self.rank[ra] > self.rank[rb]:
            self.parent[rb] = ra
        else:
            self.parent[rb] = ra
            self.rank[ra] += 1


def severity_max(sevs: list[Severity]) -> Severity:
    order = {Severity.low: 0, Severity.medium: 1, Severity.high: 2, Severity.critical: 3}
    return max(sevs, key=lambda s: order[s])


def correlate_alerts(
    alerts: list[Alert],
    correlation_window_minutes: int,
    min_shared_entities: int,
    max_alerts_per_incident: int,
    severity_escalation_threshold: int,
) -> list[Incident]:
    if not alerts:
        return []

    # Sort by time
    alerts_sorted = sorted(alerts, key=lambda a: a.timestamp)
    n = len(alerts_sorted)
    uf = UnionFind(n)

    window = timedelta(minutes=correlation_window_minutes)

    # Sliding window comparisons (batch MVP; safe for moderate n)
    j = 0
    for i in range(n):
        while alerts_sorted[i].timestamp - alerts_sorted[j].timestamp > window:
            j += 1
        ai = alerts_sorted[i]
        ents_i = set(ai.entities)
        iocs_i = {(ioc.type, ioc.value) for ioc in ai.iocs}

        for k in range(j, i):
            ak = alerts_sorted[k]

            # time proximity already satisfied by window bounds
            shared_entities = len(ents_i.intersection(ak.entities))
            shared_iocs = len(iocs_i.intersection({(x.type, x.value) for x in ak.iocs}))

            # Link if any of: shared entities threshold OR shared IOCs OR (mitre overlap + time)
            mitre_i = {(m.technique_id, m.tactic) for m in ai.mitre}
            mitre_k = {(m.technique_id, m.tactic) for m in ak.mitre}
            mitre_overlap = len(mitre_i.intersection(mitre_k)) > 0

            if shared_entities >= min_shared_entities or shared_iocs > 0 or mitre_overlap:
                uf.union(i, k)

    clusters: dict[int, list[Alert]] = defaultdict(list)
    for idx, a in enumerate(alerts_sorted):
        clusters[uf.find(idx)].append(a)

    incidents: list[Incident] = []
    for _, cluster_alerts in clusters.items():
        if len(cluster_alerts) > max_alerts_per_incident:
            cluster_alerts = cluster_alerts[:max_alerts_per_incident]

        # Compute shared entities (appear in >=2 alerts)
        all_entities = [e for a in cluster_alerts for e in a.entities]
        entity_counts = Counter(all_entities)
        shared_entities = sorted([e for e, c in entity_counts.items() if c >= 2])

        # Shared IOCs = intersection across all alerts (strong commonality)
        ioc_sets = []
        for a in cluster_alerts:
            ioc_sets.append({(x.type, x.value) for x in a.iocs})
        shared_ioc_pairs = set.intersection(*ioc_sets) if ioc_sets else set()
        shared_iocs = [IOC(type=t, value=v) for (t, v) in sorted(shared_ioc_pairs)]

        # MITRE union
        mitre_map: dict[tuple[str, str, str], MitreMapping] = {}
        for a in cluster_alerts:
            for m in a.mitre:
                mitre_map[(m.technique_id, m.technique_name, m.tactic)] = m
        mitre_union = list(mitre_map.values())

        t0 = min(a.timestamp for a in cluster_alerts)
        t1 = max(a.timestamp for a in cluster_alerts)

        sev = severity_max([a.severity for a in cluster_alerts])

        # Severity escalation policy from spec: bump if >=3 alerts share same entity :contentReference[oaicite:6]{index=6}
        if shared_entities and max(entity_counts.values()) >= severity_escalation_threshold:
            sev = bump_severity(sev)

        # Recommendations: union of rule tags -> simple playbook templates
        recs = build_recommendations(cluster_alerts)

        summary = build_summary(cluster_alerts, shared_entities, shared_iocs, mitre_union)

        incidents.append(
            Incident(
                incident_id=str(uuid.uuid4()),
                created_at=utcnow(),
                severity=sev,
                alert_count=len(cluster_alerts),
                time_window_start=t0,
                time_window_end=t1,
                alerts=sorted(cluster_alerts, key=lambda a: a.timestamp),
                shared_entities=shared_entities,
                shared_iocs=shared_iocs,
                mitre_techniques=mitre_union,
                tags=sorted(set(t for a in cluster_alerts for t in a.tags)),
                summary=summary,
                rationale={
                    "correlation_window_minutes": correlation_window_minutes,
                    "shared_entities_count": len(shared_entities),
                    "shared_iocs_count": len(shared_iocs),
                    "cluster_size": len(cluster_alerts),
                },
                recommendations=recs,
            )
        )

    # Order incidents by severity then recency
    order = {Severity.low: 0, Severity.medium: 1, Severity.high: 2, Severity.critical: 3}
    incidents.sort(key=lambda inc: (order[inc.severity], inc.time_window_end), reverse=True)
    return incidents


def build_summary(
    alerts: list[Alert],
    shared_entities: list[str],
    shared_iocs: list[IOC],
    mitre: list[MitreMapping],
) -> str:
    top_rule = Counter([a.rule_id for a in alerts]).most_common(1)[0][0]
    ent = (
        shared_entities[0]
        if shared_entities
        else (alerts[0].entities[0] if alerts[0].entities else "unknown")
    )
    mit = mitre[0].technique_id if mitre else "N/A"
    ioc = shared_iocs[0].value if shared_iocs else "none"
    return f"Incident clustered around {ent}; top signal {top_rule}; MITRE {mit}; shared IOC {ioc}."


def build_recommendations(alerts: list[Alert]) -> list[str]:
    rule_ids = {a.rule_id for a in alerts}
    recs: list[str] = []

    # Very small MVP playbook mapping
    if "CT-AUDIT-001" in rule_ids:
        recs += [
            "Re-enable CloudTrail logging immediately; preserve evidence of who stopped/deleted trails.",
            "Suspend or rotate credentials for the actor identity; audit 24h of activity before the stop/delete event.",
        ]
    if "CT-IAM-001" in rule_ids:
        recs += [
            "Revoke assumed-role sessions; review IAM policies for privilege escalation and suspicious role chaining.",
            "Validate source IP against known egress; if unknown, treat as likely compromise.",
        ]
    if "CT-AUTH-001" in rule_ids:
        recs += [
            "Block the offending source IP at WAF/NACL if repeated failures occur; notify targeted users out-of-band.",
            "Check for any subsequent successful login; if so, force password reset and rotate access keys.",
        ]
    if "VPC-NET-001" in rule_ids:
        recs += [
            "Deny traffic to the destination IP/port; snapshot the source instance/ENI for forensics.",
            "Validate destination ownership (known SaaS vs unknown) before escalation; inspect egress logs for volume patterns.",
        ]

    # Deduplicate while preserving order
    seen = set()
    out = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out
