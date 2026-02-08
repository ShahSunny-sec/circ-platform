# Cloud Incident Response & Event Correlation Platform
## MVP Specification & Detection Rule Book

---

> **Document Status:** Draft — ready for engineering sign-off  
> **Revision:** 1.0  
> **Classification:** Internal — Engineering

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Target Users](#2-target-users)
3. [Success Criteria](#3-success-criteria)
4. [Non-Goals (Explicit Descoping)](#4-non-goals)
5. [Architecture Overview](#5-architecture-overview)
6. [Canonical Schemas](#6-canonical-schemas)
   - 6.1 [Event Schema](#61-event-schema)
   - 6.2 [Alert Schema](#62-alert-schema)
   - 6.3 [Incident Schema](#63-incident-schema)
7. [Detection Rule Book](#7-detection-rule-book)
   - [Rule 01 — Suspicious IAM Role Assumption](#rule-01)
   - [Rule 02 — Brute-Force Login from Single Source](#rule-02)
   - [Rule 03 — Anomalous Data Exfiltration via VPC](#rule-03)
   - [Rule 04 — Unauthorized API Call from Unknown Region](#rule-04)
   - [Rule 05 — Security Group Wide-Open Ingress](#rule-05)
   - [Rule 06 — Privileged Action Without MFA](#rule-06)
   - [Rule 07 — DNS Tunnelling Indicator](#rule-07)
   - [Rule 08 — CloudTrail Logging Disabled](#rule-08)
8. [Prioritized Backlog](#8-prioritized-backlog)
9. [Appendices](#9-appendices)

---

## 1. Executive Summary

This platform ingests security telemetry from AWS CloudTrail and VPC Flow Logs, normalises it into a canonical event model, evaluates a library of Sigma-inspired detection rules in a local batch pipeline, and correlates individual alerts into coherent incidents by clustering on shared time windows, network entities, IOCs, and MITRE ATT&CK techniques.

The MVP targets a **single-tenant, file-based, offline-first** deployment. Everything runs locally: ingestion reads JSON/NDJSON files from disk, the rule engine and correlator execute in-process, and outputs are written as Parquet and JSON. A Streamlit dashboard surfaces incidents, alert timelines, and IOC graphs for analyst review.

The design deliberately keeps the surface area small. No streaming infrastructure, no external enrichment APIs, no agent deployment, and no multi-tenant isolation are in scope for v1. Those capabilities are all backlogged and architecturally reachable without re-platforming.

---

## 2. Target Users

| Persona | Interaction | Key Need |
|---|---|---|
| **Security Analyst (Primary)** | Daily, via Streamlit dashboard | Quickly triage correlated incidents; drill into raw events; see MITRE context |
| **SOC Lead** | Weekly review | Tune rule thresholds; export incident reports; assess detection coverage gaps |
| **Platform Engineer** | Occasional | Add new log sources; write or modify detection rules; maintain the pipeline |

---

## 3. Success Criteria

The MVP is considered successful when all of the following hold:

**Detection accuracy.** Each of the eight shipped rules produces zero false positives against the provided synthetic validation dataset and detects 100 % of the injected true-positive scenarios in the same dataset.

**Correlation fidelity.** Alerts that share at least one network entity (IP, hostname, IAM principal) *and* fall within the configured time window (default 15 minutes) are grouped into a single incident with confidence ≥ 0.9 (measured as Jaccard similarity of entity overlap across constituent alerts).

**Pipeline throughput.** The batch pipeline processes 50 000 raw events end-to-end (ingest → normalise → detect → correlate → write Parquet) in under 30 seconds on a single modern laptop core.

**Analyst workflow.** An analyst can open the Streamlit UI, filter incidents by severity and time range, click into any incident, inspect every constituent alert and its raw payload, and export the incident as JSON — all without leaving the browser tab.

**Observability.** Every pipeline stage emits structured log lines (source, stage, duration, record count). A run summary is written alongside every output batch.

---

## 4. Non-Goals

The following are explicitly out of scope for the MVP. Each is backlogged with a rationale note.

| Non-Goal | Why Descoped |
|---|---|
| Real-time / streaming ingestion (Kafka, Kinesis) | Adds operational complexity disproportionate to MVP value; batch proves the logic first |
| External threat-intel enrichment (VirusTotal, Shodan, etc.) | Introduces network dependency and rate-limit coupling; link-based enrichment only |
| Multi-tenant data isolation | Single analyst workflow is the target; RBAC is a P1 post-MVP item |
| Agent-based endpoint collection | Shifts the platform into EDR territory; out of the detection-and-correlation lane |
| Automated remediation / playbook execution | Analyst-in-the-loop is the safer default for an MVP |
| Cloud-native deployment (ECS, Lambda, k8s) | Adds infra toil before the product logic is validated |
| Persistent state / database | Parquet + JSON files are the state store; a DB is a scaling decision for later |

---

## 5. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Batch Pipeline                               │
│                                                                     │
│  ┌──────────┐   ┌─────────────┐   ┌──────────────┐   ┌───────────┐ │
│  │  Ingest  │──▶│  Normalise  │──▶│  Rule Engine │──▶│Correlator │ │
│  │ (JSON /  │   │  → RawEvent │   │  (Sigma-like)│   │           │ │
│  │  NDJSON) │   │  + IOC ext. │   │  → Alert[]   │   │→Incident[]│ │
│  └──────────┘   └─────────────┘   └──────────────┘   └─────┬─────┘ │
│                                                             │       │
│                                                             ▼       │
│                                                      ┌────────────┐ │
│                                                      │   Writer   │ │
│                                                      │ Parquet+JSON│ │
│                                                      └────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼  (reads output files)
                          ┌─────────────────────┐
                          │   Streamlit UI       │
                          │  • Incident list     │
                          │  • Alert timeline    │
                          │  • IOC / entity view │
                          │  • Raw event drill   │
                          └─────────────────────┘
```

### Stage Responsibilities

**Ingest** reads one or more JSON / NDJSON files from a configurable input directory. It performs no transformation; its sole job is to yield raw `dict` objects and tag each with the detected source schema (CloudTrail vs. VPC Flow Logs vs. generic).

**Normalise** maps each source-specific payload into the canonical `RawEvent` model. A pluggable adapter per source handles field-name translation. IOC extraction runs as a second pass over the serialised payload using a set of compiled regexes (IPv4, domain, SHA-256, CVE, URL). No external calls are made.

**Rule Engine** iterates the `RawEvent` stream and evaluates every loaded `DetectionRule`. Each rule is a list of field-match conditions combined with a configurable boolean logic operator (`AND` / `OR`). A match emits an `Alert`. Rules are loaded from YAML files in a `rules/` directory, making them editable without code changes.

**Correlator** receives the full `Alert` stream and groups alerts into `CorrelatedIncident` clusters. Clustering is driven by three independent signals, any one of which is sufficient to link two alerts:

1. **Time proximity** — both alerts fall within the correlation window (configurable, default 15 min).
2. **Shared entities** — at least one IP, hostname, or IAM principal appears in both alerts.
3. **Shared IOCs** — at least one extracted IOC (hash, domain, CVE, etc.) appears in both.

Alerts sharing a MITRE technique *and* a time window receive an additional confidence boost but do not link on technique alone.

**Writer** serialises the final `CorrelatedIncident` list to both Parquet (for analytics) and JSON (for portability and the UI). A `run_summary.json` sidecar is emitted alongside every batch.

### Data Flow Guarantees

- The pipeline is append-only at the output layer; each run writes to a new time-stamped directory.
- No record is silently dropped. Normalisation failures are captured in a `dead_letter.json` sidecar with the original payload and the parse error.
- Every stage is individually unit-testable via pure-function interfaces.

---

## 6. Canonical Schemas

### 6.1 Event Schema

The `RawEvent` is the normalised representation of every log line that enters the platform. All downstream stages consume this model exclusively.

```
RawEvent
├── event_id          : string (UUID, generated at ingest)
├── timestamp         : datetime (UTC, normalised from source)
├── source            : enum { cloudtrail, vpc_flow, firewall, auth, ids, generic }
├── severity          : enum { low, medium, high, critical }
├── iocs              : IOC[]
│   └── IOC
│       ├── type      : enum { ip, domain, sha256, md5, url, email, cve, user, host }
│       └── value     : string
├── tags              : string[]
├── source_ip         : string | null
├── dest_ip           : string | null
├── hostname          : string | null
├── username          : string | null
├── process_name      : string | null
├── action            : string | null    ← event type / API name / signature
└── raw               : object           ← original payload, verbatim
```

**Design rationale.** Flattening the most-correlated fields (`source_ip`, `dest_ip`, `hostname`, `username`) into top-level attributes avoids repeated JSON-path traversal in the rule engine and correlator hot loops. The `raw` dict preserves full fidelity for drill-down.

### 6.2 Alert Schema

An `Alert` is a (rule, event) pair: proof that a specific detection fired against a specific event.

```
Alert
├── alert_id          : string (UUID)
├── event_id          : string          ← FK → RawEvent.event_id
├── rule_id           : string          ← FK → DetectionRule.id
├── rule_name         : string
├── severity          : enum { low, medium, high, critical }
├── timestamp         : datetime        ← copied from the triggering event
├── iocs              : IOC[]           ← inherited from the triggering event
├── mitre             : MitreMapping[]  ← from the rule definition
│   └── MitreMapping
│       ├── technique_id   : string     ← e.g. "T1078"
│       ├── technique_name : string
│       └── tactic         : string     ← e.g. "initial_access"
├── tags              : string[]
└── raw_event         : object          ← snapshot of RawEvent.raw at alert time
```

### 6.3 Incident Schema

A `CorrelatedIncident` is the analyst-facing unit of work. It bundles related alerts and surfaces the shared context that made them linkable.

```
CorrelatedIncident
├── incident_id       : string (UUID)
├── created_at        : datetime (UTC)
├── severity          : enum            ← max(alert.severity) across constituents
├── alert_count       : integer
├── alerts            : Alert[]
├── shared_iocs       : IOC[]           ← intersection of IOCs across alerts
├── shared_entities   : string[]        ← IPs / hosts / users common to ≥ 2 alerts
├── mitre_techniques  : MitreMapping[]  ← union of techniques across alerts
├── time_window_start : datetime        ← min(alert.timestamp)
├── time_window_end   : datetime        ← max(alert.timestamp)
├── tags              : string[]        ← union of all constituent tags
└── summary           : string          ← auto-generated from shared context
```

**Severity escalation rule.** An incident's severity is the *maximum* severity of any constituent alert. If three or more alerts share the same entity, the incident severity is bumped up one tier (low→medium, medium→high, high→critical) regardless of individual alert severities. This prevents a swarm of low-confidence alerts from flying under the radar.

---

## 7. Detection Rule Book

Each rule below is specified in a source-of-truth format that maps directly to the YAML representation consumed by the rule engine. Fields are ordered to encourage copy-paste into the `rules/` directory.

---

### Rule 01 — Suspicious IAM Role Assumption {#rule-01}

| Field | Value |
|---|---|
| **ID** | `CT-IAM-001` |
| **Severity** | High |
| **Source** | CloudTrail |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | T1078 — Valid Accounts |

**Description.** Detects an `AssumeRole` API call where the target role name contains high-privilege indicators (`admin`, `root`, `poweruser`) and the call originates from an identity that is *not* a service-linked role or a known automation account.

**Required Fields.** `eventName`, `requestParameters.roleArn`, `userIdentity.type`, `userIdentity.userName`, `sourceIPAddress`.

**Pseudologic.**

```
eventName == "AssumeRole"
  AND requestParameters.roleArn CONTAINS ANY ["admin", "root", "poweruser"]  (case-insensitive)
  AND userIdentity.type NOT IN ["AWSService", "ServiceLinkedRole"]
  AND userIdentity.userName NOT STARTS_WITH "automation-"
```

**Containment Recommendations.**
Immediately revoke the assumed-role session via `aws sts revoke-session`. Audit the IAM policy attached to the source identity for privilege escalation paths. If the source IP is not on the organisation's known egress list, treat as a compromise indicator and escalate to Incident Response.

---

### Rule 02 — Brute-Force Login Attempt from Single Source {#rule-02}

| Field | Value |
|---|---|
| **ID** | `CT-AUTH-001` |
| **Severity** | Medium (escalates to High at ≥ 10 events in window) |
| **Source** | CloudTrail (`ConsoleLogin`) |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | T1110 — Brute Force |

**Description.** Fires on any single `ConsoleLogin` event where the response indicates authentication failure. The correlator is responsible for grouping repeated failures from the same `sourceIPAddress` into a high-confidence incident. The per-event rule severity is Medium; the incident-level escalation policy (see §6.3) handles promotion.

**Required Fields.** `eventName`, `responseElements.ConsoleLogin`, `sourceIPAddress`, `userIdentity.userName`.

**Pseudologic.**

```
eventName == "ConsoleLogin"
  AND responseElements.ConsoleLogin == "Failure"
```

**Containment Recommendations.**
If the correlator surfaces ≥ 5 failures from a single IP within the correlation window, block that IP at the VPC network ACL or WAF rule set. Notify the targeted IAM user via out-of-band channel. If any failure is followed by a *successful* login (even from a different IP), treat as a credential-stuffing success and force a password reset.

---

### Rule 03 — Anomalous Data Exfiltration via VPC Flow {#rule-03}

| Field | Value |
|---|---|
| **ID** | `VPC-NET-001` |
| **Severity** | High |
| **Source** | VPC Flow Logs |
| **MITRE Tactic** | Exfiltration |
| **MITRE Technique** | T1048 — Exfiltration Over Alternative Protocol |

**Description.** Detects an outbound TCP session where the destination port is outside the standard egress allowlist (443, 53, 123) and the byte count exceeds 10 MB (`bytes > 10485760`). This is a volume-and-direction heuristic; it catches data moved over non-standard ports but does not attempt protocol classification.

**Required Fields.** `direction`, `dstPort`, `bytes`, `dstAddr`, `srcAddr`, `action`.

**Pseudologic.**

```
direction == "egress"
  AND action == "ACCEPT"
  AND dstPort NOT IN [443, 53, 123, 22, 587, 993]
  AND bytes > 10485760
```

**Containment Recommendations.**
Immediately update the security group or NACL to deny traffic to the identified `dstAddr`. Capture the source instance's ENI for forensic snapshotting. Engage the network team to confirm whether the destination IP belongs to a known SaaS provider before escalating to external-threat status.

---

### Rule 04 — Unauthorized API Call from Unknown Region {#rule-04}

| Field | Value |
|---|---|
| **ID** | `CT-API-001` |
| **Severity** | Medium |
| **Source** | CloudTrail |
| **MITRE Tactic** | Discovery |
| **MITRE Technique** | T1538 — Cloud Service Dashboard |

**Description.** Fires when a `Describe*` or `List*` API call originates from an AWS region that is not in the organisation's approved region set. Region-restricted operations are a strong signal of reconnaissance by a compromised credential being used outside normal operational patterns.

**Required Fields.** `eventName`, `awsRegion`, `userIdentity.userName`, `sourceIPAddress`.

**Pseudologic.**

```
eventName STARTS_WITH ANY ["Describe", "List", "Get"]
  AND awsRegion NOT IN ["us-east-1", "us-west-2", "eu-west-1"]   ← org-specific allowlist
  AND userIdentity.userName IS NOT NULL
```

**Containment Recommendations.**
Flag the identity for enhanced monitoring. If the same identity has not been seen in that region in the preceding 30 days (requires historical baseline), escalate to High. No blocking action is warranted on first fire; this rule is designed to feed the correlator.

---

### Rule 05 — Security Group Wide-Open Ingress {#rule-05}

| Field | Value |
|---|---|
| **ID** | `CT-EC2-001` |
| **Severity** | High |
| **Source** | CloudTrail |
| **MITRE Tactic** | Defense Evasion |
| **MITRE Technique** | T1562.007 — Disable Cloud Security Controls |

**Description.** Triggers when an `AuthorizeSecurityGroupIngress` call is made with a CIDR of `0.0.0.0/0` (or `::/0` for IPv6). Opening ingress to the entire internet is almost never intentional in production and is a common post-compromise pivot-enablement technique.

**Required Fields.** `eventName`, `requestParameters.cidrIp`, `requestParameters.groupId`, `userIdentity.userName`.

**Pseudologic.**

```
eventName == "AuthorizeSecurityGroupIngress"
  AND (
        requestParameters.cidrIp == "0.0.0.0/0"
        OR requestParameters.cidrIpV6 == "::/0"
      )
```

**Containment Recommendations.**
Revert the security group rule immediately via `aws ec2 revoke-security-group-ingress`. Notify the identity that made the change. If the change was made programmatically (e.g., via a Lambda or CloudFormation stack), audit the automation pipeline for compromise. Consider enabling AWS Config rules to auto-remediate this condition.

---

### Rule 06 — Privileged Action Performed Without MFA {#rule-06}

| Field | Value |
|---|---|
| **ID** | `CT-IAM-002` |
| **Severity** | Critical |
| **Source** | CloudTrail |
| **MITRE Tactic** | Privilege Escalation |
| **MITRE Technique** | T1098 — Account Manipulation |

**Description.** Detects any IAM write action (`Create*`, `Delete*`, `Put*`, `Attach*`) performed by a user whose session context indicates MFA was *not* present. Privileged IAM mutations without MFA represent the single highest-risk pattern in AWS account compromise chains.

**Required Fields.** `eventName`, `additionalEventData.MFAUsed`, `userIdentity.type`, `userIdentity.userName`.

**Pseudologic.**

```
eventName STARTS_WITH ANY ["CreateUser", "DeleteUser", "PutUserPolicy",
                           "AttachUserPolicy", "CreateAccessKey",
                           "DeleteMFADevice", "PutRolePolicy", "AttachRolePolicy"]
  AND (
        additionalEventData.MFAUsed == "No"
        OR additionalEventData.MFAUsed IS NULL
      )
  AND userIdentity.type == "IAMUser"
```

**Containment Recommendations.**
This is a Critical-severity rule — page the on-call security engineer immediately. Suspend the IAM user's access keys and console password. Audit every resource created or modified by the user in the last 24 hours. If any `CreateAccessKey` events are present, treat all keys created by that user as compromised and rotate them.

---

### Rule 07 — DNS Tunnelling Indicator {#rule-07}

| Field | Value |
|---|---|
| **ID** | `VPC-DNS-001` |
| **Severity** | High |
| **Source** | VPC Flow Logs (port 53 sessions) |
| **MITRE Tactic** | Command and Control |
| **MITRE Technique** | T1071.004 — DNS |

**Description.** Heuristic for DNS tunnelling: outbound UDP traffic on port 53 where the packet size exceeds the typical DNS query ceiling (512 bytes without EDNS, conservatively flagged at 256 bytes for high-sensitivity) and the destination is *not* a known-good resolver (e.g., Route 53 resolver `169.254.169.253`, or org-approved public resolvers).

**Required Fields.** `direction`, `dstPort`, `bytes`, `dstAddr`, `srcAddr`, `protocol`.

**Pseudologic.**

```
direction == "egress"
  AND dstPort == 53
  AND protocol == "UDP"
  AND bytes > 262144                     ← 256 KB aggregate in the flow window
  AND dstAddr NOT IN ["169.254.169.253", "8.8.8.8", "1.1.1.1"]   ← known-good resolvers
```

**Containment Recommendations.**
Block outbound port 53 from the source instance to all destinations except approved resolvers at the security-group level. Capture DNS query logs from Route 53 or VPC DNS for the source instance's private hosted zone. If query logs show a high volume of TXT or NULL record lookups to a single external domain, escalate to a C2 incident and engage threat intelligence for domain analysis.

---

### Rule 08 — CloudTrail Logging Disabled {#rule-08}

| Field | Value |
|---|---|
| **ID** | `CT-AUDIT-001` |
| **Severity** | Critical |
| **Source** | CloudTrail |
| **MITRE Tactic** | Defense Evasion |
| **MITRE Technique** | T1562.002 — Disable Cloud Security Controls |

**Description.** Fires whenever a `StopLogging` or `DeleteTrail` API call is recorded. These are the two primitives an attacker uses to blind the organisation's audit trail. Because the very act of being logged implies the trail was still active *at the moment of the call*, this rule will fire even if the trail is subsequently silenced — but only for that one event. Continuous monitoring of trail status via AWS Config is a recommended defence-in-depth complement.

**Required Fields.** `eventName`, `requestParameters.Name` (or `trailARN`), `userIdentity.userName`, `sourceIPAddress`.

**Pseudologic.**

```
eventName IN ["StopLogging", "DeleteTrail"]
```

**Containment Recommendations.**
This is a Critical-severity rule — treat as a confirmed compromise indicator until proven otherwise. Re-enable the trail immediately via `aws cloudtrail start-logging`. Identify who made the call and suspend their credentials. Audit the full CloudTrail history for the 24 hours *before* the stop event to understand what activity the attacker may have been trying to hide. Notify the CISO.

---

## 8. Prioritized Backlog

Items are ordered by strategic value to the platform. Each entry includes a rationale for its current priority tier.

### Tier 1 — Post-MVP (Next Sprint)

| # | Item | Rationale |
|---|---|---|
| B-01 | **RBAC & multi-user access control** | Required the moment a second analyst touches the platform; security-critical for the tool itself |
| B-02 | **Historical baseline store** | Several rules (02, 04) would benefit from "have we seen this entity do X before?" queries; enables anomaly-based detection |
| B-03 | **AWS Config integration adapter** | Surfaces configuration drift as events; fills a detection gap between CloudTrail API calls |
| B-04 | **Parquet query layer (DuckDB)** | Enables ad-hoc analyst queries over historical output without loading everything into memory |

### Tier 2 — Near-Term (Month 2)

| # | Item | Rationale |
|---|---|---|
| B-05 | **Link-based IOC enrichment** | Attach threat-intel context (reputation, ASN, registration date) to extracted IOCs using bundled or cached reference data; no live API calls |
| B-06 | **Streaming ingestion adapter (Kinesis / SQS)** | Moves the platform from batch-per-hour to near-real-time; critical for SLAs once the product is operationally adopted |
| B-07 | **Rule performance benchmarking harness** | As the rule library grows, we need automated regression tests that catch O(n²) correlation bugs before they hit production |
| B-08 | **Incident export to PDF / DOCX** | Analyst-facing deliverable for executive escalation and post-incident review |

### Tier 3 — Future (Quarter 2)

| # | Item | Rationale |
|---|---|---|
| B-09 | **Automated containment playbooks** | Reduces MTTR; but requires careful guardrails (dry-run mode, approval gates) before enabling |
| B-10 | **Cloud-native deployment (ECS + Aurora)** | Operationalises the platform for production; deferred until the data model is stable |
| B-11 | **Multi-cloud adapter layer (GCP, Azure)** | Expands the addressable threat surface; architecturally clean because normalisation already abstracts the source |
| B-12 | **ML-based anomaly detection** | Complements rule-based detection for novel attack patterns; requires labelled data first |
| B-13 | **Threat-hunting workbench** | Interactive query interface for analysts to run custom correlations; builds on the DuckDB layer (B-04) |

---

## 9. Appendices

### A. MITRE ATT&CK Technique Index

Quick reference for all techniques referenced in this document.

| Technique ID | Name | Tactic | Rules Using It |
|---|---|---|---|
| T1078 | Valid Accounts | Initial Access | CT-IAM-001 |
| T1110 | Brute Force | Initial Access | CT-AUTH-001 |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | VPC-NET-001 |
| T1538 | Cloud Service Dashboard | Discovery | CT-API-001 |
| T1562.007 | Disable Cloud Security Controls | Defense Evasion | CT-EC2-001 |
| T1098 | Account Manipulation | Privilege Escalation | CT-IAM-002 |
| T1071.004 | DNS | Command and Control | VPC-DNS-001 |
| T1562.002 | Disable Cloud Security Controls | Defense Evasion | CT-AUDIT-001 |

### B. Correlation Window Configuration

| Parameter | Default | Notes |
|---|---|---|
| `CORRELATION_WINDOW_MINUTES` | 15 | Alerts outside this window are never linked |
| `MIN_SHARED_ENTITIES` | 1 | Minimum shared entities to trigger a link |
| `SEVERITY_ESCALATION_THRESHOLD` | 3 | Number of alerts sharing an entity before severity bump |
| `MAX_ALERTS_PER_INCIDENT` | 500 | Hard cap; prevents runaway clustering on noisy rules |

### C. Output Directory Layout

```
output/
└── 2024-01-15T14-30-00Z/
    ├── events.parquet          ← all normalised RawEvents
    ├── alerts.parquet          ← all fired Alerts
    ├── incidents.parquet       ← all CorrelatedIncidents (denormalised for analytics)
    ├── incidents.json          ← same data, nested JSON (used by Streamlit)
    ├── dead_letter.json        ← records that failed normalisation
    └── run_summary.json        ← stage timings, counts, error tallies
```

### D. Rule YAML Schema Reference

All detection rules are stored as YAML files in the `rules/` directory. The engine loads every `.yaml` file in that directory at startup.

```yaml
id: CT-IAM-001
name: Suspicious IAM Role Assumption
description: >
  Detects AssumeRole calls targeting high-privilege roles from
  non-service identities.
severity: high
logic: AND                          # AND | OR — combines conditions
mitre:
  - technique_id: T1078
    technique_name: Valid Accounts
    tactic: initial_access
conditions:
  - field: eventName
    operator: eq
    value: AssumeRole
  - field: requestParameters.roleArn
    operator: contains
    value: admin
  - field: userIdentity.type
    operator: not_in
    value: ["AWSService", "ServiceLinkedRole"]
tags:
  - iam
  - privilege
  - initial_access
```

**Supported operators:** `eq`, `neq`, `contains`, `startswith`, `endswith`, `in`, `not_in`, `exists`, `gt`, `lt`, `gte`, `lte`, `regex`.

**Dotted field paths** are resolved against the `raw` payload dict. Top-level normalised fields (`source_ip`, `dest_ip`, `hostname`, `username`, `action`) are also addressable directly.
