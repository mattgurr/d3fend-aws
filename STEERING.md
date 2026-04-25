# D3FEND-AWS — Steering Document

## 1. Problem Statement

Cloud security teams operating in AWS lack a structured, machine-readable mapping between known AWS-specific attack techniques and the defensive countermeasures available to them through native AWS services. MITRE D3FEND provides a rich defensive ontology but is platform-agnostic. The AWS Threat Technique Catalog (TTC) enumerates AWS-specific attacks but does not prescribe defenses. This project bridges that gap.

## 2. Project Vision

D3FEND-AWS is a curated, open-source dataset that maps every attack technique in the AWS Threat Technique Catalog to specific defensive techniques modeled on the MITRE D3FEND framework — scoped entirely for AWS.

The dataset is the product. It should be consumable by security engineers writing detections, security architects assessing coverage gaps, and tooling that automates either.

## 3. Scope

### In Scope

- **Attack surface:** All techniques from the [AWS Threat Technique Catalog](https://aws-samples.github.io/threat-technique-catalog-for-aws/matrix.html), organized by ATT&CK tactic.
- **Defensive tactics (D3FEND):** Three tactics, selected for immediate operational value:
  - **Detect** — Identifying threats using AWS-native signals (CloudTrail, GuardDuty, Security Hub, VPC Flow Logs, etc.)
  - **Harden** — Preventive controls via AWS services and configuration (SCPs, IAM policies, Security Groups, Config Rules, etc.)
  - **Evict** — Incident response actions to contain and remove threats (credential revocation, instance isolation, account lockdown, etc.)
- **Detail level:** Mapping-only. Each defensive technique entry describes *what* the defense is, *which AWS services* are involved, and *which attack techniques it counters*. No inline runbooks, CLI commands, or IaC snippets in v1.

### Out of Scope (v1)

- D3FEND tactics: Model, Isolate, Deceive, Restore (candidates for future phases).
- Third-party tooling (Datadog, Splunk, Wiz, etc.) — AWS-native services only.
- Runbook-level implementation detail (future enhancement).
- Risk scoring or prioritization frameworks.

## 4. Architecture

### 4.1 Data Model

Each defensive technique is a YAML file containing:

```yaml
id: D3FA-DT-0001                    # Project-specific ID (D3FEND-AWS)
name: CloudTrail Log Analysis        # Human-readable name
tactic: detect                       # detect | harden | evict
category: Platform Monitoring        # D3FEND-aligned sub-category
description: >
  Monitor CloudTrail management and data events for indicators
  of credential abuse, privilege escalation, or defense evasion.

aws_services:
  - AWS CloudTrail
  - Amazon CloudWatch Logs

counters:                            # AWS TTC technique IDs this defends against
  - T1078.A001                       # Valid Accounts: IAM Users
  - T1078.A002                       # Valid Accounts: Account Root User
  - T1562.008                        # Disable Cloud Logs

d3fend_ref: d3f:PlatformMonitoring   # Canonical D3FEND technique reference
attack_refs:                         # ATT&CK tactic context
  - TA0005                           # Defense Evasion
  - TA0006                           # Credential Access
```

### 4.2 Directory Structure

```
d3fend-aws/
├── STEERING.md                      # This document
├── README.md                        # Project overview and usage
├── LICENSE
├── schema/
│   └── technique.schema.json        # JSON Schema for technique YAML files
├── data/
│   ├── detect/                      # Defensive techniques — Detect tactic
│   │   ├── cloudtrail-log-analysis.yaml
│   │   ├── guardduty-threat-detection.yaml
│   │   └── ...
│   ├── harden/                      # Defensive techniques — Harden tactic
│   │   ├── scp-preventive-controls.yaml
│   │   ├── iam-least-privilege.yaml
│   │   └── ...
│   └── evict/                       # Defensive techniques — Evict tactic
│       ├── credential-revocation.yaml
│       ├── instance-isolation.yaml
│       └── ...
├── catalog/
│   └── aws-ttc-attacks.yaml         # Normalized list of AWS TTC attack techniques
├── scripts/
│   └── validate.py                  # Schema validation script
└── .github/
    └── workflows/
        └── validate.yml             # CI pipeline — schema validation on PR
```

### 4.3 Naming Conventions

- **Technique IDs:** `D3FA-{TACTIC}-{NNNN}` where tactic is `DT` (detect), `HD` (harden), `EV` (evict).
- **File names:** Kebab-case derived from technique name (e.g., `cloudtrail-log-analysis.yaml`).
- **AWS TTC references:** Use the original TTC IDs verbatim (e.g., `T1562.008`, `T1496.A007`).

### 4.4 Schema Validation

A JSON Schema (`schema/technique.schema.json`) defines required fields, allowed values, and format constraints for technique YAML files. Validation runs:

- Locally via `python scripts/validate.py`
- In CI via GitHub Actions on every push and pull request

## 5. AWS TTC Attack Techniques (Input Catalog)

The following ATT&CK tactics and AWS-specific techniques form the attack surface this project defends against:

| ATT&CK Tactic | Technique Count | Examples |
|---|---|---|
| Resource Development (TA0042) | 1 | Acquire Infrastructure: Domains |
| Initial Access (TA0001) | 3 | EC2 App Compromise, Overly Permissive SGs, Role Assumption |
| Execution (TA0002) | 3 | Cloud API, Lambda Invocation, Malicious Packages |
| Persistence (TA0003) | 6 | Additional Cloud Credentials/Roles, Cognito Token Abuse, Trust Modification |
| Privilege Escalation (TA0004) | 2 | Additional Cloud Credentials/Roles |
| Defense Evasion (TA0005) | 6 | Delete IAM Entities, Valid Accounts, Disable GuardDuty/Logs/Firewall |
| Credential Access (TA0006) | 2 | Credentials in Files, Instance Metadata API |
| Discovery (TA0007) | 4 | Cloud Account/DB/Storage Discovery, Service Dashboard |
| Lateral Movement (TA0008) | 1 | Role Assumption and Federated Access |
| Collection (TA0009) | 3 | API Gateway Abuse, RDS Manipulation, S3 Object Collection |
| Impact (TA0040) | 17 | Data Destruction, Ransomware Encryption, Resource Hijacking, Subdomain Takeover |

**Total: ~48 attack techniques** across 11 ATT&CK tactics.

## 6. Defensive Technique Categories (D3FEND-Aligned)

### Detect
| Category | AWS Focus |
|---|---|
| Platform Monitoring | CloudTrail, Config, CloudWatch, Access Analyzer |
| Network Traffic Analysis | VPC Flow Logs, DNS logs, Traffic Mirroring |
| Threat Detection | GuardDuty, Security Hub, Macie |
| User Behavior Analysis | CloudTrail user activity, IAM Access Analyzer |
| File/Object Analysis | S3 object scanning, Macie sensitive data discovery |

### Harden
| Category | AWS Focus |
|---|---|
| Credential Hardening | IAM password policies, key rotation, MFA enforcement |
| Access Control | SCPs, RCPs, IAM policies, resource policies, least privilege |
| Platform Hardening | Security Groups, NACLs, S3 Block Public Access, EBS encryption |
| Configuration Management | AWS Config Rules, conformance packs, guardrails |

### Evict
| Category | AWS Focus |
|---|---|
| Credential Eviction | IAM key deactivation, session revocation, password reset |
| Resource Eviction | Instance termination, security group lockdown, snapshot isolation |
| Account Eviction | Account suspension, root credential rotation, Organization removal |

## 7. Success Criteria

1. **Coverage:** Every AWS TTC attack technique has at least one defensive technique mapped to it across detect, harden, or evict.
2. **Validity:** All YAML files pass schema validation in CI.
3. **Usability:** A security architect can look up any AWS TTC attack ID and immediately find the relevant AWS-native defenses.
4. **Extensibility:** Adding a new tactic (e.g., Isolate) or new attack techniques requires only adding YAML files — no structural changes.

## 8. Milestones

| Phase | Deliverable |
|---|---|
| **P0 — Foundation** | Steering doc, repo structure, JSON Schema, CI validation pipeline, attack catalog YAML |
| **P1 — Detect** | Defensive technique YAML files for all Detect-category mappings |
| **P2 — Harden** | Defensive technique YAML files for all Harden-category mappings |
| **P3 — Evict** | Defensive technique YAML files for all Evict-category mappings |
| **P4 — Coverage audit** | Verify every AWS TTC technique has ≥1 defense. Fill gaps. |
| **Future** | Additional tactics (Model, Isolate, Deceive, Restore), runbook detail, static site generator, API |

## 9. Conventions

- **One file per defensive technique.** Keep techniques atomic — one YAML file describes one defense.
- **Many-to-many mappings.** One defense can counter multiple attacks; one attack can be countered by multiple defenses. The `counters` field in each technique handles this.
- **AWS-native only.** All services referenced must be AWS-native (no third-party). This keeps the project opinionated and focused.
- **IDs are stable.** Once assigned, a technique ID (`D3FA-*`) does not change. Deprecated techniques are marked, not deleted.
- **D3FEND alignment, not duplication.** Technique categories align to D3FEND's taxonomy, but names and descriptions are written for AWS context. The `d3fend_ref` field links back to the canonical D3FEND technique.

## 10. References

- [MITRE D3FEND](https://d3fend.mitre.org/) — Defensive technique knowledge graph
- [AWS Threat Technique Catalog](https://aws-samples.github.io/threat-technique-catalog-for-aws/matrix.html) — AWS-specific attack techniques
- [MITRE ATT&CK Cloud](https://attack.mitre.org/matrices/enterprise/cloud/) — Cloud ATT&CK matrix
- [D3FEND GitHub](https://github.com/d3fend/d3fend-ontology) — D3FEND ontology source
