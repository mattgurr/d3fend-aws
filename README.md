# D3FEND-AWS

A structured dataset mapping [AWS Threat Technique Catalog](https://aws-samples.github.io/threat-technique-catalog-for-aws/matrix.html) attack techniques to defensive countermeasures modeled on the [MITRE D3FEND](https://d3fend.mitre.org/) framework — scoped entirely for AWS-native services.

## What This Is

- **~48 AWS-specific attack techniques** from the AWS TTC, organized by ATT&CK tactic
- **Defensive technique mappings** across three D3FEND tactics: **Detect**, **Harden**, **Evict**
- **YAML data files** with JSON Schema validation — one file per defensive technique
- **AWS-native only** — every defense references AWS services, not third-party tooling

## Quick Start

```
data/
  detect/    # Detection techniques (CloudTrail, GuardDuty, Security Hub, ...)
  harden/    # Hardening techniques (SCPs, IAM policies, Config Rules, ...)
  evict/     # Eviction techniques (credential revocation, instance isolation, ...)
catalog/
  aws-ttc-attacks.yaml   # Normalized attack technique catalog
schema/
  technique.schema.json  # JSON Schema for technique files
```

### Validate

```bash
pip install pyyaml jsonschema
python scripts/validate.py
```

## Technique Format

Each defensive technique is a YAML file:

```yaml
id: D3FA-DT-0001
name: CloudTrail Management Event Analysis
tactic: detect
category: Platform Monitoring
description: >
  Analyze CloudTrail management events to detect unauthorized API
  activity indicating credential abuse or privilege escalation.
aws_services:
  - AWS CloudTrail
  - Amazon CloudWatch Logs
counters:
  - T1078.A001
  - T1078.A002
d3fend_ref: d3f:PlatformMonitoring
attack_tactics:
  - TA0005
```

## References

- [MITRE D3FEND](https://d3fend.mitre.org/)
- [AWS Threat Technique Catalog](https://aws-samples.github.io/threat-technique-catalog-for-aws/matrix.html)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [STEERING.md](STEERING.md) — project steering document

## License

MIT
