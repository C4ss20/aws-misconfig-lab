# AWS Misconfiguration Lab · Phase 1 (IAM Policy Review)

A **safe, offline** IAM policy analyzer for learning AWS least privilege, policy review, and misconfiguration triage. This is **Phase 1** of a cloud-security portfolio project, not a deployed AWS environment or a Prowler scan.

## Problem → approach → results

Excessively broad IAM permissions can lead to unnecessary attack surface. This starter examines **user-supplied IAM identity policy JSON** for potentially risky patterns and produces structured findings with practical review/remediation suggestions.

| Check | Finding | Classification |
| --- | --- | --- |
| IAM-001 | `Action: *` or `iam:*` and `Resource: *` | CRITICAL (heuristic) |
| IAM-002 | Service wildcard actions with `Resource: *` | HIGH |
| IAM-003 | Potential privilege management actions with `Resource: *` | HIGH |
| IAM-004 | `sts:AssumeRole` with any resource | MEDIUM |
| IAM-000 | `NotAction` / `NotResource` requires contextual analysis | REVIEW |

**Important:** Findings are **heuristic alerts, not proof of exploitable permissions**. Effective access depends on all policy types, resource controls, permission boundaries, SCPs, IAM conditions and trust relationships. Use AWS IAM Access Analyzer and proper test scopes to validate.

## Run locally

Python 3.10+ and standard library only. No AWS account, credentials, network or billed resources required.

```bash
python3 -m iam_audit.cli examples/overly-permissive-policy.json \
  --output reports/lab-policy-report.json
python3 -m iam_audit.cli examples/scoped-policy.json
python3 -m unittest discover -s tests -v
```

The first example intentionally triggers several findings. The second shows a basic, narrower identity policy with no findings under this limited check set.

## What is implemented

- Parse a local identity-based IAM policy JSON.
- Identify obvious action/resource wildcard and privilege-management patterns.
- Produce JSON including severity, rule, statement number and remediation guidance.
- Explicitly flag complex `NotAction` / `NotResource` semantics for manual review.
- Unit tests, a CI test workflow, synthetic policy examples.

## Roadmap — evidence first

1. **AWS sandbox:** Deploy a deliberately scoped test environment with a separate low-privilege identity and budget guardrails. Capture evidence in your own account.
2. **Prowler:** Run a read-only, authorized audit of that sandbox and export verified findings.
3. **Fix and retest:** Apply the least-privilege changes, compare before/after findings.
4. **Controls:** Map selected findings to AWS Well-Architected security pillars and documented controls.
5. **Automated checks:** Add robust IAM evaluation / Access Analyzer integration, with opt-in AWS credentials and CI protection.

No account has been provisioned, scanned or charged as part of this package; no screenshots or findings are invented. **Do not commit AWS credentials, resource IDs or sensitive configuration data.**
