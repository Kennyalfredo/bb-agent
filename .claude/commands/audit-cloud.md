---
description: Authenticated AWS cloud-configuration audit for a contracted engagement. Confirms identity + read-only role, runs the posture suite (Prowler/ScoutSuite/cloudfox/cloudsplaining/pmapper + credential report + Access Analyzer + GuardDuty), applies false-positive triage (policy conditions, SG→live-instance, cross-account attribution), and consolidates confirmed findings. Read-only, proof-ceiling. Never writes/exploits/auto-submits.
argument-hint: <slug> <aws-cli-profile>   (e.g. acme acme-audit)
allowed-tools: Agent, Bash, Read, Write, AskUserQuestion
---

You are running an **authenticated AWS cloud-configuration audit** (contracted-pentest tier).
Arguments: $ARGUMENTS  (expected: `<slug> <aws-cli-profile>`)

This is credential-gated client work: the operator provisioned a read-only engagement role and configured an AWS CLI profile. Distinct from bug-bounty passive recon and the web-vuln tier. Authorization = the provisioned role + profile. Deliverable = SYSCLOUDSEC Typst via `/informe <slug> tecnico` (Eje 3) — this command does NOT draft it.

## Orchestration

### 0. Preflight (do this inline, before delegating)
- Parse `<slug>` + `<profile>`. If `<profile>` missing, ask the operator to configure one (`! aws configure --profile <name>` so secrets never transit the chat) and stop.
- `aws sts get-caller-identity --profile <profile>` — confirm it is live and report Account + role ARN back to the operator. On `ExpiredToken`, ask for a fresh SSO token and stop.
- Confirm the role is read-only (`SecurityAudit`/`IAMReadOnlyAccess` or narrower). If it carries write/admin, warn the operator and confirm scope before proceeding (this tier is read-only by design).

### 1. Synthesize the engagement scope JSON
Write `memory/programs/<slug>.json` (if absent) with `engagement_type:"cloud_audit"`, `program.platform:"direct"`, the AWS account id, `rules`: `cloud_readonly:true`, `writes_allowed:false`, `exploitation_allowed:false`, `proof_ceiling:true`, `credential_validation_allowed:false`, plus a `notes` line recording the account + role + date. Confirm the slug back to the operator.

### 2. Delegate to `cloud-auditor`
Call the `cloud-auditor` subagent with `<slug> <profile>`. It runs the read-only suite (Prowler + ScoutSuite + cloudfox + cloudsplaining + pmapper region-restricted + IAM credential report + IAM Access Analyzer + GuardDuty), grabs token-cheap data first, launches the heavy tools in the background, then applies the false-positive triage per `feedback_cloud_scanner_fp_triage.md` (policy-condition awareness, SG→live-instance attachment, cross-account attribution, RDS caveat, systematic secrets sweep) and writes `out/<slug>/cloud/<ts>/FINDINGS.md`.

Remind it (hard rules): read-only only; proof ceiling (no port-scan/GetObject/secret-value reads/AssumeRole); pause + request refresh on `ExpiredToken`; never ship a raw scanner FAIL without triage; document FP counts killed; never auto-submit or draft the client report.

### 3. Summarize to the operator
Relay: account + role; per-severity CONFIRMED counts; the headline confirmed findings (with concrete resource names); the false-positive counts killed by triage (so the value of verification is explicit); any steps left incomplete (e.g. pmapper if the token expired mid-run, or "no Access Analyzer enabled"); the FINDINGS.md path. End by pointing to **`/informe <slug> tecnico`** for the Typst deliverable, and note nothing was written/exploited/submitted.

## Guardrails (state these hold)
- Read-only, proof ceiling. No writes, privesc execution, persistence, snapshot-share, port scans, bucket-object reads, or secret-value reads.
- Credentials stay in the AWS CLI profile; never echoed, never committed. SSO tokens expire ~hourly — refresh cleanly, never proceed on a dead token.
- Every reported finding passes the false-positive triage; raw ScoutSuite/Prowler FAILs are not findings until verified.
- Multi-account note: if the account is a child of an AWS Org, only the accounts you hold creds for are in scope — flag other siblings/SCPs as an untested gap, don't assume.
