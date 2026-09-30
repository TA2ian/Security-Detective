# Security-Detective

Evidence-first security assessment and hardening platform for authorized security testing of websites, APIs, Telegram systems, source repositories, mobile applications, and infrastructure.

## Core principles

- Authorization and scope are enforced by Core, not by scanners.
- Passive/read-only assessment is the default.
- State-changing and destructive operations are disabled by default.
- Findings require evidence and use an explicit lifecycle.
- Severity, confidence, exploitability, impact, exposure, and asset criticality remain separate signals.
- AI may analyze and correlate evidence, but it must not invent evidence or bypass security policy.

## Current foundation

```text
Target
  -> Authorization
  -> Scope Guard
  -> Execution Policy
  -> Assessment Engine
  -> Scanner
  -> Evidence
  -> Finding
  -> Risk
  -> Verification
```

The current branch implements the Core domain contracts, authorization/scope policy, safe execution policy, finding lifecycle, bounded risk scoring, assessment orchestration, and automated tests.

All active security testing must be performed only against targets for which the operator has explicit authorization and within the defined scope.
