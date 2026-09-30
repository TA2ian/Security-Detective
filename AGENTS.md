# Security-Detective Agent Contract

## Mission

Security-Detective is an evidence-first defensive security assessment and hardening platform. It assesses only authorized targets and must preserve explicit authorization, scope, evidence integrity, and safe execution boundaries.

## Non-negotiable invariants

1. Never bypass authorization, scope, or execution policy.
2. Passive/read-only operations are the default.
3. State-changing and destructive operations remain disabled unless explicitly authorized by both Authorization and ExecutionPolicy.
4. Never declare a vulnerability confirmed without sufficient evidence.
5. Keep discovery, detection, validation, remediation, and verification as separate phases.
6. Keep severity, confidence, exploitability, impact, exposure, and asset criticality as separate signals.
7. Never fabricate, infer as fact, or silently modify evidence.
8. Scanner code is untrusted application code from the Core's perspective; it must not become the source of authorization truth.
9. Do not weaken security controls merely to make tests pass.
10. Do not modify main, merge PRs, or change deployment/production configuration unless explicitly requested.
11. Every security-sensitive change requires tests and a review of failure/rollback behavior.
12. Do not perform active testing against third-party systems without explicit authorization and an explicit scope.

## Architecture

Target -> Authorization -> Scope -> Execution Policy -> Assessment Engine -> Scanner/Collector -> Evidence -> Finding -> Risk -> Report -> Remediation -> Verification.

Core owns policy enforcement. Scanners must not implement their own authorization model as a replacement for Core.

## Development protocol

Before changing code:
- inspect the relevant implementation and tests;
- identify affected invariants and trust boundaries;
- make the smallest coherent change;
- add regression tests for the security property;
- run the relevant tests;
- run the full test suite before declaring completion;
- report anything that could not be verified.

When a test fails:
- determine whether the failure exposes a real defect;
- fix the defect rather than weakening the assertion;
- rerun affected tests and the full suite.

When a security boundary is ambiguous, fail closed and document the assumption.

## Git discipline

Work on the active feature branch. Keep commits focused. Never force-push or rewrite history unless explicitly requested.

## Testing

Use deterministic local fixtures and owned security-lab targets for active testing. Never use real credentials, production secrets, or uncontrolled third-party targets in tests.
