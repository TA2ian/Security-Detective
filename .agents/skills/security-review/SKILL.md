---
name: security-review
description: Performs a rigorous Security-Detective security review of code changes, trust boundaries, authorization, scope, evidence, lifecycle, and tests.
---

# Security Review Skill

## Use when

Use for security-sensitive changes, Core changes, scanner changes, policy changes, authentication/authorization work, evidence handling, or before a release/merge.

## Procedure

1. Inspect the changed files and their tests.
2. Map each change to its trust boundary.
3. Check authorization and capability intersection.
4. Check scope normalization and deny precedence.
5. Check target/assessment/evidence ownership.
6. Check lifecycle transitions and failure paths.
7. Check deduplication and evidence preservation.
8. Check secret handling and logging/reporting exposure.
9. Check input validation and malformed/untrusted data behavior.
10. Add regression tests for every discovered security defect.
11. Run focused tests, then the full suite.
12. Report verified results separately from assumptions.

## Review standard

Prefer fail-closed behavior. Do not accept "works in the happy path" as sufficient evidence for a security boundary.
