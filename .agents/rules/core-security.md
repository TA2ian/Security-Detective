---
trigger: glob
globs: "security_detective/core/**/*.py, tests/**/*.py"
description: "Core security invariants, authorization boundaries, evidence integrity, and lifecycle rules."
---

# Core Security Rules

- Authorization must be valid, unexpired, timezone-aware when expiry is supplied, and capability-specific.
- Authorization capability and ExecutionPolicy capability must both permit an operation.
- Scope must explicitly allow a resource and deny rules must override allow rules.
- Assessment, asset, evidence, and finding identifiers must remain bound to their owning target/assessment.
- Confirmed findings require evidence belonging to the same assessment.
- Scanner output must not cross target or assessment boundaries.
- Finding deduplication must never discard evidence.
- Lifecycle transitions must be explicit and fail closed on invalid transitions.
- Risk scoring must validate all normalized inputs and remain bounded.
- Do not treat a scanner's self-declared capability as permission.
- Do not expose secrets through evidence, logs, reports, or test fixtures.
