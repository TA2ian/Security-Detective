---
trigger: model_decision
description: "Guidelines for implementing or reviewing HTTP, passive web, TLS, headers, redirect, and exposure scanners."
---

# HTTP Passive Scanner Rules

- Default to safe, read-only HTTP operations.
- Enforce Core authorization and scope before every network operation.
- Do not follow redirects outside authorized scope.
- Normalize URLs and HTTP evidence consistently.
- Never send destructive methods or state-changing requests in passive mode.
- Avoid credential submission, brute force, exploit payloads, persistence, or evasion.
- Treat response bodies as untrusted input.
- Redact cookies, authorization headers, tokens, API keys, and other secrets from evidence.
- Findings must reference concrete HTTP evidence.
- Prefer deterministic rules with explicit identifiers and versions.
- Test scanners against locally controlled vulnerable fixtures before external targets.
