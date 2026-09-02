from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from urllib.parse import urlparse

from .models import Authorization, Scope


class PolicyViolation(PermissionError):
    """Raised when a security operation is outside its authorization boundary."""


@dataclass(frozen=True, slots=True)
class ExecutionPolicy:
    allowed_capabilities: frozenset[str] = frozenset({"passive_scan"})
    allow_state_change: bool = False
    allow_destructive: bool = False

    def require(self, capability: str, *, state_changing: bool = False, destructive: bool = False) -> None:
        if capability not in self.allowed_capabilities:
            raise PolicyViolation(f"Capability not permitted: {capability}")
        if state_changing and not self.allow_state_change:
            raise PolicyViolation("State-changing operations are disabled")
        if destructive and not self.allow_destructive:
            raise PolicyViolation("Destructive operations are disabled")


def validate_authorization(auth: Authorization, required_capability: str) -> None:
    if not auth.authorized:
        raise PolicyViolation("Target is not authorized for assessment")
    if auth.expires_at is not None and auth.expires_at <= datetime.now(timezone.utc):
        raise PolicyViolation("Authorization has expired")
    if required_capability not in auth.granted_capabilities:
        raise PolicyViolation(f"Authorization does not grant: {required_capability}")


def _candidate(value: str) -> str:
    parsed = urlparse(value)
    return parsed.netloc.lower() if parsed.scheme and parsed.netloc else value.lower()


def in_scope(value: str, scope: Scope) -> bool:
    """Return True only when explicitly allowed and not denied."""
    candidate = _candidate(value)
    allowed = any(fnmatch(candidate, _candidate(rule.pattern)) for rule in scope.allows)
    denied = any(fnmatch(candidate, _candidate(rule.pattern)) for rule in scope.denies)
    return allowed and not denied


def authorize_operation(
    *,
    authorization: Authorization,
    scope: Scope,
    policy: ExecutionPolicy,
    capability: str,
    resource: str,
    state_changing: bool = False,
    destructive: bool = False,
) -> None:
    validate_authorization(authorization, capability)
    if not in_scope(resource, scope):
        raise PolicyViolation(f"Resource is outside authorized scope: {resource}")
    policy.require(capability, state_changing=state_changing, destructive=destructive)
