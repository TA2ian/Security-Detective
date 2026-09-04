from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import UUID, uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TargetType(str, Enum):
    WEBSITE = "website"
    WEB_APPLICATION = "web_application"
    API = "api"
    TELEGRAM_BOT = "telegram_bot"
    TELEGRAM_CHANNEL = "telegram_channel"
    TELEGRAM_GROUP = "telegram_group"
    SOURCE_REPOSITORY = "source_repository"
    MOBILE_APPLICATION = "mobile_application"
    INFRASTRUCTURE = "infrastructure"


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    UNKNOWN = "unknown"


class AssessmentStatus(str, Enum):
    CREATED = "created"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingStatus(str, Enum):
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    FIXED = "fixed"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    UNVERIFIED = "unverified"
    ACCEPTED_RISK = "accepted_risk"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class EvidenceType(str, Enum):
    SOURCE = "source"
    HTTP = "http"
    CONFIGURATION = "configuration"
    DATABASE = "database"
    RUNTIME = "runtime"
    BEHAVIORAL = "behavioral"


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """One explicit allow/deny boundary. Deny always wins."""
    pattern: str
    action: str = "allow"

    def __post_init__(self) -> None:
        if self.action not in {"allow", "deny"}:
            raise ValueError("ScopeRule action must be 'allow' or 'deny'")
        if not self.pattern.strip():
            raise ValueError("ScopeRule pattern must not be empty")


@dataclass(frozen=True, slots=True)
class Scope:
    allows: tuple[ScopeRule, ...] = ()
    denies: tuple[ScopeRule, ...] = ()


@dataclass(frozen=True, slots=True)
class Authorization:
    authorized: bool
    granted_capabilities: frozenset[str] = frozenset()
    authorization_reference: str | None = None
    expires_at: datetime | None = None


@dataclass(slots=True)
class Target:
    name: str
    target_type: TargetType
    environment: Environment = Environment.UNKNOWN
    scope: Scope = field(default_factory=Scope)
    authorization: Authorization | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)


@dataclass(frozen=True, slots=True)
class Asset:
    target_id: UUID
    asset_type: str
    identifier: str
    discovered_by: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)


@dataclass(frozen=True, slots=True)
class Evidence:
    assessment_id: UUID
    evidence_type: EvidenceType
    title: str
    summary: str
    data: Mapping[str, Any] = field(default_factory=dict)
    redacted: bool = False
    id: UUID = field(default_factory=uuid4)
    collected_at: datetime = field(default_factory=utcnow)


@dataclass(slots=True)
class Finding:
    assessment_id: UUID
    asset_id: UUID
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    exploitability: float
    impact: float
    status: FindingStatus = FindingStatus.SUSPECTED
    evidence_ids: list[UUID] = field(default_factory=list)
    remediation: str | None = None
    id: UUID = field(default_factory=uuid4)
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        for name, value in (("confidence", self.confidence), ("exploitability", self.exploitability), ("impact", self.impact)):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    name: str
    category: str
    severity: Severity
    description: str
    remediation: str
    version: str = "1.0.0"


@dataclass(slots=True)
class Assessment:
    target_id: UUID
    authorization_id: str | None = None
    status: AssessmentStatus = AssessmentStatus.CREATED
    scanner_ids: list[str] = field(default_factory=list)
    asset_ids: list[UUID] = field(default_factory=list)
    finding_ids: list[UUID] = field(default_factory=list)
    id: UUID = field(default_factory=uuid4)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    def transition(self, new_status: AssessmentStatus) -> None:
        allowed: dict[AssessmentStatus, set[AssessmentStatus]] = {
            AssessmentStatus.CREATED: {AssessmentStatus.AUTHORIZED, AssessmentStatus.CANCELLED},
            AssessmentStatus.AUTHORIZED: {AssessmentStatus.RUNNING, AssessmentStatus.CANCELLED},
            AssessmentStatus.RUNNING: {AssessmentStatus.COMPLETED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED},
            AssessmentStatus.COMPLETED: set(),
            AssessmentStatus.FAILED: set(),
            AssessmentStatus.CANCELLED: set(),
        }
        if new_status not in allowed[self.status]:
            raise ValueError(f"Invalid assessment transition: {self.status.value} -> {new_status.value}")
        self.status = new_status
        if new_status == AssessmentStatus.RUNNING:
            self.started_at = utcnow()
        if new_status in {AssessmentStatus.COMPLETED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED}:
            self.completed_at = utcnow()
