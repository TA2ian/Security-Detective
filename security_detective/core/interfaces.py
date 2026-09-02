from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Protocol

from .models import Asset, Evidence, Finding, Target
from .policies import ExecutionPolicy


@dataclass(frozen=True, slots=True)
class ScanContext:
    target: Target
    assessment_id: str
    execution_policy: ExecutionPolicy


@dataclass(slots=True)
class ScanResult:
    assets: list[Asset] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class Scanner(Protocol):
    id: str
    version: str
    supported_target_types: frozenset[str]
    required_capabilities: frozenset[str]

    def scan(self, context: ScanContext) -> ScanResult:
        """Perform only operations permitted by the supplied context."""


class Collector(Protocol):
    id: str

    def collect(self, context: ScanContext, asset: Asset) -> Iterable[Evidence]:
        """Collect normalized evidence without bypassing Core policy."""


class Reporter(Protocol):
    id: str

    def render(self, assessment: object) -> str:
        """Render an assessment without exposing unredacted secrets."""
