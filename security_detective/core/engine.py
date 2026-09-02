from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .interfaces import ScanContext, Scanner
from .models import Assessment, AssessmentStatus, Target
from .policies import ExecutionPolicy, PolicyViolation, validate_authorization
from .validation import deduplicate_findings


@dataclass(frozen=True, slots=True)
class AssessmentOutput:
    assessment: Assessment
    findings_count: int
    evidence_count: int
    assets_count: int


class AssessmentEngine:
    """Orchestrates scanners while keeping authorization and policy enforcement in Core."""

    def __init__(self, scanners: Iterable[Scanner]) -> None:
        self._scanners = tuple(scanners)

    def run(self, target: Target, assessment: Assessment, policy: ExecutionPolicy) -> AssessmentOutput:
        if target.authorization is None:
            raise PolicyViolation("Assessment requires an authorization record")

        validate_authorization(target.authorization, "passive_scan")
        assessment.transition(AssessmentStatus.AUTHORIZED)
        assessment.transition(AssessmentStatus.RUNNING)

        all_findings = []
        all_evidence = []
        all_assets = []

        try:
            for scanner in self._scanners:
                if target.target_type.value not in scanner.supported_target_types:
                    continue
                missing = scanner.required_capabilities - policy.allowed_capabilities
                if missing:
                    continue

                context = ScanContext(target=target, assessment_id=str(assessment.id), execution_policy=policy)
                result = scanner.scan(context)
                all_assets.extend(result.assets)
                all_evidence.extend(result.evidence)
                all_findings.extend(result.findings)
                assessment.scanner_ids.append(scanner.id)

            all_findings = deduplicate_findings(all_findings)
            assessment.asset_ids.extend(asset.id for asset in all_assets)
            assessment.finding_ids.extend(finding.id for finding in all_findings)
            assessment.transition(AssessmentStatus.COMPLETED)
        except Exception:
            assessment.transition(AssessmentStatus.FAILED)
            raise

        return AssessmentOutput(
            assessment=assessment,
            findings_count=len(all_findings),
            evidence_count=len(all_evidence),
            assets_count=len(all_assets),
        )
