from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Iterable

from .interfaces import ScanContext, Scanner
from .models import Assessment, AssessmentStatus, Target
from .policies import ExecutionPolicy, PolicyViolation, validate_authorization
from .validation import deduplicate_findings, require_evidence_for_confirmation


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
        if assessment.target_id != target.id:
            raise PolicyViolation("Assessment target does not match the target being scanned")
        if target.authorization is None:
            raise PolicyViolation("Assessment requires an authorization record")

        required_capability = "passive_scan"
        validate_authorization(target.authorization, required_capability)
        policy.require(required_capability)

        reference = target.authorization.authorization_reference
        if not reference or assessment.authorization_id != reference:
            raise PolicyViolation("Assessment authorization must match a valid target authorization reference")

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
                for capability in scanner.required_capabilities:
                    validate_authorization(target.authorization, capability)
                    policy.require(capability)

                # Scanner code receives an isolated target snapshot. It cannot mutate
                # the live authorization/scope/target object used by Core mid-assessment.
                scanner_target = deepcopy(target)
                context = ScanContext(
                    target=scanner_target,
                    assessment_id=str(assessment.id),
                    execution_policy=policy,
                )
                result = scanner.scan(context)
                all_assets.extend(result.assets)
                all_evidence.extend(result.evidence)
                all_findings.extend(result.findings)
                assessment.scanner_ids.append(scanner.id)

            all_findings = deduplicate_findings(all_findings)
            target_asset_ids = set()
            evidence_ids = set()
            for asset in all_assets:
                if asset.target_id != target.id:
                    raise PolicyViolation("Scanner returned an asset for another target")
                target_asset_ids.add(asset.id)
            for evidence in all_evidence:
                if evidence.assessment_id != assessment.id:
                    raise PolicyViolation("Scanner returned evidence for another assessment")
                evidence_ids.add(evidence.id)

            for finding in all_findings:
                if finding.assessment_id != assessment.id:
                    raise PolicyViolation("Scanner returned a finding for another assessment")
                if finding.asset_id not in target_asset_ids:
                    raise PolicyViolation("Scanner returned a finding for an unknown asset")
                if finding.status.value == "confirmed":
                    require_evidence_for_confirmation(finding, all_evidence)
                if not set(finding.evidence_ids).issubset(evidence_ids):
                    raise PolicyViolation("Finding references unavailable evidence")

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
