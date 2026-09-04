from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from .models import Evidence, Finding, FindingStatus


class FindingValidationError(ValueError):
    pass


_ALLOWED: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.OBSERVED: {FindingStatus.SUSPECTED, FindingStatus.FALSE_POSITIVE},
    FindingStatus.SUSPECTED: {FindingStatus.VALIDATING, FindingStatus.FALSE_POSITIVE, FindingStatus.UNVERIFIED},
    FindingStatus.VALIDATING: {FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE, FindingStatus.UNVERIFIED},
    FindingStatus.CONFIRMED: {FindingStatus.FIXED, FindingStatus.ACCEPTED_RISK},
    FindingStatus.FIXED: {FindingStatus.VERIFIED, FindingStatus.CONFIRMED},
    FindingStatus.VERIFIED: set(),
    FindingStatus.FALSE_POSITIVE: set(),
    FindingStatus.UNVERIFIED: {FindingStatus.VALIDATING},
    FindingStatus.ACCEPTED_RISK: {FindingStatus.VALIDATING},
}


def transition_finding(finding: Finding, new_status: FindingStatus) -> Finding:
    if new_status not in _ALLOWED[finding.status]:
        raise FindingValidationError(f"Invalid finding transition: {finding.status.value} -> {new_status.value}")
    return replace(finding, status=new_status)


def require_evidence_for_confirmation(finding: Finding, evidence: Iterable[Evidence]) -> None:
    evidence_ids = {item.id for item in evidence}
    if finding.status == FindingStatus.CONFIRMED and not (set(finding.evidence_ids) & evidence_ids):
        raise FindingValidationError("A confirmed finding must reference available evidence")


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Deduplicate by assessment, asset, rule and title while preserving all evidence."""
    unique: dict[tuple[object, object, str, str], Finding] = {}
    for finding in findings:
        key = (finding.assessment_id, finding.asset_id, finding.rule_id, finding.title)
        current = unique.get(key)
        if current is None:
            unique[key] = finding
            continue
        if finding.confidence > current.confidence:
            winner, other = finding, current
        else:
            winner, other = current, finding
        merged_evidence = list(dict.fromkeys([*winner.evidence_ids, *other.evidence_ids]))
        unique[key] = replace(winner, evidence_ids=merged_evidence)
    return list(unique.values())
