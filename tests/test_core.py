from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from security_detective.core.models import (
    Assessment,
    AssessmentStatus,
    Authorization,
    Asset,
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    Scope,
    ScopeRule,
    Severity,
    Target,
    TargetType,
)
from security_detective.core.policies import ExecutionPolicy, PolicyViolation, authorize_operation, in_scope
from security_detective.core.risk import calculate_risk
from security_detective.core.validation import FindingValidationError, deduplicate_findings, require_evidence_for_confirmation, transition_finding


def auth(*caps: str, reference: str | None = None) -> Authorization:
    return Authorization(authorized=True, granted_capabilities=frozenset(caps), authorization_reference=reference)


def test_scope_deny_wins_and_url_host_is_normalized() -> None:
    scope = Scope(allows=(ScopeRule("example.com"), ScopeRule("*.example.com")), denies=(ScopeRule("admin.example.com", action="deny"),))
    assert in_scope("example.com", scope)
    assert in_scope("https://www.example.com/path?q=1", scope)
    assert not in_scope("https://admin.example.com/path", scope)


def test_scope_does_not_treat_deny_rule_with_wrong_action_as_deny() -> None:
    scope = Scope(allows=(ScopeRule("example.com"),), denies=(ScopeRule("example.com", action="allow"),))
    assert in_scope("example.com", scope)


def test_scope_blocks_unauthorized_resource() -> None:
    with pytest.raises(PolicyViolation):
        authorize_operation(
            authorization=auth("passive_scan"),
            scope=Scope(allows=(ScopeRule("example.com"),)),
            policy=ExecutionPolicy(),
            capability="passive_scan",
            resource="other.example.com",
        )


def test_state_change_is_denied_by_default() -> None:
    with pytest.raises(PolicyViolation):
        authorize_operation(
            authorization=auth("active_scan"),
            scope=Scope(allows=(ScopeRule("example.com"),)),
            policy=ExecutionPolicy(allowed_capabilities=frozenset({"active_scan"})),
            capability="active_scan",
            resource="example.com",
            state_changing=True,
        )


def test_expired_and_naive_authorization_are_rejected() -> None:
    expired = auth("passive_scan")
    expired = Authorization(True, expired.granted_capabilities, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    with pytest.raises(PolicyViolation):
        authorize_operation(authorization=expired, scope=Scope(allows=(ScopeRule("example.com"),)), policy=ExecutionPolicy(), capability="passive_scan", resource="example.com")

    naive = Authorization(True, frozenset({"passive_scan"}), expires_at=datetime.now() + timedelta(hours=1))
    with pytest.raises(PolicyViolation):
        authorize_operation(authorization=naive, scope=Scope(allows=(ScopeRule("example.com"),)), policy=ExecutionPolicy(), capability="passive_scan", resource="example.com")


def test_assessment_transitions_are_strict() -> None:
    assessment = Assessment(target_id=Target(name="x", target_type=TargetType.WEBSITE).id)
    assessment.transition(AssessmentStatus.AUTHORIZED)
    assessment.transition(AssessmentStatus.RUNNING)
    assert assessment.started_at is not None
    assessment.transition(AssessmentStatus.COMPLETED)
    assert assessment.completed_at is not None
    with pytest.raises(ValueError):
        assessment.transition(AssessmentStatus.RUNNING)


def test_confirmed_finding_requires_evidence() -> None:
    asset = Asset(target_id=Target(name="x", target_type=TargetType.WEBSITE).id, asset_type="host", identifier="example.com", discovered_by="test")
    finding = Finding(assessment_id=uuid4(), asset_id=asset.id, rule_id="TEST-001", title="Test", description="Test", severity=Severity.HIGH, confidence=0.9, exploitability=0.8, impact=0.8, status=FindingStatus.CONFIRMED)
    with pytest.raises(FindingValidationError):
        require_evidence_for_confirmation(finding, [])


def test_finding_lifecycle_and_deduplication_preserve_evidence() -> None:
    assessment_id = uuid4()
    asset_id = uuid4()
    base = Finding(assessment_id=assessment_id, asset_id=asset_id, rule_id="TEST-001", title="Test", description="Test", severity=Severity.MEDIUM, confidence=0.5, exploitability=0.5, impact=0.5)
    suspected = transition_finding(base, FindingStatus.VALIDATING)
    confirmed = transition_finding(suspected, FindingStatus.CONFIRMED)
    evidence_a = Evidence(assessment_id=assessment_id, evidence_type=EvidenceType.HTTP, title="HTTP A", summary="safe evidence")
    evidence_b = Evidence(assessment_id=assessment_id, evidence_type=EvidenceType.HTTP, title="HTTP B", summary="safe evidence")
    confirmed.evidence_ids.append(evidence_a.id)
    stronger = Finding(assessment_id=assessment_id, asset_id=asset_id, rule_id="TEST-001", title="Test", description="Test", severity=Severity.MEDIUM, confidence=0.95, exploitability=0.5, impact=0.5, evidence_ids=[evidence_b.id])
    result = deduplicate_findings([confirmed, stronger])
    assert len(result) == 1
    assert result[0].confidence == 0.95
    assert set(result[0].evidence_ids) == {evidence_a.id, evidence_b.id}

    assert transition_finding(transition_finding(confirmed, FindingStatus.FIXED), FindingStatus.VERIFIED).status == FindingStatus.VERIFIED
    with pytest.raises(FindingValidationError):
        transition_finding(transition_finding(base, FindingStatus.UNVERIFIED), FindingStatus.CONFIRMED)


def test_risk_score_is_bounded_and_prioritized() -> None:
    finding = Finding(assessment_id=uuid4(), asset_id=uuid4(), rule_id="TEST-001", title="Critical", description="Test", severity=Severity.CRITICAL, confidence=1.0, exploitability=1.0, impact=1.0)
    result = calculate_risk(finding, exposure=1.0, asset_criticality=1.0)
    assert 0 <= result.score <= 100
    assert result.priority == "critical"
