from datetime import datetime, timedelta, timezone

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


def auth(*caps: str) -> Authorization:
    return Authorization(authorized=True, granted_capabilities=frozenset(caps))


def test_scope_deny_wins() -> None:
    scope = Scope(allows=(ScopeRule("example.com"),), denies=(ScopeRule("admin.example.com"),))
    assert in_scope("example.com", scope)
    assert not in_scope("admin.example.com", scope)


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


def test_expired_authorization_is_rejected() -> None:
    expired = Authorization(
        authorized=True,
        granted_capabilities=frozenset({"passive_scan"}),
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    with pytest.raises(PolicyViolation):
        authorize_operation(
            authorization=expired,
            scope=Scope(allows=(ScopeRule("example.com"),)),
            policy=ExecutionPolicy(),
            capability="passive_scan",
            resource="example.com",
        )


def test_assessment_transitions_are_strict() -> None:
    assessment = Assessment(target_id=Target(name="x", target_type=TargetType.WEBSITE).id)
    assessment.transition(AssessmentStatus.AUTHORIZED)
    assessment.transition(AssessmentStatus.RUNNING)
    assessment.transition(AssessmentStatus.COMPLETED)
    with pytest.raises(ValueError):
        assessment.transition(AssessmentStatus.RUNNING)


def test_confirmed_finding_requires_evidence() -> None:
    asset = Asset(target_id=Target(name="x", target_type=TargetType.WEBSITE).id, asset_type="host", identifier="example.com", discovered_by="test")
    finding = Finding(
        assessment_id=__import__("uuid").uuid4(), asset_id=asset.id, rule_id="TEST-001", title="Test", description="Test",
        severity=Severity.HIGH, confidence=0.9, exploitability=0.8, impact=0.8, status=FindingStatus.CONFIRMED,
    )
    with pytest.raises(FindingValidationError):
        require_evidence_for_confirmation(finding, [])


def test_finding_lifecycle_and_deduplication() -> None:
    assessment_id = __import__("uuid").uuid4()
    asset_id = __import__("uuid").uuid4()
    base = Finding(
        assessment_id=assessment_id, asset_id=asset_id, rule_id="TEST-001", title="Test", description="Test",
        severity=Severity.MEDIUM, confidence=0.5, exploitability=0.5, impact=0.5,
    )
    suspected = transition_finding(base, FindingStatus.VALIDATING)
    confirmed = transition_finding(suspected, FindingStatus.CONFIRMED)
    evidence = Evidence(assessment_id=assessment_id, evidence_type=EvidenceType.HTTP, title="HTTP", summary="safe evidence")
    confirmed.evidence_ids.append(evidence.id)
    require_evidence_for_confirmation(confirmed, [evidence])
    stronger = Finding(
        assessment_id=assessment_id, asset_id=asset_id, rule_id="TEST-001", title="Test", description="Test",
        severity=Severity.MEDIUM, confidence=0.95, exploitability=0.5, impact=0.5,
    )
    assert len(deduplicate_findings([base, stronger])) == 1
    assert deduplicate_findings([base, stronger])[0].confidence == 0.95


def test_risk_score_is_bounded_and_prioritized() -> None:
    finding = Finding(
        assessment_id=__import__("uuid").uuid4(), asset_id=__import__("uuid").uuid4(), rule_id="TEST-001", title="Critical",
        description="Test", severity=Severity.CRITICAL, confidence=1.0, exploitability=1.0, impact=1.0,
    )
    result = calculate_risk(finding, exposure=1.0, asset_criticality=1.0)
    assert 0 <= result.score <= 100
    assert result.priority == "critical"
