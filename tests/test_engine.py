import pytest

from security_detective.core.engine import AssessmentEngine
from security_detective.core.interfaces import ScanContext, ScanResult
from security_detective.core.models import Assessment, Asset, Authorization, Evidence, EvidenceType, Finding, FindingStatus, Severity, Target, TargetType
from security_detective.core.policies import ExecutionPolicy, PolicyViolation


class EmptyScanner:
    id = "test.empty"
    version = "1.0.0"
    supported_target_types = frozenset({"website"})
    required_capabilities = frozenset({"passive_scan"})

    def scan(self, context: ScanContext) -> ScanResult:
        assert context.target.name == "example.com"
        return ScanResult()


def make_target() -> Target:
    return Target(name="example.com", target_type=TargetType.WEBSITE, authorization=Authorization(authorized=True, granted_capabilities=frozenset({"passive_scan"}), authorization_reference="auth-1"))


def test_engine_runs_only_supported_and_permitted_scanners() -> None:
    target = make_target()
    assessment = Assessment(target_id=target.id, authorization_id="auth-1")
    output = AssessmentEngine([EmptyScanner()]).run(target, assessment, ExecutionPolicy())
    assert output.assessment.status.value == "completed"
    assert output.assessment.scanner_ids == ["test.empty"]


def test_engine_rejects_policy_without_required_passive_capability() -> None:
    target = make_target()
    assessment = Assessment(target_id=target.id, authorization_id="auth-1")
    with pytest.raises(PolicyViolation):
        AssessmentEngine([EmptyScanner()]).run(target, assessment, ExecutionPolicy(allowed_capabilities=frozenset()))


def test_engine_rejects_missing_authorization_reference() -> None:
    target = make_target()
    assessment = Assessment(target_id=target.id)
    with pytest.raises(PolicyViolation):
        AssessmentEngine([EmptyScanner()]).run(target, assessment, ExecutionPolicy())


def test_engine_rejects_mismatched_authorization_reference() -> None:
    target = make_target()
    assessment = Assessment(target_id=target.id, authorization_id="wrong")
    with pytest.raises(PolicyViolation):
        AssessmentEngine([EmptyScanner()]).run(target, assessment, ExecutionPolicy())


class InvalidOutputScanner:
    id = "test.invalid"
    version = "1.0.0"
    supported_target_types = frozenset({"website"})
    required_capabilities = frozenset({"passive_scan"})

    def scan(self, context: ScanContext) -> ScanResult:
        foreign_target = Target(name="foreign.example", target_type=TargetType.WEBSITE)
        asset = Asset(target_id=foreign_target.id, asset_type="host", identifier="foreign.example", discovered_by=self.id)
        evidence = Evidence(assessment_id=__import__("uuid").uuid4(), evidence_type=EvidenceType.HTTP, title="foreign", summary="foreign")
        finding = Finding(assessment_id=__import__("uuid").uuid4(), asset_id=asset.id, rule_id="TEST", title="foreign", description="foreign", severity=Severity.HIGH, confidence=1.0, exploitability=1.0, impact=1.0, status=FindingStatus.CONFIRMED)
        return ScanResult(assets=[asset], evidence=[evidence], findings=[finding])


class MutatingScanner:
    id = "test.mutating"
    version = "1.0.0"
    supported_target_types = frozenset({"website"})
    required_capabilities = frozenset({"passive_scan"})

    def scan(self, context: ScanContext) -> ScanResult:
        context.target.name = "mutated.example"
        context.target.authorization = None
        return ScanResult()


def test_engine_isolates_live_target_from_scanner_mutation() -> None:
    target = make_target()
    assessment = Assessment(target_id=target.id, authorization_id="auth-1")
    output = AssessmentEngine([MutatingScanner()]).run(target, assessment, ExecutionPolicy())
    assert output.assessment.status.value == "completed"
    assert target.name == "example.com"
    assert target.authorization is not None


def test_engine_rejects_scanner_output_crossing_target_boundary() -> None:
    target = make_target()
    assessment = Assessment(target_id=target.id, authorization_id="auth-1")
    with pytest.raises(PolicyViolation):
        AssessmentEngine([InvalidOutputScanner()]).run(target, assessment, ExecutionPolicy())
    assert assessment.status.value == "failed"
