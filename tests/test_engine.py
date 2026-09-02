from security_detective.core.engine import AssessmentEngine
from security_detective.core.interfaces import ScanContext, ScanResult
from security_detective.core.models import Assessment, Authorization, Target, TargetType
from security_detective.core.policies import ExecutionPolicy


class EmptyScanner:
    id = "test.empty"
    version = "1.0.0"
    supported_target_types = frozenset({"website"})
    required_capabilities = frozenset({"passive_scan"})

    def scan(self, context: ScanContext) -> ScanResult:
        assert context.target.name == "example.com"
        return ScanResult()


def test_engine_runs_only_supported_and_permitted_scanners() -> None:
    target = Target(
        name="example.com",
        target_type=TargetType.WEBSITE,
        authorization=Authorization(authorized=True, granted_capabilities=frozenset({"passive_scan"})),
    )
    assessment = Assessment(target_id=target.id)
    output = AssessmentEngine([EmptyScanner()]).run(target, assessment, ExecutionPolicy())
    assert output.assessment.status.value == "completed"
    assert output.assessment.scanner_ids == ["test.empty"]
