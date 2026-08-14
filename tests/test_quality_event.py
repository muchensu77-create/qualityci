from pathlib import Path

from qualityci.controlled_references import load_controlled_reference_bundle
from qualityci.engine import run_case_with_evidence_bundles, run_case_with_reference_bundle
from qualityci.loader import apply_mutation, load_case
from qualityci.models import CheckStatus
from validation_support import native_validation_case, validation_bundle


ROOT = Path(__file__).parents[1]
CASE = ROOT / "datasets/qualityci-cases/electronics_quality_event/baseline.json"
REFERENCES = ROOT / "datasets/qualityci-cases/electronics_quality_event/reference_sources/manifest.json"


def _run(case):
    native = native_validation_case(case)
    return run_case_with_evidence_bundles(
        native,
        load_controlled_reference_bundle(REFERENCES),
        validation_bundle(native, "SOURCE"),
    )


def test_quality_event_runs_same_evidence_regression_contract():
    case = load_case(CASE)
    result = _run(case)
    assert case["event"]["event_type"] == "QUALITY_EVENT"
    assert result.overall_status == CheckStatus.PASS
    assert all(finding.evidence for finding in result.findings)


def test_quality_event_without_effectiveness_evidence_is_unverifiable():
    case = load_case(CASE)
    mutation = {
        "mutation_id": "QUALITY_EVENT_NO_EFFECTIVENESS",
        "operations": [{"op": "delete", "target": "event", "path": "validation_evidence"}],
    }
    native = native_validation_case(apply_mutation(case, mutation))
    result = run_case_with_reference_bundle(
        native,
        load_controlled_reference_bundle(REFERENCES),
    )
    finding = next(item for item in result.findings if item.rule_id == "QCI-R006")
    assert finding.status == CheckStatus.UNVERIFIABLE
    assert finding.evidence[0].locator == "validation_evidence"
