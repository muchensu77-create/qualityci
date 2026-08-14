from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .controlled_references import load_controlled_reference_bundle
from .engine import run_case_with_evidence_bundles, run_case_with_reference_bundle
from .loader import load_case, load_json, strict_json_loads
from .models import CheckStatus
from .validation_evidence import (
    ValidationEvidenceBundle,
    ValidationEvidenceMember,
)


SYNTHETIC_BENCHMARK_NOTICE = (
    "QualityCI Bench v0.1 is a synthetic competition benchmark built from public "
    "background material and explicitly fabricated quality documents. Its metrics "
    "measure regression behavior on injected mutations; they are not evidence of "
    "real-factory quality improvement, recall, safety, or deployment readiness. "
    "The reported finding metrics classify non-PASS rule alerts, not distinct defects; "
    "evidence_present_rate checks presence only, not locator correctness."
)


@dataclass(frozen=True)
class MutationEvaluation:
    mutation_id: str
    description: str
    exact_rule_state_match: bool
    expected_rule_statuses: dict[str, str]
    actual_rule_statuses: dict[str, str]
    mismatched_rule_ids: tuple[str, ...]
    expected_positive_rule_ids: tuple[str, ...]
    predicted_positive_rule_ids: tuple[str, ...]
    positive_findings_with_evidence: int
    predicted_positive_findings: int


@dataclass(frozen=True)
class BenchmarkEvaluation:
    benchmark_kind: str
    truth_independence: str
    finding_metric_unit: str
    evidence_metric_scope: str
    synthetic_data_notice: str
    case_id: str
    ruleset_version: str
    baseline_all_rules_pass: bool
    mutations_evaluated: int
    rules_per_mutation: int
    rule_states_evaluated: int
    rule_states_correct: int
    rule_state_accuracy: float
    mutations_exact_match: int
    mutation_pass_rate: float
    finding_true_positives: int
    finding_false_positives: int
    finding_false_negatives: int
    finding_precision: float
    finding_recall: float
    finding_f1: float
    positive_findings_with_evidence: int
    predicted_positive_findings: int
    evidence_present_rate: float
    mutation_results: tuple[MutationEvaluation, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ratio(numerator: int, denominator: int) -> float:
    """Return an unrounded ratio; undefined zero-denominator metrics are 0.0."""

    return numerator / denominator if denominator else 0.0


def _validate_truth_vector(
    mutation: dict[str, Any],
    actual_rule_ids: set[str],
) -> dict[str, str]:
    mutation_id = str(mutation.get("mutation_id", "<missing>"))
    truth = mutation.get("expected_rule_statuses")
    if not isinstance(truth, dict):
        raise ValueError(f"{mutation_id}: expected_rule_statuses must be an object")

    truth_rule_ids = set(truth)
    missing = sorted(actual_rule_ids - truth_rule_ids)
    extra = sorted(truth_rule_ids - actual_rule_ids)
    if missing or extra:
        raise ValueError(
            f"{mutation_id}: truth vector must cover the complete ruleset; "
            f"missing={missing}, extra={extra}"
        )

    allowed = {str(status) for status in CheckStatus}
    invalid = {rule_id: value for rule_id, value in truth.items() if value not in allowed}
    if invalid:
        raise ValueError(f"{mutation_id}: invalid expected statuses: {invalid}")
    return {str(rule_id): str(status) for rule_id, status in truth.items()}


def _benchmark_validation_bundle(
    index: dict[str, Any],
    key: str,
) -> ValidationEvidenceBundle | None:
    if set(index) != {"contract_version", "entries"}:
        raise ValueError("benchmark validation index has unsupported keys")
    if index.get("contract_version") != "qualityci-benchmark-validation-index-0.1":
        raise ValueError("benchmark validation index contract is unsupported")
    entries = index.get("entries")
    if not isinstance(entries, dict) or key not in entries:
        raise ValueError(f"benchmark validation entry is missing: {key}")
    entry = entries[key]
    if entry is None:
        return None
    if not isinstance(entry, dict) or set(entry) != {"manifest_json", "report_json"}:
        raise ValueError(f"benchmark validation entry is malformed: {key}")
    manifest_json = entry["manifest_json"]
    report_json = entry["report_json"]
    if type(manifest_json) is not str or type(report_json) is not str:
        raise ValueError(f"benchmark validation entry must contain exact JSON strings: {key}")
    manifest = strict_json_loads(manifest_json)
    members = manifest.get("members") if isinstance(manifest, dict) else None
    if not isinstance(members, list) or len(members) != 1:
        raise ValueError(f"benchmark validation entry must have one member: {key}")
    member = members[0]
    return ValidationEvidenceBundle(
        manifest_json.encode("utf-8"),
        (
            ValidationEvidenceMember(
                member["source_id"],
                member["evidence_id"],
                member["source_path"],
                report_json.encode("utf-8"),
            ),
        ),
    )


def evaluate_benchmark(benchmark_dir: str | Path) -> BenchmarkEvaluation:
    """Evaluate every mutation in one explicitly synthetic QualityCI Bench case.

    A positive *rule alert* is defined before execution as an expected rule state
    other than ``PASS``. ``CONTRADICTED`` and ``UNVERIFIABLE`` are both positive
    for this engineering regression metric, while rule-state accuracy still
    requires the exact class. This is not issue-level defect detection recall.

    ``mutation_pass_rate`` is the proportion of mutations whose complete rule-state
    vector is exactly correct. ``evidence_present_rate`` is the proportion of
    reported positive findings carrying at least one evidence reference.
    """

    root = Path(benchmark_dir)
    baseline_path = root / "baseline_v04.json"
    reference_manifest = root / "reference_sources/manifest.json"
    validation_index_path = root / "validation_sources/benchmark_evidence.json"
    mutation_paths = sorted((root / "mutations").glob("*.json"))
    if not baseline_path.is_file():
        raise ValueError(f"benchmark baseline not found: {baseline_path}")
    if not mutation_paths:
        raise ValueError(f"benchmark contains no mutations: {root / 'mutations'}")
    if not reference_manifest.is_file():
        raise ValueError(f"benchmark controlled-reference pack not found: {reference_manifest}")
    if not validation_index_path.is_file():
        raise ValueError(
            f"benchmark validation evidence index not found: {validation_index_path}"
        )

    baseline_case = load_case(baseline_path)
    if baseline_case.get("synthetic_for_competition") is not True:
        raise ValueError("benchmark must be explicitly marked synthetic_for_competition=true")

    reference_bundle = load_controlled_reference_bundle(reference_manifest)
    validation_index = load_json(validation_index_path)
    baseline_validation = _benchmark_validation_bundle(validation_index, "BASELINE")
    if baseline_validation is None:
        raise ValueError("benchmark baseline requires raw validation evidence")
    baseline_result = run_case_with_evidence_bundles(
        baseline_case,
        reference_bundle,
        baseline_validation,
    )
    baseline_statuses = {
        finding.rule_id: str(finding.status) for finding in baseline_result.findings
    }
    actual_rule_ids = set(baseline_statuses)
    if not actual_rule_ids:
        raise ValueError("ruleset produced no findings for the benchmark baseline")

    total_state_correct = 0
    total_state_count = 0
    exact_mutations = 0
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    evidence_present = 0
    predicted_positive_count = 0
    seen_mutation_ids: set[str] = set()
    mutation_results: list[MutationEvaluation] = []

    for mutation_path in mutation_paths:
        mutation = load_json(mutation_path)
        mutation_id = str(mutation.get("mutation_id", ""))
        if not mutation_id:
            raise ValueError(f"{mutation_path.name}: mutation_id is required")
        if mutation_id in seen_mutation_ids:
            raise ValueError(f"duplicate mutation_id: {mutation_id}")
        seen_mutation_ids.add(mutation_id)

        mutated_case = load_case(baseline_path, mutation_path)
        validation_bundle = _benchmark_validation_bundle(
            validation_index,
            mutation_id,
        )
        result = (
            run_case_with_evidence_bundles(
                mutated_case,
                reference_bundle,
                validation_bundle,
            )
            if validation_bundle is not None
            else run_case_with_reference_bundle(mutated_case, reference_bundle)
        )
        findings = {finding.rule_id: finding for finding in result.findings}
        if set(findings) != actual_rule_ids:
            raise ValueError(
                f"{mutation_id}: runtime ruleset differs from baseline; "
                f"baseline={sorted(actual_rule_ids)}, runtime={sorted(findings)}"
            )

        expected = _validate_truth_vector(mutation, actual_rule_ids)
        actual = {rule_id: str(finding.status) for rule_id, finding in findings.items()}
        mismatched = tuple(
            sorted(rule_id for rule_id in actual_rule_ids if actual[rule_id] != expected[rule_id])
        )
        exact = not mismatched
        exact_mutations += int(exact)
        total_state_count += len(actual_rule_ids)
        total_state_correct += len(actual_rule_ids) - len(mismatched)

        expected_positive = {
            rule_id for rule_id, status in expected.items() if status != str(CheckStatus.PASS)
        }
        predicted_positive = {
            rule_id for rule_id, status in actual.items() if status != str(CheckStatus.PASS)
        }
        true_positives += len(expected_positive & predicted_positive)
        false_positives += len(predicted_positive - expected_positive)
        false_negatives += len(expected_positive - predicted_positive)

        with_evidence = sum(bool(findings[rule_id].evidence) for rule_id in predicted_positive)
        evidence_present += with_evidence
        predicted_positive_count += len(predicted_positive)

        mutation_results.append(
            MutationEvaluation(
                mutation_id=mutation_id,
                description=str(mutation.get("description", "")),
                exact_rule_state_match=exact,
                expected_rule_statuses=dict(sorted(expected.items())),
                actual_rule_statuses=dict(sorted(actual.items())),
                mismatched_rule_ids=mismatched,
                expected_positive_rule_ids=tuple(sorted(expected_positive)),
                predicted_positive_rule_ids=tuple(sorted(predicted_positive)),
                positive_findings_with_evidence=with_evidence,
                predicted_positive_findings=len(predicted_positive),
            )
        )

    precision = _ratio(true_positives, true_positives + false_positives)
    recall = _ratio(true_positives, true_positives + false_negatives)
    f1 = _ratio(2 * precision * recall, precision + recall)

    return BenchmarkEvaluation(
        benchmark_kind="SYNTHETIC_MUTATION_REGRESSION",
        truth_independence="CO_DEVELOPED_ENGINEERING_SELF_TEST",
        finding_metric_unit="RULE_ALERT_PER_MUTATION",
        evidence_metric_scope="PRESENCE_ONLY_NOT_LOCATOR_CORRECTNESS",
        synthetic_data_notice=SYNTHETIC_BENCHMARK_NOTICE,
        case_id=str(baseline_case["case_id"]),
        ruleset_version=baseline_result.ruleset_version,
        baseline_all_rules_pass=all(
            status == str(CheckStatus.PASS) for status in baseline_statuses.values()
        ),
        mutations_evaluated=len(mutation_results),
        rules_per_mutation=len(actual_rule_ids),
        rule_states_evaluated=total_state_count,
        rule_states_correct=total_state_correct,
        rule_state_accuracy=_ratio(total_state_correct, total_state_count),
        mutations_exact_match=exact_mutations,
        mutation_pass_rate=_ratio(exact_mutations, len(mutation_results)),
        finding_true_positives=true_positives,
        finding_false_positives=false_positives,
        finding_false_negatives=false_negatives,
        finding_precision=precision,
        finding_recall=recall,
        finding_f1=f1,
        positive_findings_with_evidence=evidence_present,
        predicted_positive_findings=predicted_positive_count,
        evidence_present_rate=_ratio(evidence_present, predicted_positive_count),
        mutation_results=tuple(mutation_results),
    )
