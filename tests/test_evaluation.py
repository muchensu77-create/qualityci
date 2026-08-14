import json
import shutil
from pathlib import Path

import pytest

from qualityci.evaluation import SYNTHETIC_BENCHMARK_NOTICE, evaluate_benchmark
from qualityci.loader import load_json


ROOT = Path(__file__).parents[1]
BENCHMARK = ROOT / "datasets/qualityci-bench/tacoma_24v152"
RULE_IDS = {f"QCI-R{number:03d}" for number in range(1, 8)}


def _rewrite_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def test_benchmark_has_30_mutations_and_complete_truth_vectors():
    mutation_paths = sorted((BENCHMARK / "mutations").glob("*.json"))
    assert len(mutation_paths) >= 30
    for mutation_path in mutation_paths:
        mutation = load_json(mutation_path)
        assert set(mutation["expected_rule_statuses"]) == RULE_IDS, mutation["mutation_id"]


def test_evaluator_reports_exact_synthetic_mutation_metrics():
    report = evaluate_benchmark(BENCHMARK)

    assert report.benchmark_kind == "SYNTHETIC_MUTATION_REGRESSION"
    assert report.synthetic_data_notice == SYNTHETIC_BENCHMARK_NOTICE
    assert "not evidence of real-factory quality improvement" in report.synthetic_data_notice
    assert report.baseline_all_rules_pass is True
    assert report.mutations_evaluated == 30
    assert report.rules_per_mutation == 7
    assert report.rule_states_evaluated == 210
    assert report.rule_states_correct == 210
    assert report.rule_state_accuracy == 1.0
    assert report.mutations_exact_match == 30
    assert report.mutation_pass_rate == 1.0
    assert report.finding_true_positives == 40
    assert report.finding_false_positives == 0
    assert report.finding_false_negatives == 0
    assert report.finding_precision == 1.0
    assert report.finding_recall == 1.0
    assert report.finding_f1 == 1.0
    assert report.predicted_positive_findings == 40
    assert report.positive_findings_with_evidence == 40
    assert report.evidence_present_rate == 1.0
    assert len(report.to_dict()["mutation_results"]) == 30


def test_evaluator_counts_fp_fn_and_state_errors_from_declared_truth(tmp_path: Path):
    copied = tmp_path / "benchmark"
    shutil.copytree(BENCHMARK, copied)

    false_positive_path = copied / "mutations/M005_inspection_old_reference.json"
    false_positive = load_json(false_positive_path)
    false_positive["expected_rule_statuses"]["QCI-R005"] = "PASS"
    _rewrite_json(false_positive_path, false_positive)

    false_negative_path = copied / "mutations/M016_non_special_characteristic_boundary.json"
    false_negative = load_json(false_negative_path)
    false_negative["expected_rule_statuses"]["QCI-R003"] = "CONTRADICTED"
    _rewrite_json(false_negative_path, false_negative)

    report = evaluate_benchmark(copied)
    assert report.rule_states_correct == 208
    assert report.rule_state_accuracy == pytest.approx(208 / 210)
    assert report.mutations_exact_match == 28
    assert report.mutation_pass_rate == pytest.approx(28 / 30)
    assert report.finding_true_positives == 39
    assert report.finding_false_positives == 1
    assert report.finding_false_negatives == 1
    assert report.finding_precision == pytest.approx(39 / 40)
    assert report.finding_recall == pytest.approx(39 / 40)
    assert report.finding_f1 == pytest.approx(39 / 40)


def test_evaluator_rejects_partial_rule_truth(tmp_path: Path):
    copied = tmp_path / "benchmark"
    shutil.copytree(BENCHMARK, copied)
    mutation_path = copied / "mutations/M002_missing_validation.json"
    mutation = load_json(mutation_path)
    mutation["expected_rule_statuses"].pop("QCI-R001")
    _rewrite_json(mutation_path, mutation)

    with pytest.raises(ValueError, match="truth vector must cover the complete ruleset"):
        evaluate_benchmark(copied)
