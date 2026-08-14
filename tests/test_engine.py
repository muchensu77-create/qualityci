import copy
from dataclasses import replace
from pathlib import Path

import pytest

from qualityci.controlled_references import load_controlled_reference_bundle
from qualityci.engine import run_case_with_evidence_bundles, run_case_with_reference_bundle
from qualityci.evaluation import _benchmark_validation_bundle
from qualityci.loader import load_case, load_json
from qualityci.models import CheckStatus
from qualityci.revision_artifacts import (
    RevisionArtifactError,
    load_revision_artifact_bundle,
)
from qualityci.workflow import (
    ApprovalGateError,
    replay_with_resolution,
    resolution_approval_subject,
    resolution_patch_hash,
)
from qualityci.validation_evidence import load_validation_evidence_bundle
from validation_support import validation_bundle
from a05_support import (
    NativeApprovalClaims,
    native_approval_claims,
    native_approval_replay,
)


ROOT = Path(__file__).parents[1]
CASE = ROOT / "datasets/qualityci-bench/tacoma_24v152/baseline_v04.json"
MUTATIONS = ROOT / "datasets/qualityci-bench/tacoma_24v152/mutations"
RESOLUTIONS = ROOT / "datasets/qualityci-bench/tacoma_24v152/resolutions"
REPLACEMENT = ROOT / "datasets/qualityci-bench/tacoma_24v152/replacement_artifacts/R001/manifest.json"
REFERENCES = ROOT / "datasets/qualityci-bench/tacoma_24v152/reference_sources/manifest.json"
VALIDATION_INDEX = ROOT / "datasets/qualityci-bench/tacoma_24v152/validation_sources/benchmark_evidence.json"
SOURCE_VALIDATION = ROOT / "datasets/qualityci-bench/tacoma_24v152/validation_sources/R001/source/manifest.json"
RESOLVED_VALIDATION = ROOT / "datasets/qualityci-bench/tacoma_24v152/validation_sources/R001/resolved/manifest.json"


def _run_actual(case, evidence_key="BASELINE"):
    if evidence_key is None:
        return run_case_with_reference_bundle(
            case, load_controlled_reference_bundle(REFERENCES)
        )
    if evidence_key == "DYNAMIC":
        evidence = validation_bundle(case, "SOURCE")
    else:
        evidence = _benchmark_validation_bundle(load_json(VALIDATION_INDEX), evidence_key)
    if evidence is None:
        return run_case_with_reference_bundle(
            case, load_controlled_reference_bundle(REFERENCES)
        )
    return run_case_with_evidence_bundles(
        case,
        load_controlled_reference_bundle(REFERENCES),
        evidence,
    )


def _approval_claims(case, resolution):
    return native_approval_claims(
        case,
        resolution,
        artifact_bundle=load_revision_artifact_bundle(REPLACEMENT),
        reference_bundle=load_controlled_reference_bundle(REFERENCES),
    )


def _replay(case, resolution, *, claims=None):
    return native_approval_replay(
        case,
        resolution,
        artifact_bundle=load_revision_artifact_bundle(REPLACEMENT),
        reference_bundle=load_controlled_reference_bundle(REFERENCES),
        source_validation_bundle=load_validation_evidence_bundle(SOURCE_VALIDATION),
        resolved_validation_bundle=load_validation_evidence_bundle(RESOLVED_VALIDATION),
        claims=claims,
    ).replay


def _bind_resolution(case, resolution, roles=("PROCESS_OWNER", "QUALITY_MANAGER")):
    resolution["replacement_set_id"] = "REPLACEMENT-RES-SYN-001"
    subject = {
        "case_id": case["case_id"],
        "event_id": case["event"]["event_id"],
        "event_revision": case["event"]["revision"],
        "approved_case_hash": "0" * 64,
    }
    patch_hash = "0" * 64
    resolution["approvals"] = [
        {
            "role": role,
            "decision": "APPROVED",
            "case_id": subject["case_id"],
            "event_id": subject["event_id"],
            "event_revision": subject["event_revision"],
            "approved_case_hash": subject["approved_case_hash"],
            "approved_patch_hash": patch_hash,
        }
        for role in roles
    ]
    return resolution


def test_baseline_passes_all_rules():
    result = _run_actual(load_case(CASE))
    assert result.overall_status == CheckStatus.PASS
    assert len(result.findings) == 7
    assert all(finding.status == CheckStatus.PASS for finding in result.findings)
    assert all(finding.evidence for finding in result.findings)


def test_run_id_is_deterministic():
    first = _run_actual(load_case(CASE))
    second = _run_actual(load_case(CASE))
    assert first.run_id == second.run_id
    assert first.case_hash == second.case_hash


def test_two_thousand_characteristics_complete_with_indexed_rules():
    case = load_case(CASE)
    characteristic_ids = [f"CTQ-PERF-{index:04d}" for index in range(2_000)]
    case["event"]["affected_characteristics"] = characteristic_ids
    case["event"]["affected_process_steps"] = ["WELD-10"]
    case["event"]["affected_links"] = [
        {
            "process_step_id": "WELD-10",
            "characteristic_id": characteristic_id,
        }
        for characteristic_id in characteristic_ids
    ]

    for document_type in ("CONTROL_PLAN", "SOP", "INSPECTION_RECORD"):
        document = next(
            item for item in case["documents"] if item["document_type"] == document_type
        )
        characteristics = []
        for index, characteristic_id in enumerate(characteristic_ids):
            characteristic = {
                "process_step_id": "WELD-10",
                "characteristic_id": characteristic_id,
                "specification": {
                    "target": 0,
                    "minimum": 0,
                    "maximum": 0,
                    "unit": "mm",
                },
                "locator": f"{document_type}#{characteristic_id}",
            }
            if document_type == "CONTROL_PLAN":
                characteristic.update(
                    control_id=f"CTRL-PERF-{index:04d}",
                    control_method="100% inspection",
                    frequency="each part",
                    reaction_plan="isolate and review",
                )
            characteristics.append(characteristic)
        document["fields"]["characteristics"] = characteristics

    pfmea = next(
        item for item in case["documents"] if item["document_type"] == "PFMEA"
    )
    pfmea["fields"]["risks"] = [
        {
            "failure_mode_id": f"FM-PERF-{index:04d}",
            "process_step_id": "WELD-10",
            "characteristic_id": characteristic_id,
            "special_characteristic": True,
            "locator": f"PFMEA#{characteristic_id}",
        }
        for index, characteristic_id in enumerate(characteristic_ids)
    ]

    result = _run_actual(case, "DYNAMIC")
    findings = {finding.rule_id: finding.status for finding in result.findings}

    assert result.overall_status == CheckStatus.PASS
    assert findings["QCI-R002"] == CheckStatus.PASS
    assert findings["QCI-R003"] == CheckStatus.PASS


def test_mutation_truth_labels():
    for mutation_path in sorted(MUTATIONS.glob("*.json")):
        mutation = load_json(mutation_path)
        result = _run_actual(
            load_case(CASE, mutation_path),
            mutation["mutation_id"],
        )
        actual = {finding.rule_id: str(finding.status) for finding in result.findings}
        for rule_id, expected_status in mutation["expected_rule_statuses"].items():
            assert actual[rule_id] == expected_status, mutation["mutation_id"]
        assert all(finding.evidence for finding in result.findings), mutation["mutation_id"]


def test_contradicted_has_priority_over_unverifiable():
    mutation_path = MUTATIONS / "M001_stale_sop_conflict.json"
    result = _run_actual(
        load_case(CASE, mutation_path),
        "M001_STALE_SOP_CONFLICT",
    )
    assert result.overall_status == CheckStatus.CONTRADICTED


def test_approved_resolution_reruns_to_new_baseline():
    case = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    resolution = load_json(RESOLUTIONS / "R001_resolve_stale_sop.json")
    replay = _replay(case, resolution)
    assert replay.before.overall_status == CheckStatus.CONTRADICTED
    assert replay.after.overall_status == CheckStatus.PASS
    assert replay.baseline is not None
    assert replay.baseline.status == "BASELINED"


def test_unapproved_resolution_is_blocked():
    case = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    resolution = load_json(RESOLUTIONS / "R001_resolve_stale_sop.json")
    claims = _approval_claims(case, resolution)
    assertions = tuple(
        assertion
        for assertion in claims.assertions
        if assertion["role_claim"] != "QUALITY_MANAGER"
    )
    with pytest.raises(ApprovalGateError, match="QUALITY_MANAGER"):
        _replay(case, resolution, claims=replace(claims, assertions=assertions))


def test_missing_or_unknown_risk_level_fails_closed():
    missing = load_case(CASE)
    missing["event"].pop("risk_level")
    with pytest.raises(ValueError, match="risk_level"):
        _run_actual(missing)

    unknown = load_case(CASE)
    unknown["event"]["risk_level"] = "UNKNOWN"
    with pytest.raises(ValueError, match="risk_level"):
        _run_actual(unknown)


@pytest.mark.parametrize("decision", ["REJECTED", "CHANGES_REQUESTED"])
def test_any_current_revision_rejection_blocks_high_risk_approval(decision):
    case = load_case(CASE)
    case["event"]["approvals"].append(
        {
            "role": "SAFETY_REVIEWER",
            "decision": decision,
            "event_revision": case["event"]["revision"],
        }
    )

    result = _run_actual(case)
    finding = next(item for item in result.findings if item.rule_id == "QCI-R007")

    assert finding.status == CheckStatus.CONTRADICTED
    assert decision in finding.evidence[0].excerpt


def test_rejection_for_another_revision_does_not_block_current_approval():
    case = load_case(CASE)
    case["event"]["approvals"].append(
        {
            "role": "SAFETY_REVIEWER",
            "decision": "REJECTED",
            "event_revision": "STALE-REVISION",
        }
    )

    result = _run_actual(case)
    finding = next(item for item in result.findings if item.rule_id == "QCI-R007")

    assert finding.status == CheckStatus.PASS


def test_approval_is_bound_to_exact_resolution_operations():
    case = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    approved = load_json(RESOLUTIONS / "R001_resolve_stale_sop.json")
    claims = _approval_claims(case, approved)
    tampered = copy.deepcopy(approved)
    tampered["operations"] = list(reversed(tampered["operations"]))
    with pytest.raises(ApprovalGateError, match="subject"):
        _replay(case, tampered, claims=claims)


def test_unknown_role_and_empty_patch_cannot_authorize_resolution():
    case = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    approved = load_json(RESOLUTIONS / "R001_resolve_stale_sop.json")

    claims = _approval_claims(case, approved)
    assertions = tuple(copy.deepcopy(item) for item in claims.assertions)
    assertions[0]["role_claim"] = "ATTACKER_CONTROLLED_ROLE"
    with pytest.raises(ApprovalGateError, match="role_claim is unsupported"):
        _replay(
            case,
            approved,
            claims=replace(claims, assertions=assertions),
        )

    empty_patch = copy.deepcopy(approved)
    empty_patch["operations"] = []
    empty_patch["approvals"] = []
    with pytest.raises(ApprovalGateError, match="contain operations"):
        _replay(case, empty_patch)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("case_id", "ANOTHER-CASE", "case/event"),
        ("title", "Same event, unapproved surrounding context", "case snapshot"),
    ],
)
def test_approval_cannot_be_reused_for_another_case_or_changed_context(field, value, message):
    approved_case = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    resolution = load_json(RESOLUTIONS / "R001_resolve_stale_sop.json")
    claims = _approval_claims(approved_case, resolution)
    changed_case = copy.deepcopy(approved_case)
    changed_case[field] = value
    with pytest.raises(ApprovalGateError, match="subject"):
        _replay(changed_case, resolution, claims=claims)


def test_approval_cannot_be_reused_for_another_event_id():
    approved_case = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    resolution = load_json(RESOLUTIONS / "R001_resolve_stale_sop.json")
    claims = _approval_claims(approved_case, resolution)
    changed_case = copy.deepcopy(approved_case)
    changed_case["event"]["event_id"] = "ECO-OTHER-EVENT"
    with pytest.raises(ApprovalGateError, match="subject"):
        _replay(changed_case, resolution, claims=claims)


def test_non_approved_or_incomplete_extra_approval_record_blocks_resolution():
    case = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    resolution = load_json(RESOLUTIONS / "R001_resolve_stale_sop.json")
    claims = _approval_claims(case, resolution)
    rejected = tuple(copy.deepcopy(item) for item in claims.assertions)
    rejected[0]["decision"] = "REJECTED"
    with pytest.raises(ApprovalGateError, match="decision"):
        _replay(case, resolution, claims=replace(claims, assertions=rejected))

    incomplete = tuple(copy.deepcopy(item) for item in claims.assertions)
    incomplete[0].pop("authorization_record_hash")
    with pytest.raises(ApprovalGateError, match="exact versioned key set"):
        _replay(case, resolution, claims=replace(claims, assertions=incomplete))


@pytest.mark.parametrize("description", [None, "", "   "])
def test_resolution_description_is_required_at_runtime(description):
    case = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    resolution = load_json(RESOLUTIONS / "R001_resolve_stale_sop.json")
    if description is None:
        resolution.pop("description")
    else:
        resolution["description"] = description
    with pytest.raises(ApprovalGateError, match="description|approval-free key set"):
        _replay(case, resolution)


def test_resolution_id_rejects_whitespace_at_runtime():
    case = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    resolution = load_json(RESOLUTIONS / "R001_resolve_stale_sop.json")
    resolution["resolution_id"] = "   "
    with pytest.raises(ApprovalGateError, match="resolution_id"):
        _replay(case, resolution)


@pytest.mark.parametrize("target", ["event", "case"])
def test_resolution_cannot_modify_case_or_event_security_context(target):
    case = load_case(CASE)
    case["event"]["risk_level"] = "MEDIUM"
    path = "risk_level" if target == "event" else "event.risk_level"
    resolution = _bind_resolution(
        case,
        {
            "resolution_id": f"RES-RECLASSIFY-{target.upper()}",
            "description": "Attempt to raise risk inside a document resolution",
            "operations": [
                {"op": "set", "target": target, "path": path, "value": "HIGH"}
            ],
        },
        roles=("PROCESS_OWNER",),
    )
    with pytest.raises(ApprovalGateError, match="modify documents only"):
        _replay(case, resolution)


def test_resolved_case_is_validated_before_release_or_baseline():
    case = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    resolution = _bind_resolution(
        case,
        {
            "resolution_id": "RES-INVALID-AFTER",
            "description": "Attempt to remove the sole approved SOP",
            "operations": [
                {
                    "op": "set",
                    "document_id": "SOP-AXLE-SYN",
                    "path": "status",
                    "value": "DRAFT",
                }
            ],
        },
    )
    with pytest.raises(
        (ApprovalGateError, RevisionArtifactError), match="exactly cover"
    ):
        _replay(case, resolution)
