import copy
import json
from pathlib import Path

import pytest

from qualityci.engine import run_case
from qualityci.loader import (
    MAX_APPROVAL_ITEMS,
    MAX_CHARACTERISTICS_PER_DOCUMENT,
    MAX_DOCUMENTS,
    MAX_EVENT_AFFECTED_ITEMS,
    MAX_JSON_FILE_BYTES,
    MAX_MUTATION_OPERATIONS,
    MAX_PROCESS_STEPS_PER_DOCUMENT,
    MAX_RISKS_PER_DOCUMENT,
    MAX_SOURCE_ANCHOR_CHARACTERS,
    MAX_VALIDATION_EVIDENCE_ITEMS,
    apply_mutation,
    canonical_hash,
    load_case,
    load_json,
    validate_case,
    _require_string_list,
)
from qualityci.models import CheckStatus


ROOT = Path(__file__).parents[1]
CASE = ROOT / "datasets/qualityci-bench/tacoma_24v152/baseline.json"
MUTATIONS = ROOT / "datasets/qualityci-bench/tacoma_24v152/mutations"


def _finding(case, rule_id):
    return next(item for item in run_case(case).findings if item.rule_id == rule_id)


def _document(case, document_type):
    return next(item for item in case["documents"] if item["document_type"] == document_type)


@pytest.mark.parametrize(
    ("value", "maximum", "message"),
    [
        ([1], 10, "non-empty strings"),
        ([""], 10, "non-empty strings"),
        (["A", "B"], 1, "maximum"),
    ],
)
def test_string_list_guard_rejects_invalid_elements_and_over_limit(
    value, maximum, message
):
    with pytest.raises(ValueError, match=message):
        _require_string_list(value, "guarded list", maximum)


def test_required_document_type_needs_exactly_one_approved_document():
    no_approved = load_case(CASE)
    _document(no_approved, "SOP")["status"] = "DRAFT"
    with pytest.raises(ValueError, match="exactly one APPROVED"):
        run_case(no_approved)

    duplicate = load_case(CASE)
    second = copy.deepcopy(_document(duplicate, "SOP"))
    second["document_id"] = "SOP-AXLE-SYN-DUPLICATE"
    duplicate["documents"].append(second)
    with pytest.raises(ValueError, match="exactly one APPROVED"):
        run_case(duplicate)


def test_historical_superseded_document_is_allowed_and_not_checked_by_date_gate():
    case = load_case(CASE)
    historical = copy.deepcopy(_document(case, "SOP"))
    historical.update(
        document_id="SOP-AXLE-SYN-HISTORICAL",
        revision="A0",
        status="SUPERSEDED",
        revision_date="2020-01-01",
    )
    case["documents"].append(historical)
    finding = _finding(case, "QCI-R004")
    assert finding.status == CheckStatus.PASS
    assert all(item.document_id != historical["document_id"] for item in finding.evidence)


def test_structured_waiver_is_traceable_and_boolean_waiver_is_rejected():
    waived = load_case(CASE, MUTATIONS / "M018_approved_waiver_boundary.json")
    finding = _finding(waived, "QCI-R004")
    assert finding.status == CheckStatus.PASS
    assert any(item.locator == "WaiverRegister#WVR-SYN-001" for item in finding.evidence)

    boolean_waiver = load_case(CASE)
    _document(boolean_waiver, "PROCESS_FLOW")["approved_waiver"] = True
    with pytest.raises(ValueError, match="approved_waiver must be an object"):
        run_case(boolean_waiver)


def test_incomplete_waiver_is_a_business_contradiction_not_a_shape_error():
    case = load_case(CASE)
    process_flow = _document(case, "PROCESS_FLOW")
    process_flow["revision_date"] = "2024-01-01"
    process_flow["approved_waiver"] = {"waiver_id": "WVR-INCOMPLETE"}
    assert _finding(case, "QCI-R004").status == CheckStatus.CONTRADICTED


def test_duplicate_characteristic_id_is_rejected_even_when_payloads_differ():
    case = load_case(CASE)
    control = _document(case, "CONTROL_PLAN")
    duplicate = copy.deepcopy(control["fields"]["characteristics"][0])
    duplicate["specification"]["maximum"] = 1
    control["fields"]["characteristics"].append(duplicate)
    with pytest.raises(ValueError, match="duplicate characteristic_id"):
        run_case(case)


@pytest.mark.parametrize(
    "specification",
    [
        {},
        {"target": 0, "minimum": 0, "maximum": 0},
        {"target": 0, "minimum": 0, "maximum": 0, "unit": "   "},
        {"target": 2, "minimum": 0, "maximum": 1, "unit": "mm"},
    ],
)
def test_incomplete_or_invalid_impacted_specs_are_unverifiable_not_pass(specification):
    case = load_case(CASE)
    for document_type in ("CONTROL_PLAN", "SOP", "INSPECTION_RECORD"):
        item = _document(case, document_type)["fields"]["characteristics"][0]
        item["specification"] = copy.deepcopy(specification)
    assert _finding(case, "QCI-R002").status == CheckStatus.UNVERIFIABLE


def test_structurally_invalid_spec_number_is_rejected():
    case = load_case(CASE)
    _document(case, "SOP")["fields"]["characteristics"][0]["specification"]["target"] = "zero"
    with pytest.raises(ValueError, match="finite number"):
        run_case(case)


def test_process_flow_participates_in_affected_step_coverage():
    case = load_case(CASE)
    _document(case, "PROCESS_FLOW")["fields"]["process_steps"].remove("WELD-10")
    assert _finding(case, "QCI-R001").status == CheckStatus.CONTRADICTED


def test_empty_pfmea_risks_are_unverifiable_but_explicit_non_special_is_valid():
    missing = load_case(CASE)
    _document(missing, "PFMEA")["fields"]["risks"] = []
    assert _finding(missing, "QCI-R003").status == CheckStatus.UNVERIFIABLE

    non_special = load_case(CASE, MUTATIONS / "M016_non_special_characteristic_boundary.json")
    assert _finding(non_special, "QCI-R003").status == CheckStatus.PASS


def test_r003_ignores_special_characteristics_outside_the_current_event_scope():
    case = load_case(CASE)
    pfmea = _document(case, "PFMEA")
    pfmea["fields"]["risks"].append(
        {
            "failure_mode_id": "FM-UNRELATED",
            "process_step_id": "WELD-10",
            "characteristic_id": "CTQ-UNRELATED",
            "special_characteristic": True,
            "locator": "PFMEA!row-999",
        }
    )

    finding = _finding(case, "QCI-R003")
    assert finding.status == CheckStatus.PASS
    assert all(item.locator != "PFMEA!row-999" for item in finding.evidence)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda case: case.update(case_id=" "), "case_id"),
        (lambda case: _document(case, "SOP").update(owner=""), "owner"),
        (lambda case: _document(case, "SOP").update(revision_date="2024-99-01"), "ISO"),
        (lambda case: _document(case, "SOP").update(revision_date="20240101"), "YYYY-MM-DD"),
        (lambda case: _document(case, "SOP").update(revision_date="2024-W01-1"), "YYYY-MM-DD"),
        (
            lambda case: _document(case, "PFMEA")["fields"].update(process_steps="WELD-10"),
            "process_steps",
        ),
        (
            lambda case: case["event"]["validation_evidence"][0].update(result="UNKNOWN"),
            "result",
        ),
        (
            lambda case: case["event"]["validation_evidence"][0].update(evidence_id="   "),
            "evidence_id",
        ),
        (
            lambda case: case["event"]["approvals"][0].update(decision="MAYBE"),
            "decision",
        ),
        (
            lambda case: case["event"]["approvals"][0].update(role="   "),
            "role",
        ),
        (
            lambda case: case["event"]["approvals"][0].update(event_revision="   "),
            "event_revision",
        ),
        (
            lambda case: _document(case, "CONTROL_PLAN")["fields"]["characteristics"][0].update(
                reaction_plan=123
            ),
            "reaction_plan",
        ),
        (
            lambda case: _document(case, "CONTROL_PLAN")["fields"]["characteristics"][0].update(
                characteristic_id="   "
            ),
            "characteristic_id",
        ),
    ],
)
def test_structural_runtime_validation_rejects_malformed_fields(mutator, message):
    case = load_case(CASE)
    mutator(case)
    with pytest.raises(ValueError, match=message):
        run_case(case)


def test_event_approval_role_and_revision_subject_must_be_unique():
    case = load_case(CASE)
    duplicate = copy.deepcopy(case["event"]["approvals"][0])
    duplicate["decision"] = "REJECTED"
    case["event"]["approvals"].append(duplicate)

    with pytest.raises(ValueError, match=r"unique role \+ event_revision"):
        run_case(case)


def test_case_schema_marks_identity_fields_as_nonblank():
    schema = json.loads((ROOT / "schemas/case.schema.json").read_text("utf-8"))
    nonblank_pattern = r".*\S.*"
    validation = schema["$defs"]["validationEvidence"]["properties"]
    approvals = schema["$defs"]["event"]["properties"]["approvals"]

    assert validation["evidence_id"]["pattern"] == nonblank_pattern
    assert approvals["x-uniqueBy"] == ["role", "event_revision"]


@pytest.mark.parametrize("field", ["control_method", "frequency", "reaction_plan"])
def test_whitespace_control_content_is_a_rule_contradiction(field):
    case = load_case(CASE)
    _document(case, "CONTROL_PLAN")["fields"]["characteristics"][0][field] = "   "

    finding = _finding(case, "QCI-R003")

    assert finding.status == CheckStatus.CONTRADICTED


def test_legacy_validation_locator_never_self_attests_even_when_malformed():
    case = load_case(CASE)
    case["event"]["validation_evidence"][0]["locator"] = "   "

    finding = _finding(case, "QCI-R006")

    assert finding.status == CheckStatus.UNVERIFIABLE
    assert "VALIDATION_CONTEXT_REQUIRED" in finding.summary


@pytest.mark.parametrize("field", ["waiver_id", "locator"])
def test_whitespace_waiver_content_cannot_authorize_a_stale_document(field):
    case = load_case(CASE)
    process_flow = _document(case, "PROCESS_FLOW")
    process_flow["revision_date"] = "2024-01-01"
    process_flow["approved_waiver"] = {
        "waiver_id": "WVR-001",
        "document_id": process_flow["document_id"],
        "event_revision": case["event"]["revision"],
        "scope": "REVISION_DATE_EXCEPTION",
        "approved_roles": ["QUALITY_MANAGER", "PROCESS_OWNER"],
        "valid_from": "2024-02-01",
        "valid_until": "2024-03-01",
        "locator": "WAIVER#1",
    }
    process_flow["approved_waiver"][field] = "   "

    finding = _finding(case, "QCI-R004")

    assert finding.status == CheckStatus.CONTRADICTED


def test_semantically_identical_dict_key_order_produces_identical_run_result():
    original = load_case(CASE, MUTATIONS / "M001_stale_sop_conflict.json")
    reordered = json.loads(json.dumps(original, ensure_ascii=False, sort_keys=True))
    assert run_case(original).to_dict() == run_case(reordered).to_dict()


@pytest.mark.parametrize(
    "payload",
    [
        '{"decision":"REJECTED","decision":"APPROVED"}',
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"value":-Infinity}',
        '{"value":1e999}',
    ],
)
def test_strict_json_rejects_duplicate_keys_and_non_finite_numbers(tmp_path, payload):
    source = tmp_path / "ambiguous.json"
    source.write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError):
        load_json(source)


def test_json_file_size_limit_accepts_boundary_and_rejects_one_byte_over(tmp_path):
    prefix = '{"padding":"'
    suffix = '"}'
    payload = prefix + "x" * (MAX_JSON_FILE_BYTES - len(prefix) - len(suffix)) + suffix
    source = tmp_path / "bounded.json"
    source.write_text(payload, encoding="utf-8")

    assert source.stat().st_size == MAX_JSON_FILE_BYTES
    assert load_json(source)["padding"].startswith("x")

    source.write_text(payload + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="byte input limit"):
        load_json(source)


@pytest.mark.parametrize("value", [None, "", "   "])
def test_document_source_anchor_is_required_and_nonblank(value):
    case = load_case(CASE)
    document = case["documents"][0]
    if value is None:
        document.pop("source_hash")
    else:
        document["source_hash"] = value

    with pytest.raises(ValueError, match="source_hash"):
        run_case(case)


def test_document_source_anchor_is_bounded():
    case = load_case(CASE)
    case["documents"][0]["source_hash"] = "x" * (MAX_SOURCE_ANCHOR_CHARACTERS + 1)

    with pytest.raises(ValueError, match="source_hash exceeds"):
        run_case(case)


def test_blank_inspection_reference_identity_is_a_loader_error():
    case = load_case(CASE)
    inspection = _document(case, "INSPECTION_RECORD")
    inspection["fields"]["references"]["SOP"] = "   "

    with pytest.raises(ValueError, match="native reference SOP must be an identity object"):
        run_case(case)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda case: case.update(documents=[{}] * (MAX_DOCUMENTS + 1)), "documents"),
        (
            lambda case: case["event"].update(
                affected_process_steps=["STEP"] * (MAX_EVENT_AFFECTED_ITEMS + 1)
            ),
            "affected_process_steps",
        ),
        (
            lambda case: case["event"].update(
                affected_characteristics=["CTQ"] * (MAX_EVENT_AFFECTED_ITEMS + 1)
            ),
            "affected_characteristics",
        ),
        (
            lambda case: case["event"].update(
                validation_evidence=[{}] * (MAX_VALIDATION_EVIDENCE_ITEMS + 1)
            ),
            "validation_evidence",
        ),
        (
            lambda case: case["event"].update(
                approvals=[{}] * (MAX_APPROVAL_ITEMS + 1)
            ),
            "approvals",
        ),
        (
            lambda case: _document(case, "PROCESS_FLOW")["fields"].update(
                process_steps=["STEP"] * (MAX_PROCESS_STEPS_PER_DOCUMENT + 1)
            ),
            "process_steps",
        ),
        (
            lambda case: _document(case, "CONTROL_PLAN")["fields"].update(
                characteristics=[{}] * (MAX_CHARACTERISTICS_PER_DOCUMENT + 1)
            ),
            "characteristics",
        ),
        (
            lambda case: _document(case, "PFMEA")["fields"].update(
                risks=[{}] * (MAX_RISKS_PER_DOCUMENT + 1)
            ),
            "risks",
        ),
    ],
)
def test_case_collection_limits_reject_one_item_over(mutator, message):
    case = load_case(CASE)
    mutator(case)

    with pytest.raises(ValueError, match=rf"{message}.*maximum"):
        validate_case(case)


def test_event_collection_limit_accepts_exact_boundary():
    case = load_case(CASE)
    case["event"]["affected_process_steps"] = [
        f"STEP-{index}" for index in range(MAX_EVENT_AFFECTED_ITEMS)
    ]
    case["event"]["affected_links"] = []

    validate_case(case)


def test_mutation_operation_limit_accepts_boundary_and_rejects_one_over():
    case = load_case(CASE)
    operation = {"op": "set", "target": "case", "path": "title", "value": "bounded"}
    mutation = {
        "mutation_id": "M-LIMIT",
        "operations": [operation] * MAX_MUTATION_OPERATIONS,
    }

    assert apply_mutation(case, mutation)["title"] == "bounded"

    mutation["operations"].append(operation)
    with pytest.raises(ValueError, match="mutation operations.*maximum"):
        apply_mutation(case, mutation)


def test_canonical_hash_rejects_non_finite_direct_python_values():
    with pytest.raises(ValueError, match="JSON compliant"):
        canonical_hash({"unknown_extension": float("nan")})
