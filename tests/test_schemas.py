import copy
import json
from pathlib import Path

import pytest

from qualityci.controlled_references import load_controlled_reference_bundle
from qualityci.engine import run_case, run_case_with_reference_bundle
from qualityci.loader import load_case


ROOT = Path(__file__).parents[1]


def test_json_schemas_are_valid_json_with_required_contracts():
    expected = {
        "case.schema.json": {"case_id", "synthetic_for_competition", "event", "documents"},
        "controlled-reference-pack.schema.json": {"contract_version", "documents"},
        "case-source-pack.schema.json": {
            "manifest_version", "case", "event", "documents",
        },
        "case-source-set.schema.json": {
            "source_set_hash", "source_set_contract_version",
            "source_pack_contract_version", "builder_manifest", "members",
        },
        "case-source-lineage.schema.json": {
            "contract_version", "lineage_hash", "root_binding_hash",
            "parent_lineage_hash", "input_case_hash", "operation_kind",
            "operation_contract_version", "operation_material_hash",
            "operation_material", "output_case_hash",
        },
        "run-result.schema.json": {
            "run_id",
            "case_id",
            "case_hash",
            "ruleset_version",
            "reference_assurance_state",
            "reference_set_hash",
            "reference_contract_version",
            "validation_assurance_state",
            "validation_evidence_set_hash",
            "validation_evidence_contract_version",
            "overall_status",
            "impact_plan",
            "findings",
        },
        "validation-evidence-pack.schema.json": {
            "contract_version", "phase", "members"
        },
        "validation-report.schema.json": {
            "case_schema_version", "case_subject_hash", "claim", "event_id",
            "event_revision", "evidence_id", "evidence_type", "issued_at",
            "issuer_id", "issuer_role", "locator", "performed_at", "result",
            "ruleset_version", "scope_digest", "summary"
        },
        "validation-approval-policy.schema.json": {
            "contract_version", "validation_evidence_contract_version",
            "required_phases", "source_case_subject_hash",
            "source_scope_digest", "resolved_case_subject_hash",
            "resolved_scope_digest"
        },
        "approval-subject.schema.json": {
            "contract_version", "purpose_code", "scope_code", "purpose_text",
            "purpose_text_hash", "resolution_id", "resolution_description_hash",
            "operations_hash", "case_id", "event_id", "event_revision",
            "pre_case_subject_hash", "artifact_subject_hash",
            "controlled_reference_policy_hash", "validation_approval_policy_hash",
            "approval_policy_version", "required_role_claims", "use_policy",
            "execution_nonce",
        },
        "approval-assertion.schema.json": {
            "assertion_contract_version", "approval_id", "approval_subject_hash",
            "decision", "approver_id_claim", "role_claim",
            "authorization_record_id", "authorization_record_hash", "issued_at",
            "effective_from", "expires_at",
        },
        "authorization-record.schema.json": {
            "contract_version", "record_id", "approver_id_claim", "role_claim",
            "purpose_code", "scope_code", "effective_from", "expires_at",
        },
        "authorization-record-pack.schema.json": {
            "contract_version", "bundle_id", "members",
        },
        "authorization-trust-snapshot.schema.json": {
            "contract_version", "snapshot_id", "snapshot_sequence", "issued_at",
            "trust_domain", "anchor_id", "signature_algorithm", "issuer_keys",
            "signature",
        },
        "authorization-authenticity-decision.schema.json": {
            "contract_version", "state", "reason_code",
            "authorization_record_set_hash",
            "authorization_record_set_contract_version", "trust_snapshot_hash",
            "trust_snapshot_contract_version", "trust_policy_hash",
            "trust_policy_version", "authorization_authenticity_context_hash",
        },
        "approval-consumption.schema.json": {
            "contract_version", "approval_subject_hash", "assertion_set_hash",
            "authorization_record_set_hash", "execution_nonce", "use_policy",
            "replay_admission_hash", "after_case_hash", "after_run_id",
        },
        "baseline-approval-binding.schema.json": {
            "contract_version", "baseline_id", "baseline_hash",
            "after_case_hash", "after_run_id", "resolution_id",
            "artifact_set_hash", "approval_subject_hash", "assertion_hashes",
            "assertion_set_hash", "authorization_record_set_hash",
        },
        "replay-approval-expectation.schema.json": {
            "contract_version", "resolution_id", "after_case_hash",
            "after_run_id", "artifact_set_hash", "approval_subject_hash",
            "assertion_hashes", "assertion_set_hash",
            "authorization_record_set_hash", "consumption_hash",
            "replay_admission_hash", "baseline", "baseline_binding_hash",
        },
        "replay-validation-binding.schema.json": {
            "contract_version", "resolution_id", "source_case_hash",
            "after_case_hash", "after_run_id", "source_evidence_set_hash",
            "source_case_subject_hash", "source_scope_digest",
            "resolved_evidence_set_hash", "resolved_case_subject_hash",
            "resolved_scope_digest", "evidence_pair_hash",
            "replay_admission_hash", "ruleset_version",
            "validation_contract_version"
        },
        "mutation.schema.json": {"mutation_id", "description", "operations", "expected_rule_statuses"},
        "resolution.schema.json": {"resolution_id", "description", "approvals", "operations"},
        "proposal-preview.schema.json": {
            "state",
            "trusted",
            "eligible_for_baseline",
            "resolution_id",
            "proposal_id",
            "preview_findings",
        },
        "revision-artifact-manifest.schema.json": {
            "manifest_version",
            "replacement_set_id",
            "case_schema_version",
            "parser_contract_version",
            "mapping_contract_version",
            "security_root_policy_version",
            "documents",
        },
        "replay-admission.schema.json": {
            "replay_admission_hash",
            "contract_version",
            "resolution_id",
            "resolution_hash",
            "assurance_state",
            "artifact_set_hash",
            "controlled_reference_set_hash",
            "controlled_reference_source_set_hash",
            "pre_case",
            "before_case",
            "before_run",
            "after_case",
            "after_run",
            "approval_subject",
            "approval_subject_hash",
            "approved_patch_hash",
            "approval_refs",
            "baseline",
            "ruleset_versions",
            "reference_contract_version",
        },
        "revision-artifact-subject.schema.json": {
            "replacement_set_id",
            "artifact_set_hash",
            "controlled_reference_set_hash",
            "controlled_reference_source_set_hash",
            "artifact_contract_version",
            "case_schema_version",
            "parser_contract_version",
            "mapping_contract_version",
            "security_root_policy_version",
            "reference_contract_version",
            "touched_document_artifacts",
        },
        "replay-ledger.schema.json": {
            "contract_version",
            "replay_admission_hash",
            "assurance_state",
            "resolution_id",
            "artifact_set_hash",
            "controlled_reference_set_hash",
            "controlled_reference_source_set_hash",
            "approved_case_hash",
            "before_run",
            "after_case",
            "after_run",
            "baseline",
        },
    }
    for name, required in expected.items():
        schema = json.loads((ROOT / "schemas" / name).read_text("utf-8"))
        assert schema["$schema"].endswith("2020-12/schema")
        assert required.issubset(schema["required"])


def test_a06_core_schemas_accept_exact_public_assets_and_sealed_decision():
    jsonschema = pytest.importorskip("jsonschema")

    from qualityci.authorization_authenticity import (
        load_authorization_trust_snapshot_bundle,
        prepare_authorization_authenticity_context,
    )
    from qualityci.authorization_records import load_authorization_record_bundle

    fixture = ROOT / "tests/fixtures/authorization_authenticity"
    record_schema = json.loads(
        (ROOT / "schemas/authorization-record.schema.json").read_text("utf-8")
    )
    pack_schema = json.loads(
        (ROOT / "schemas/authorization-record-pack.schema.json").read_text("utf-8")
    )
    snapshot_schema = json.loads(
        (ROOT / "schemas/authorization-trust-snapshot.schema.json").read_text("utf-8")
    )
    decision_schema = json.loads(
        (ROOT / "schemas/authorization-authenticity-decision.schema.json").read_text("utf-8")
    )
    schemas = (record_schema, pack_schema, snapshot_schema, decision_schema)
    for schema in schemas:
        jsonschema.Draft202012Validator.check_schema(schema)

    format_checker = jsonschema.FormatChecker()
    record_validator = jsonschema.Draft202012Validator(
        record_schema, format_checker=format_checker
    )
    pack_validator = jsonschema.Draft202012Validator(
        pack_schema, format_checker=format_checker
    )
    snapshot_validator = jsonschema.Draft202012Validator(
        snapshot_schema, format_checker=format_checker
    )
    decision_validator = jsonschema.Draft202012Validator(
        decision_schema, format_checker=format_checker
    )

    manifest = json.loads((fixture / "manifest.json").read_bytes())
    snapshot = json.loads((fixture / "trust_snapshot.json").read_bytes())
    pack_validator.validate(manifest)
    snapshot_validator.validate(snapshot)
    records = []
    for name in ("process_owner.json", "quality_manager.json"):
        record = json.loads((fixture / name).read_bytes())
        record_validator.validate(record)
        records.append(record)

    context = prepare_authorization_authenticity_context(
        load_authorization_record_bundle(fixture / "manifest.json"),
        load_authorization_trust_snapshot_bundle(fixture / "trust_snapshot.json"),
    )
    decision = {
        "contract_version": context.contract_version,
        "state": context.state,
        "reason_code": context.reason_code,
        "authorization_record_set_hash": context.authorization_record_set_hash,
        "authorization_record_set_contract_version": (
            context.authorization_record_set_contract_version
        ),
        "trust_snapshot_hash": context.trust_snapshot_hash,
        "trust_snapshot_contract_version": context.trust_snapshot_contract_version,
        "trust_policy_hash": context.trust_policy_hash,
        "trust_policy_version": context.trust_policy_version,
        "authorization_authenticity_context_hash": (
            context.authorization_authenticity_context_hash
        ),
    }
    decision_validator.validate(decision)

    invalid_pack = copy.deepcopy(manifest)
    invalid_pack["members"][0]["content_hash"] += "\n"
    with pytest.raises(jsonschema.ValidationError):
        pack_validator.validate(invalid_pack)

    for field in ("signature", "issued_at"):
        invalid_record = copy.deepcopy(records[0])
        invalid_record[field] += "\n"
        with pytest.raises(jsonschema.ValidationError):
            record_validator.validate(invalid_record)

    for mutator in (
        lambda item: item.__setitem__("signature", item["signature"] + "\n"),
        lambda item: item.__setitem__("issued_at", item["issued_at"] + "\n"),
        lambda item: item["issuer_keys"][0].__setitem__(
            "public_key", item["issuer_keys"][0]["public_key"] + "\n"
        ),
        lambda item: item["issuer_keys"][0].__setitem__(
            "effective_from", item["issuer_keys"][0]["effective_from"] + "\n"
        ),
    ):
        invalid_snapshot = copy.deepcopy(snapshot)
        mutator(invalid_snapshot)
        with pytest.raises(jsonschema.ValidationError):
            snapshot_validator.validate(invalid_snapshot)

    for field in (
        "authorization_record_set_hash",
        "trust_snapshot_hash",
        "trust_policy_hash",
        "authorization_authenticity_context_hash",
    ):
        invalid_decision = copy.deepcopy(decision)
        invalid_decision[field] += "\n"
        with pytest.raises(jsonschema.ValidationError):
            decision_validator.validate(invalid_decision)


def test_schema_contracts_encode_fail_closed_boundaries():
    case = json.loads((ROOT / "schemas/case.schema.json").read_text("utf-8"))
    event = case["$defs"]["event"]
    assert "risk_level" in event["required"]
    assert set(event["properties"]["risk_level"]["enum"]) == {"LOW", "MEDIUM", "HIGH"}
    document_constraints = case["properties"]["documents"]["allOf"]
    assert len(document_constraints) == 5
    assert all(item["minContains"] == item["maxContains"] == 1 for item in document_constraints)
    characteristics = case["$defs"]["document"]["properties"]["fields"]["properties"]["characteristics"]
    assert characteristics["x-uniqueBy"] == "characteristic_id"
    characteristic = case["$defs"]["characteristic"]
    assert "specification" not in characteristic["required"]
    assert "required" not in characteristic["properties"]["specification"]
    assert characteristic["properties"]["specification"]["properties"]["unit"] == {
        "type": "string"
    }
    assert case["$defs"]["document"]["properties"]["approved_waiver"] == {
        "$ref": "#/$defs/waiver"
    }
    assert "required" not in case["$defs"]["waiver"]
    waiver_locator = case["$defs"]["waiver"]["properties"]["locator"]
    assert waiver_locator == {"type": "string"}
    source_hash = case["$defs"]["document"]["properties"]["source_hash"]
    assert source_hash["minLength"] == 1
    assert source_hash["maxLength"] == 256
    timestamp_pattern = (
        "^[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):"
        "[0-5][0-9]:[0-5][0-9](?:\\.[0-9]+)?Z$"
    )
    approval_subject = json.loads(
        (ROOT / "schemas/approval-subject.schema.json").read_text("utf-8")
    )
    assert approval_subject["additionalProperties"] is False
    assert approval_subject["properties"]["contract_version"] == {
        "enum": [
            "qualityci-approval-subject-0.1",
            "qualityci-approval-subject-0.2",
        ]
    }
    version_dispatch = approval_subject["allOf"][0]
    assert version_dispatch["if"]["properties"]["contract_version"] == {
        "const": "qualityci-approval-subject-0.2"
    }
    assert version_dispatch["then"] == {"required": ["pre_case_source"]}
    assert version_dispatch["else"] == {
        "not": {"required": ["pre_case_source"]}
    }
    assert approval_subject["properties"]["purpose_code"] == {
        "const": "APPLY_APPROVED_RESOLUTION"
    }
    assert approval_subject["properties"]["scope_code"] == {
        "const": "EXACT_SUBJECT"
    }
    assert approval_subject["properties"]["use_policy"] == {
        "const": "SINGLE_REPLAY"
    }
    assert approval_subject["properties"]["required_role_claims"] == {
        "type": "array",
        "minItems": 2,
        "maxItems": 2,
        "uniqueItems": True,
        "prefixItems": [
            {"const": "PROCESS_OWNER"},
            {"const": "QUALITY_MANAGER"},
        ],
        "items": False,
    }
    for field in (
        "purpose_text_hash", "resolution_description_hash", "operations_hash",
        "pre_case_subject_hash", "artifact_subject_hash",
        "controlled_reference_policy_hash", "validation_approval_policy_hash",
    ):
        assert approval_subject["properties"][field]["pattern"] == "^[0-9a-f]{64}$"

    approval_assertion = json.loads(
        (ROOT / "schemas/approval-assertion.schema.json").read_text("utf-8")
    )
    assert approval_assertion["additionalProperties"] is False
    assert approval_assertion["properties"]["assertion_contract_version"] == {
        "const": "qualityci-approval-assertion-0.1"
    }
    assert approval_assertion["properties"]["decision"] == {
        "const": "APPROVED"
    }
    for field in ("issued_at", "effective_from", "expires_at"):
        assert approval_assertion["properties"][field] == {
            "type": "string",
            "format": "date-time",
            "pattern": timestamp_pattern,
        }
    a05_sidecar_contracts = {
        "approval-consumption.schema.json": (
            "qualityci-approval-consumption-0.1",
            {
                "approval_subject_hash", "assertion_set_hash",
                "authorization_record_set_hash", "replay_admission_hash",
                "after_case_hash",
            },
        ),
        "baseline-approval-binding.schema.json": (
            "qualityci-baseline-approval-binding-0.1",
            {
                "baseline_hash", "after_case_hash", "artifact_set_hash",
                "approval_subject_hash", "assertion_set_hash",
                "authorization_record_set_hash",
            },
        ),
        "replay-approval-expectation.schema.json": (
            "qualityci-replay-approval-expectation-0.1",
            {
                "after_case_hash", "artifact_set_hash",
                "approval_subject_hash", "assertion_set_hash",
                "authorization_record_set_hash", "consumption_hash",
                "replay_admission_hash",
            },
        ),
    }
    for name, (version, hash_fields) in a05_sidecar_contracts.items():
        schema = json.loads((ROOT / "schemas" / name).read_text("utf-8"))
        assert schema["additionalProperties"] is False
        contract = schema["properties"]["contract_version"]
        assert set(contract.get("enum", [contract.get("const")])) == {
            version,
            version[:-3] + "0.2",
        }
        for field in hash_fields:
            assert schema["properties"][field]["pattern"] == "^[0-9a-f]{64}$"

    replay_admission = json.loads(
        (ROOT / "schemas/replay-admission.schema.json").read_text("utf-8")
    )
    replay_ledger = json.loads(
        (ROOT / "schemas/replay-ledger.schema.json").read_text("utf-8")
    )
    admission_native_required = set(
        replay_admission["allOf"][0]["then"]["required"]
    )
    assert admission_native_required == {
        "authorization_record_set_hash", "approval_assertion_set_hash",
        "execution_nonce", "use_policy",
    }
    ledger_native_required = set(replay_ledger["allOf"][0]["then"]["required"])
    assert ledger_native_required == {
        "approval_subject_hash", "approval_assertion_set_hash",
        "authorization_record_set_hash", "execution_nonce", "use_policy",
        "consumption_hash",
    }
    required_evidence = case["$defs"]["validationPlan"]["properties"][
        "required_evidence"
    ]["items"]["properties"]
    for field in ("valid_from", "valid_until"):
        assert required_evidence[field] == {
            "type": "string",
            "format": "date-time",
            "pattern": timestamp_pattern,
        }
    validation_report = json.loads(
        (ROOT / "schemas/validation-report.schema.json").read_text("utf-8")
    )
    for field in ("performed_at", "issued_at"):
        assert validation_report["properties"][field] == {
            "type": "string",
            "format": "date-time",
            "pattern": timestamp_pattern,
        }

    mutation = json.loads((ROOT / "schemas/mutation.schema.json").read_text("utf-8"))
    truth = mutation["properties"]["expected_rule_statuses"]
    assert truth["minProperties"] == truth["maxProperties"] == 7
    assert mutation["properties"]["operations"]["items"]["allOf"]

    resolution = json.loads((ROOT / "schemas/resolution.schema.json").read_text("utf-8"))
    approval = resolution["properties"]["approvals"]["items"]
    assert "approved_patch_hash" in approval["required"]
    assert {"case_id", "event_id", "approved_case_hash"}.issubset(approval["required"])
    assert approval["properties"]["approved_case_hash"]["pattern"] == "^[0-9a-f]{64}$"
    assert approval["properties"]["approved_patch_hash"]["pattern"] == "^[0-9a-f]{64}$"
    assert set(approval["properties"]["role"]["enum"]) == {
        "QUALITY_MANAGER",
        "PROCESS_OWNER",
    }
    resolution_operation = resolution["properties"]["operations"]["items"]
    assert resolution_operation["allOf"][1]["properties"]["target"] == {
        "const": "document"
    }

    preview = json.loads((ROOT / "schemas/proposal-preview.schema.json").read_text("utf-8"))
    assert preview["additionalProperties"] is False
    assert preview["properties"]["state"] == {"const": "PROPOSED_UNATTESTED"}
    assert preview["properties"]["trusted"] == {"const": False}
    assert preview["properties"]["eligible_for_baseline"] == {"const": False}
    forbidden_actual_fields = {
        item["required"][0] for item in preview["not"]["anyOf"]
    }
    assert forbidden_actual_fields == {"overall_status", "run_id", "case_hash", "baseline"}

    manifest = json.loads(
        (ROOT / "schemas/revision-artifact-manifest.schema.json").read_text("utf-8")
    )
    assert manifest["additionalProperties"] is False
    member = manifest["properties"]["documents"]["items"]
    assert member["additionalProperties"] is False
    assert "source_hash" not in member["properties"]
    assert "mapping_provenance" not in member["properties"]
    assert manifest["properties"]["documents"]["maxItems"] == 128


def test_run_result_schema_and_runtime_share_reference_identity_surface():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "schemas/run-result.schema.json").read_text("utf-8"))
    base = ROOT / "datasets/qualityci-bench/tacoma_24v152"
    case = load_case(base / "baseline.json")
    untrusted = run_case(case).to_dict()
    attested = run_case_with_reference_bundle(
        case,
        load_controlled_reference_bundle(base / "reference_sources/manifest.json"),
    ).to_dict()
    current_profile = {
        "run_result_contract_version",
        "run_identity_version",
        "case_source_assurance_state",
        "case_source_pack_contract_version",
        "case_source_set_contract_version",
        "case_source_set_hash",
        "case_source_binding_hash",
        "case_source_lineage_contract_version",
        "case_source_lineage_hash",
    }
    assert set(untrusted) == set(schema["required"]) | current_profile
    assert set(attested) == set(schema["required"]) | current_profile
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(untrusted)
    validator.validate(attested)
    assert untrusted["run_result_contract_version"] == "qualityci-run-result-0.2"
    assert untrusted["run_identity_version"] == "qualityci-run-identity-v4"
    assert untrusted["case_source_assurance_state"] == "UNBOUND_SERIALIZED_CASE"
    assert all(
        untrusted[field] is None
        for field in current_profile
        - {
            "run_result_contract_version",
            "run_identity_version",
            "case_source_assurance_state",
        }
    )
    assert untrusted["reference_assurance_state"] == "UNATTESTED_JSON"
    assert untrusted["reference_set_hash"] is None
    assert untrusted["reference_contract_version"] is None
    assert attested["reference_assurance_state"] == "ATTESTED_REFERENCE_SET"
    assert len(attested["reference_set_hash"]) == 64
    assert (
        attested["reference_contract_version"]
        == "qualityci-controlled-reference-0.1"
    )
