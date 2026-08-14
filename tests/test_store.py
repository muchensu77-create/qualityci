import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from qualityci.controlled_references import load_controlled_reference_bundle
from qualityci.engine import run_case
from qualityci.loader import canonical_hash, load_case, load_json
from qualityci.revision_artifacts import load_revision_artifact_bundle
from qualityci.store import QualityCIStore, StoreIntegrityError
from qualityci.workflow import (
    StatelessApprovalReplayResult,
    resolution_patch_hash_for_subject,
)
from qualityci.validation_evidence import load_validation_evidence_bundle
from a05_support import native_approval_claims, native_approval_replay


ROOT = Path(__file__).parents[1]
BASE = ROOT / "datasets/qualityci-bench/tacoma_24v152"
_NATIVE_REPLAYS = {}


def _bundle():
    return load_revision_artifact_bundle(
        BASE / "replacement_artifacts/R001/manifest.json"
    )


def _reference_bundle():
    return load_controlled_reference_bundle(BASE / "reference_sources/manifest.json")


def _source_validation_bundle():
    return load_validation_evidence_bundle(
        BASE / "validation_sources/R001/source/manifest.json"
    )


def _resolved_validation_bundle():
    return load_validation_evidence_bundle(
        BASE / "validation_sources/R001/resolved/manifest.json"
    )


def _m001_case():
    return load_case(
        BASE / "baseline_v04.json",
        BASE / "mutations/M001_stale_sop_conflict.json",
    )


def _replay(case, resolution):
    claims = native_approval_claims(
        case,
        resolution,
        artifact_bundle=_bundle(),
        reference_bundle=_reference_bundle(),
    )
    envelope = native_approval_replay(
        case,
        resolution,
        artifact_bundle=_bundle(),
        reference_bundle=_reference_bundle(),
        source_validation_bundle=_source_validation_bundle(),
        resolved_validation_bundle=_resolved_validation_bundle(),
        claims=claims,
    )
    replay = envelope.replay
    _NATIVE_REPLAYS[_replay_key(replay)] = (envelope, claims)
    return replay


def _replay_key(replay):
    return (
        replay.resolution_id,
        replay.before.case_hash,
        replay.after.case_hash,
        replay.artifact_set_hash,
        replay.validation_evidence_pair_hash,
    )


def _native_replay_inputs(replay):
    return _NATIVE_REPLAYS[_replay_key(replay)]


def _save_replay(store, replay, resolution):
    envelope, claims = _native_replay_inputs(replay)
    return store.save_native_replay(
        StatelessApprovalReplayResult(
            replay=replay,
            replay_approval=envelope.replay_approval,
        ),
        claims.resolution,
        approval_subject=claims.subject,
        approval_assertions=list(claims.assertions),
        authorization_bundle=claims.authorization_bundle,
        authorization_trust_bundle=claims.authorization_trust_bundle,
        artifact_bundle=_bundle(),
        reference_bundle=_reference_bundle(),
        source_validation_bundle=_source_validation_bundle(),
        resolved_validation_bundle=_resolved_validation_bundle(),
    )


def _insert_raw_audited_run(store, result, payload):
    payload_json = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        allow_nan=False,
    )
    entity = {
        "run_id": result.run_id,
        "case_id": result.case_id,
        "status": str(result.overall_status),
        "ruleset_version": result.ruleset_version,
        "payload_json": payload_json,
    }
    with store.connection:
        store.connection.execute(
            "INSERT INTO runs(run_id, case_id, status, ruleset_version, payload_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                entity["run_id"],
                entity["case_id"],
                entity["status"],
                entity["ruleset_version"],
                entity["payload_json"],
            ),
        )
        store._append_audit(
            "run",
            result.run_id,
            "CHECK_RUN_RECORDED",
            {
                "primary_key": {"run_id": result.run_id},
                "entity_fingerprint": canonical_hash(entity),
            },
        )


def _canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        allow_nan=False,
    )


def _stored_approval_payload(resolution, approval, artifact_subject=None):
    payload = {
        key: approval[key]
        for key in (
            "role",
            "decision",
            "case_id",
            "event_id",
            "event_revision",
            "approved_case_hash",
            "approved_patch_hash",
        )
    }
    payload["resolution_id"] = resolution["resolution_id"]
    payload["operations"] = resolution["operations"]
    if artifact_subject is not None:
        payload["artifact_subject"] = artifact_subject
    if "comment" in approval:
        payload["comment"] = approval["comment"]
    return payload


def _insert_raw_audited_approval(store, payload, **row_overrides):
    row = {
        field: payload[field]
        for field in (
            "resolution_id",
            "case_id",
            "event_id",
            "event_revision",
            "approved_case_hash",
            "approved_patch_hash",
            "role",
            "decision",
        )
    }
    row.update(row_overrides)
    row["payload_json"] = _canonical_json(payload)
    entity_id = (
        f"{row['resolution_id']}@{row['case_id']}@{row['event_id']}@"
        f"{row['event_revision']}@{row['approved_case_hash']}@{row['role']}"
    )
    with store.connection:
        store.connection.execute(
            """INSERT INTO approvals
               (resolution_id, case_id, event_id, event_revision,
                approved_case_hash, approved_patch_hash, role, decision, payload_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            tuple(
                row[field]
                for field in (
                    "resolution_id",
                    "case_id",
                    "event_id",
                    "event_revision",
                    "approved_case_hash",
                    "approved_patch_hash",
                    "role",
                    "decision",
                    "payload_json",
                )
            ),
        )
        store._append_audit(
            "approval",
            entity_id,
            "APPROVAL_RECORDED",
            {
                "primary_key": {
                    field: row[field]
                    for field in (
                        "resolution_id",
                        "case_id",
                        "event_id",
                        "event_revision",
                        "approved_case_hash",
                        "role",
                    )
                },
                "entity_fingerprint": canonical_hash(row),
            },
        )


def _insert_raw_audited_baseline(store, payload, **row_overrides):
    row = {
        "baseline_id": payload["baseline_id"],
        "case_id": payload["case_id"],
        "source_run_id": payload["source_run_id"],
        "payload_json": _canonical_json(payload),
    }
    row.update(row_overrides)
    with store.connection:
        store.connection.execute(
            "INSERT INTO baselines(baseline_id, case_id, source_run_id, payload_json) "
            "VALUES (?, ?, ?, ?)",
            (
                row["baseline_id"],
                row["case_id"],
                row["source_run_id"],
                row["payload_json"],
            ),
        )
        store._append_audit(
            "baseline",
            row["baseline_id"],
            "BASELINE_CREATED",
            {
                "primary_key": {"baseline_id": row["baseline_id"]},
                "entity_fingerprint": canonical_hash(row),
            },
        )


def _save_replay_prerequisites(store, case, resolution, replay):
    store.save_case(case)
    _save_replay(store, replay, resolution)


def test_store_persists_replay_and_valid_hash_chain(tmp_path):
    mutated = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    replay = _replay(mutated, resolution)
    with QualityCIStore(tmp_path / "qualityci.db") as store:
        assert store.save_case(mutated)
        _save_replay(store, replay, resolution)
        counts = store.counts()
        assert counts == {
            "cases": 2,
            "runs": 2,
            "approvals": 0,
            "baselines": 1,
            "artifact_blobs": 7,
            "artifact_sets": 1,
            "artifact_set_members": 2,
            "controlled_reference_sets": 1,
            "controlled_reference_members": 3,
            "run_reference_sets": 0,
            "replay_admissions": 1,
            "replay_ledger": 1,
            "validation_evidence_sets": 2,
            "validation_evidence_members": 2,
            "run_validation_sets": 2,
            "replay_validation_bindings": 1,
            "authorization_record_sets": 1,
            "authorization_record_members": 2,
            "authorization_trust_snapshots": 1,
            "approval_subjects": 1,
            "approval_assertions": 2,
            "approval_consumptions": 1,
            "replay_approval_expectations": 1,
            "baseline_approval_bindings": 1,
            "replay_authorization_authenticity_bindings": 1,
            "case_source_sets": 0,
            "case_source_members": 0,
            "case_lineage_bindings": 0,
            "run_case_source_sets": 0,
            "audit_events": 23,
        }
        assert store.verify_audit_chain()
        assert (
            store.audit_events()[-1]["action"]
            == "REPLAY_APPROVAL_EXPECTATION_RECORDED"
        )


def test_store_is_idempotent_for_same_case_and_run():
    case = load_case(BASE / "baseline.json")
    result = run_case(case)
    with QualityCIStore() as store:
        assert store.save_case(case)
        assert not store.save_case(case)
        assert store.save_run(result)
        assert not store.save_run(result)
        counts = store.counts()
        assert counts["run_case_source_sets"] == 1
        assert counts["audit_events"] == 3


def test_store_keeps_distinct_case_hashes_for_same_case_id():
    original = load_case(BASE / "baseline.json")
    mutated = _m001_case()
    with QualityCIStore() as store:
        assert store.save_case(original)
        assert store.save_case(mutated)
        assert store.counts()["cases"] == 2
        assert store.counts()["audit_events"] == 2


def test_audit_chain_detects_tampering():
    case = load_case(BASE / "baseline.json")
    with QualityCIStore() as store:
        store.save_case(case)
        assert store.verify_audit_chain()
        store.connection.execute("UPDATE audit_events SET payload_json = '{}' WHERE sequence = 1")
        store.connection.commit()
        assert not store.verify_audit_chain()


def test_empty_store_is_not_a_valid_audit_chain():
    with QualityCIStore() as store:
        assert not store.verify_audit_chain()


def test_audit_chain_detects_business_payload_tampering():
    case = load_case(BASE / "baseline.json")
    result = run_case(case)
    with QualityCIStore() as store:
        store.save_case(case)
        store.save_run(result)
        assert store.verify_audit_chain()
        store.connection.execute("UPDATE runs SET payload_json = '{}' WHERE run_id = ?", (result.run_id,))
        store.connection.commit()
        assert not store.verify_audit_chain()


def test_audit_chain_detects_deleted_audit_history():
    case = load_case(BASE / "baseline.json")
    with QualityCIStore() as store:
        store.save_case(case)
        store.connection.execute("DELETE FROM audit_events")
        store.connection.commit()
        assert not store.verify_audit_chain()


def test_audit_chain_rejects_rehashed_but_semantically_wrong_header():
    case = load_case(BASE / "baseline.json")
    with QualityCIStore() as store:
        store.save_case(case)
        row = store.connection.execute("SELECT * FROM audit_events WHERE sequence = 1").fetchone()
        wrong_type = "run"
        seed = "|".join(
            (
                row["previous_hash"],
                row["created_at"],
                wrong_type,
                row["entity_id"],
                row["action"],
                row["payload_json"],
            )
        )
        forged_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        store.connection.execute(
            "UPDATE audit_events SET entity_type = ?, event_hash = ? WHERE sequence = 1",
            (wrong_type, forged_hash),
        )
        store.connection.commit()
        assert not store.verify_audit_chain()


def test_store_rejects_forged_run_result_for_registered_case():
    from qualityci.models import CheckStatus

    case = load_case(BASE / "baseline.json")
    result = run_case(case)
    conflicting = replace(result, overall_status=CheckStatus.CONTRADICTED)
    with QualityCIStore() as store:
        store.save_case(case)
        store.save_run(result)
        with pytest.raises(StoreIntegrityError, match="recomputed"):
            store.save_run(conflicting)
        assert store.counts()["runs"] == 1


def test_run_persistence_has_no_importable_raw_write_capability():
    import qualityci.store as store_module

    case = load_case(BASE / "baseline.json")
    result = run_case(case)
    with QualityCIStore() as store:
        store.save_case(case)
        with pytest.raises(TypeError, match="unexpected keyword"):
            store.save_run(result, prevalidated=object())
        for name in (
            "_RUN_PERSISTENCE_SEAL",
            "_PrevalidatedReplayRun",
        ):
            with pytest.raises(AttributeError):
                getattr(store_module, name)
        for name in (
            "_persist_run",
            "_save_prevalidated_replay_run",
        ):
            with pytest.raises(AttributeError):
                getattr(store, name)
        assert store.counts()["runs"] == 0
        assert store.verify_audit_chain()


def test_prevalidated_replay_run_write_rolls_back_with_transaction(tmp_path: Path):
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    replay = _replay(case, resolution)
    with QualityCIStore(tmp_path / "prevalidated-rollback.db") as store:
        store.save_case(case)
        before = store.counts()
        original_fault_point = store._fault_point

        def fail_after_runs(stage):
            if stage == "after_runs":
                raise RuntimeError("fault:prevalidated-runs")
            return original_fault_point(stage)

        store._fault_point = fail_after_runs
        with pytest.raises(RuntimeError, match="fault:prevalidated-runs"):
            _save_replay(store, replay, resolution)
        assert store.counts() == before
        assert not store.connection.in_transaction
        assert store.verify_audit_chain()


def test_replay_store_runs_engine_once_per_expected_run(
    tmp_path: Path,
    monkeypatch,
):
    import qualityci.store as store_module
    import qualityci.workflow as workflow_module

    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    replay = _replay(case, resolution)
    original_store_run = store_module._run_case_with_reference_context
    original_workflow_run = workflow_module._run_case_with_reference_context
    store_calls = 0
    workflow_calls = 0

    def counted_store_run(*args, **kwargs):
        nonlocal store_calls
        store_calls += 1
        return original_store_run(*args, **kwargs)

    def counted_workflow_run(*args, **kwargs):
        nonlocal workflow_calls
        workflow_calls += 1
        return original_workflow_run(*args, **kwargs)

    monkeypatch.setattr(
        store_module,
        "_run_case_with_reference_context",
        counted_store_run,
    )
    monkeypatch.setattr(
        workflow_module,
        "_run_case_with_reference_context",
        counted_workflow_run,
    )
    with QualityCIStore(tmp_path / "prevalidated-engine-count.db") as store:
        store.save_case(case)
        _save_replay(store, replay, resolution)
        assert (workflow_calls, store_calls) == (2, 0)
        assert store.verify_audit_chain()


def test_store_rejects_run_without_registered_case():
    result = run_case(load_case(BASE / "baseline.json"))
    with QualityCIStore() as store:
        with pytest.raises(StoreIntegrityError, match="must be registered"):
            store.save_run(result)
        assert store.counts() == {
            "cases": 0,
            "runs": 0,
            "approvals": 0,
            "baselines": 0,
            "artifact_blobs": 0,
            "artifact_sets": 0,
            "artifact_set_members": 0,
            "controlled_reference_sets": 0,
            "controlled_reference_members": 0,
            "run_reference_sets": 0,
            "replay_admissions": 0,
            "replay_ledger": 0,
            "validation_evidence_sets": 0,
            "validation_evidence_members": 0,
            "run_validation_sets": 0,
            "replay_validation_bindings": 0,
            "authorization_record_sets": 0,
            "authorization_record_members": 0,
            "authorization_trust_snapshots": 0,
            "approval_subjects": 0,
            "approval_assertions": 0,
            "approval_consumptions": 0,
            "replay_approval_expectations": 0,
            "baseline_approval_bindings": 0,
            "replay_authorization_authenticity_bindings": 0,
            "case_source_sets": 0,
            "case_source_members": 0,
            "case_lineage_bindings": 0,
            "run_case_source_sets": 0,
            "audit_events": 0,
        }


def test_store_rejects_run_when_only_same_case_id_different_hash_is_registered():
    original = load_case(BASE / "baseline.json")
    mutated = _m001_case()
    result = run_case(mutated)
    with QualityCIStore() as store:
        store.save_case(original)
        with pytest.raises(StoreIntegrityError, match="case_hash"):
            store.save_run(result)
        assert store.counts()["runs"] == 0


@pytest.mark.parametrize("payload_kind", ("empty", "forged"))
def test_audit_chain_rejects_cryptographically_valid_but_semantically_invalid_run(payload_kind):
    case = load_case(BASE / "baseline.json")
    result = run_case(case)
    if payload_kind == "empty":
        payload = {}
    else:
        payload = result.to_dict()
        payload["overall_status"] = (
            "PASS" if payload["overall_status"] != "PASS" else "CONTRADICTED"
        )
    with QualityCIStore() as store:
        store.save_case(case)
        _insert_raw_audited_run(store, result, payload)
        assert not store.verify_audit_chain()


def test_audit_chain_rejects_run_without_exact_case_reference():
    result = run_case(load_case(BASE / "baseline.json"))
    with QualityCIStore() as store:
        _insert_raw_audited_run(store, result, result.to_dict())
        assert not store.verify_audit_chain()


def test_store_recomputes_and_rejects_forged_baseline_metadata():
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    replay = _replay(case, resolution)
    assert replay.baseline is not None

    forged_baselines = (
        replace(replay.baseline, baseline_id="forged-baseline"),
        replace(replay.baseline, ruleset_version="forged-ruleset"),
        replace(replay.baseline, status="FORGED"),
    )
    for forged_baseline in forged_baselines:
        with QualityCIStore() as store:
            store.save_case(case)
            with pytest.raises(StoreIntegrityError, match="recomputed"):
                _save_replay(
                    store,
                    replace(replay, baseline=forged_baseline),
                    resolution,
                )
            assert store.counts()["runs"] == 0
            assert store.counts()["approvals"] == 0


def test_store_never_records_invalid_extra_approval():
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    replay = _replay(case, resolution)
    invalid = copy.deepcopy(resolution)
    invalid["approvals"].append({"role": "QUALITY_MANAGER", "decision": "REJECTED"})
    envelope, claims = _native_replay_inputs(replay)
    with QualityCIStore() as store:
        store.save_case(case)
        with pytest.raises(StoreIntegrityError, match="LEGACY_APPROVAL_UNATTESTED"):
            store.save_native_replay(
                envelope,
                invalid,
                approval_subject=claims.subject,
                approval_assertions=list(claims.assertions),
                authorization_bundle=claims.authorization_bundle,
                authorization_trust_bundle=claims.authorization_trust_bundle,
                artifact_bundle=_bundle(),
                reference_bundle=_reference_bundle(),
                source_validation_bundle=_source_validation_bundle(),
                resolved_validation_bundle=_resolved_validation_bundle(),
            )
        assert store.counts()["runs"] == 0
        assert store.counts()["approvals"] == 0


def test_audit_chain_rejects_cryptographically_valid_orphan_approval():
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    payload = _stored_approval_payload(resolution, resolution["approvals"][0])
    payload["case_id"] = "NO-SUCH-CASE"
    payload["approved_case_hash"] = "a" * 64
    payload["approved_patch_hash"] = resolution_patch_hash_for_subject(
        payload,
        case_id=payload["case_id"],
        event_id=payload["event_id"],
        event_revision=payload["event_revision"],
        approved_case_hash=payload["approved_case_hash"],
    )
    with QualityCIStore() as store:
        _insert_raw_audited_approval(store, payload)
        assert not store.verify_audit_chain()


def test_audit_chain_rejects_approval_column_payload_drift():
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    payload = _stored_approval_payload(resolution, resolution["approvals"][0])
    with QualityCIStore() as store:
        store.save_case(case)
        _insert_raw_audited_approval(store, payload, role="PROCESS_OWNER")
        assert not store.verify_audit_chain()


def test_audit_chain_rejects_approval_bound_to_wrong_event_revision():
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    payload = _stored_approval_payload(resolution, resolution["approvals"][0])
    payload["event_revision"] = "999"
    payload["approved_patch_hash"] = resolution_patch_hash_for_subject(
        payload,
        case_id=payload["case_id"],
        event_id=payload["event_id"],
        event_revision=payload["event_revision"],
        approved_case_hash=payload["approved_case_hash"],
    )
    with QualityCIStore() as store:
        store.save_case(case)
        _insert_raw_audited_approval(store, payload)
        assert not store.verify_audit_chain()


def test_audit_chain_rejects_approval_with_wrong_patch_hash():
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    payload = _stored_approval_payload(resolution, resolution["approvals"][0])
    payload["approved_patch_hash"] = "0" * 64
    with QualityCIStore() as store:
        store.save_case(case)
        _insert_raw_audited_approval(store, payload)
        assert not store.verify_audit_chain()


@pytest.mark.parametrize(
    ("field", "value"),
    (("role", "UNAUTHORIZED"), ("decision", "REJECTED")),
)
def test_audit_chain_rejects_approval_with_invalid_role_or_decision(field, value):
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    payload = _stored_approval_payload(resolution, resolution["approvals"][0])
    payload[field] = value
    with QualityCIStore() as store:
        store.save_case(case)
        _insert_raw_audited_approval(store, payload)
        assert not store.verify_audit_chain()


def test_audit_chain_rejects_cryptographically_valid_orphan_baseline():
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    replay = _replay(case, resolution)
    assert replay.baseline is not None
    payload = replay.baseline.to_dict()
    payload["case_id"] = "NO-SUCH-CASE"
    payload["baseline_id"] = "0" * 16
    with QualityCIStore() as store:
        _save_replay_prerequisites(store, case, resolution, replay)
        assert store.verify_audit_chain()
        _insert_raw_audited_baseline(store, payload)
        assert not store.verify_audit_chain()


def test_audit_chain_rejects_baseline_linked_to_non_pass_run():
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    replay = _replay(case, resolution)
    assert replay.baseline is not None
    payload = replay.baseline.to_dict()
    payload["source_run_id"] = replay.before.run_id
    payload["baseline_id"] = "1" * 16
    with QualityCIStore() as store:
        _save_replay_prerequisites(store, case, resolution, replay)
        assert store.verify_audit_chain()
        _insert_raw_audited_baseline(store, payload)
        assert not store.verify_audit_chain()


def test_audit_chain_rejects_baseline_column_payload_drift():
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    replay = _replay(case, resolution)
    assert replay.baseline is not None
    payload = replay.baseline.to_dict()
    payload["baseline_id"] = "2" * 16
    with QualityCIStore() as store:
        _save_replay_prerequisites(store, case, resolution, replay)
        assert store.verify_audit_chain()
        _insert_raw_audited_baseline(store, payload, source_run_id="f" * 16)
        assert not store.verify_audit_chain()


def test_audit_chain_rejects_high_risk_baseline_missing_required_approval():
    case = _m001_case()
    resolution = load_json(BASE / "resolutions/R001_resolve_stale_sop.json")
    replay = _replay(case, resolution)
    assert replay.baseline is not None
    assert case["event"]["risk_level"] == "HIGH"
    payload = replay.baseline.to_dict()
    payload["approved_roles"] = ["QUALITY_MANAGER"]
    seed = (
        f"{payload['source_run_id']}:{payload['resolution_id']}:"
        f"{payload['approved_patch_hash']}:"
        f"{canonical_hash(tuple(payload['approved_roles']))}"
    )
    payload["baseline_id"] = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    with QualityCIStore() as store:
        _save_replay_prerequisites(
            store,
            case,
            resolution,
            replay,
        )
        assert store.verify_audit_chain()
        _insert_raw_audited_baseline(store, payload)
        assert not store.verify_audit_chain()


def test_save_case_enforces_synthetic_validated_boundary():
    valid = load_case(BASE / "baseline.json")
    invalid_cases = []

    non_synthetic = copy.deepcopy(valid)
    non_synthetic["synthetic_for_competition"] = False
    invalid_cases.append(non_synthetic)

    malformed = copy.deepcopy(valid)
    malformed["documents"][0]["owner"] = ""
    invalid_cases.append(malformed)

    with QualityCIStore() as store:
        for case in invalid_cases:
            with pytest.raises(ValueError):
                store.save_case(case)
        assert store.counts()["cases"] == 0
        assert store.counts()["audit_events"] == 0
