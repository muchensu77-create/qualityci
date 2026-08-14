from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from qualityci.case_builder import build_case_from_pack
from qualityci.case_source_assurance import (
    CASE_SOURCE_BOUND,
    CaseSourceBundle,
    load_case_source_bundle,
)
from qualityci.controlled_references import load_controlled_reference_bundle
from qualityci.engine import (
    legacy_run_result_projection,
    run_case_with_evidence_bundles,
)
from qualityci.loader import canonical_hash, load_case
from qualityci.orchestration import (
    TEAM_FINAL_DECISION_CONTRACT_VERSION,
    TEAM_RUN_CONTRACT_VERSION,
    TEAM_SHARED_STATE_CONTRACT_VERSION,
    TEAM_TASK_CONTEXT_CONTRACT_VERSION,
    TEAM_TRACE_EVENT_CONTRACT_VERSION,
    LegacyTeamRunView,
    SourceRootedTeamRunResult,
    TeamRunResult,
    run_agent_team,
    run_agent_team_with_source_bundle,
)
from qualityci.validation_evidence import load_validation_evidence_bundle
from validation_support import validation_bundle


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "datasets/qualityci-bench/tacoma_24v152"
CASE_PATH = BENCH / "baseline_v04.json"
REFERENCE_MANIFEST = BENCH / "reference_sources/manifest.json"
VALIDATION_MANIFEST = BENCH / "validation_sources/BASELINE/source/manifest.json"
SOURCE_MANIFEST = ROOT / "tests/fixtures/case_builder/manifest.json"

LEGACY_RUN_KEYS = {
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
}


def test_direct_team_exposes_one_exact_legacy_v3_view_and_stays_blocked() -> None:
    case = load_case(CASE_PATH)
    reference = load_controlled_reference_bundle(REFERENCE_MANIFEST)
    validation = load_validation_evidence_bundle(VALIDATION_MANIFEST)
    current = run_case_with_evidence_bundles(case, reference, validation)

    result = run_agent_team(
        case,
        reference_bundle=reference,
        validation_bundle=validation,
    )
    payload = result.to_dict()

    assert type(result.run) is LegacyTeamRunView
    assert not hasattr(result.run, "__dict__")
    assert set(result.run.__slots__) == LEGACY_RUN_KEYS
    assert set(payload["run"]) == LEGACY_RUN_KEYS
    assert payload["run"] == legacy_run_result_projection(current)
    assert result.run.run_id == payload["run"]["run_id"] == "594e17d5d7d0f21e"
    assert result.run.overall_status.value == "PASS"
    assert result.final_team_state == "BLOCKED_PENDING_RESOLUTION"
    assert result.shared_state["run_id"] == result.run.run_id
    assert result.trace[2].output_hash == canonical_hash(payload["run"])
    assert result.trace[3].input_hash == canonical_hash(payload["run"])
    assert result.trace[-1].state_to == "BLOCKED_PENDING_RESOLUTION"
    with pytest.raises(FrozenInstanceError):
        result.run.run_id = "forged"  # type: ignore[misc]


def test_source_rooted_team_02_carries_one_tuple_everywhere_and_can_be_ready() -> None:
    bundle = load_case_source_bundle(SOURCE_MANIFEST)
    case = build_case_from_pack(SOURCE_MANIFEST)
    validation = validation_bundle(case, "SOURCE")

    result = run_agent_team_with_source_bundle(
        bundle,
        validation_bundle=validation,
    )
    payload = result.to_dict()
    source = payload["case_source"]

    assert type(result) is SourceRootedTeamRunResult
    assert result.contract_version == TEAM_RUN_CONTRACT_VERSION
    assert result.final_team_state == "READY_FOR_HUMAN_RELEASE_REVIEW"
    assert result.run.overall_status.value == "PASS"
    assert result.run.case_source_assurance_state == CASE_SOURCE_BOUND
    assert len(payload["run"]) == 22
    assert payload["run"]["run_result_contract_version"] == "qualityci-run-result-0.2"
    assert payload["run"]["run_identity_version"] == "qualityci-run-identity-v4"
    assert payload["run"] == result.run.to_dict()
    assert payload["task_context"]["contract_version"] == (
        TEAM_TASK_CONTEXT_CONTRACT_VERSION
    )
    assert payload["shared_state"]["contract_version"] == (
        TEAM_SHARED_STATE_CONTRACT_VERSION
    )
    assert payload["final_decision"]["contract_version"] == (
        TEAM_FINAL_DECISION_CONTRACT_VERSION
    )
    assert all(
        event["contract_version"] == TEAM_TRACE_EVENT_CONTRACT_VERSION
        for event in payload["trace"]
    )
    assert payload["task_context"]["case_source"] == source
    assert payload["shared_state"]["case_source"] == source
    assert payload["final_decision"]["case_source"] == source
    assert all(event["case_source"] == source for event in payload["trace"])
    assert payload["final_decision"] == {
        "contract_version": TEAM_FINAL_DECISION_CONTRACT_VERSION,
        "case_source": source,
        "decision": "READY_FOR_HUMAN_RELEASE_REVIEW",
        "run_id": result.run.run_id,
        "overall_status": "PASS",
    }
    assert result.trace[-1].output_hash == canonical_hash(payload["final_decision"])
    source_input = {
        "case_source": source,
        "case_hash": result.run.case_hash,
    }
    dispatch_artifact = {
        "case_source": source,
        "dispatch_plan": payload["shared_state"]["dispatch_plan"],
    }
    impact_artifact = {
        "case_source": source,
        "case_hash": result.run.case_hash,
        "impact_plan": payload["run"]["impact_plan"],
    }
    assert result.trace[0].input_hash == canonical_hash(source_input)
    assert result.trace[0].output_hash == result.trace[1].input_hash
    assert result.trace[1].output_hash == result.trace[2].input_hash
    assert result.trace[2].output_hash == result.trace[3].input_hash
    assert payload["shared_state"]["artifact_hashes"]["dispatch_plan"] == (
        canonical_hash(dispatch_artifact)
    )
    assert payload["shared_state"]["artifact_hashes"]["impact_plan"] == (
        canonical_hash(impact_artifact)
    )
    assert source["case_source_set_hash"] not in {
        canonical_hash(payload["shared_state"]["dispatch_plan"]),
        canonical_hash(payload["run"]["impact_plan"]),
    }

    original_payload = result.to_dict()
    original_hash = canonical_hash(original_payload)
    frozen_targets = (
        (result, "case_source", result.case_source),
        (result.case_source, "case_source_set_hash", "0" * 64),
        (result.task_context, "case_source", result.case_source),
        (result.trace[0], "case_source", result.case_source),
        (result.shared_state, "case_source", result.case_source),
        (result.shared_state.artifact_hashes, "run_result", "0" * 64),
        (result.shared_state.dispatch_plan[0], "agent_id", "FORGED"),
        (result.final_decision, "case_source", result.case_source),
    )
    for target, attribute, forged in frozen_targets:
        assert not hasattr(target, "__dict__")
        with pytest.raises(FrozenInstanceError):
            setattr(target, attribute, forged)
    detached = result.to_dict()
    detached["case_source"]["case_source_set_hash"] = "0" * 64
    detached["task_context"]["case_source"]["case_source_set_hash"] = "1" * 64
    detached["shared_state"]["artifact_hashes"]["run_result"] = "2" * 64
    detached["shared_state"]["dispatch_plan"][0]["agent_id"] = "FORGED"
    detached["trace"][0]["case_source"]["case_source_set_hash"] = "3" * 64
    assert result.to_dict() == original_payload
    assert canonical_hash(result.to_dict()) == original_hash


def test_source_rooted_team_rejects_case_or_bundle_lookalikes() -> None:
    with pytest.raises(TypeError, match="exact CaseSourceBundle"):
        run_agent_team_with_source_bundle({})  # type: ignore[arg-type]

    class BundleSubclass(CaseSourceBundle):
        pass

    bundle = load_case_source_bundle(SOURCE_MANIFEST)
    attacked = BundleSubclass(
        bundle.manifest_bytes,
        bundle.members,
        bundle.snapshot,
    )
    with pytest.raises(TypeError, match="exact CaseSourceBundle"):
        run_agent_team_with_source_bundle(attacked)


def test_legacy_team_value_constructors_reject_mixed_or_inconsistent_profiles() -> None:
    case = load_case(CASE_PATH)
    reference = load_controlled_reference_bundle(REFERENCE_MANIFEST)
    validation = load_validation_evidence_bundle(VALIDATION_MANIFEST)
    current = run_case_with_evidence_bundles(case, reference, validation)
    legacy = run_agent_team(
        case,
        reference_bundle=reference,
        validation_bundle=validation,
    )

    with pytest.raises(ValueError, match="LEGACY_V3 run_id differs"):
        replace(legacy.run, run_id="0" * 16)
    with pytest.raises(ValueError, match="unattested reference profile"):
        replace(legacy.run, reference_assurance_state="UNATTESTED_JSON")
    with pytest.raises(TypeError, match="only an exact LEGACY_V3"):
        TeamRunResult(
            run=current,  # type: ignore[arg-type]
            trace=legacy.trace,
            final_team_state=legacy.final_team_state,
            shared_state=legacy.shared_state,
        )

    missing_shared = dict(legacy.shared_state)
    missing_shared.pop("run_id")
    with pytest.raises(TypeError, match="shared state has an invalid exact profile"):
        replace(legacy, shared_state=missing_shared)

    with pytest.raises(ValueError, match="runtime mode is unsupported"):
        TeamRunResult(
            run=legacy.run,
            trace=legacy.trace,
            final_team_state=legacy.final_team_state,
            shared_state=legacy.shared_state,
            runtime_mode="qualityci-team-runtime-unknown",
        )

    with pytest.raises(ValueError, match="ruleset_version is unsupported"):
        replace(legacy.run, ruleset_version="qci-rules-unknown")

    drifted_artifacts = dict(legacy.shared_state["artifact_hashes"])
    drifted_artifacts["run_result"] = "0" * 64
    drifted_shared = dict(legacy.shared_state)
    drifted_shared["artifact_hashes"] = drifted_artifacts
    with pytest.raises(ValueError, match="artifact hashes differ"):
        replace(legacy, shared_state=drifted_shared)

    drifted_trace = (
        *legacy.trace[:2],
        replace(legacy.trace[2], output_hash="0" * 64),
        legacy.trace[3],
    )
    with pytest.raises(ValueError, match="trace hash joins"):
        replace(legacy, trace=drifted_trace)


def test_source_rooted_nested_constructors_reject_types_versions_and_profiles() -> None:
    bundle = load_case_source_bundle(SOURCE_MANIFEST)
    case = build_case_from_pack(SOURCE_MANIFEST)
    result = run_agent_team_with_source_bundle(
        bundle,
        validation_bundle=validation_bundle(case, "SOURCE"),
    )

    with pytest.raises(ValueError, match="task context contract version"):
        replace(
            result.task_context,
            contract_version="qualityci-team-task-context-9.9",
        )
    with pytest.raises(TypeError, match="exact CaseSourceAssurance"):
        replace(result.task_context, case_source={})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="trace contract version"):
        replace(
            result.trace[0],
            contract_version="qualityci-team-trace-event-9.9",
        )
    with pytest.raises(ValueError, match="final decision differs"):
        replace(result.final_decision, overall_status="CONTRADICTED")
    with pytest.raises(ValueError, match="dispatch plan differs"):
        wrong_step = replace(
            result.shared_state.dispatch_plan[0],
            agent_id="QCI-UNKNOWN",
        )
        replace(
            result.shared_state,
            dispatch_plan=(wrong_step, *result.shared_state.dispatch_plan[1:]),
        )
    with pytest.raises(TypeError, match="dispatch plan must use exact"):
        replace(
            result.shared_state,
            dispatch_plan=list(result.shared_state.dispatch_plan),  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="findings must be an exact Finding tuple"):
        replace(result, run=replace(result.run, findings=(object(),)))  # type: ignore[arg-type]


def test_source_rooted_root_constructor_rejects_mixed_profiles_and_join_drift() -> None:
    bundle = load_case_source_bundle(SOURCE_MANIFEST)
    case = build_case_from_pack(SOURCE_MANIFEST)
    result = run_agent_team_with_source_bundle(
        bundle,
        validation_bundle=validation_bundle(case, "SOURCE"),
    )
    legacy = run_agent_team(case)

    with pytest.raises(ValueError, match="root contract version"):
        SourceRootedTeamRunResult(
            contract_version="qualityci-team-run-9.9",
            case_source=result.case_source,
            task_context=result.task_context,
            run=result.run,
            trace=result.trace,
            final_team_state=result.final_team_state,
            final_decision=result.final_decision,
            shared_state=result.shared_state,
        )
    with pytest.raises(TypeError, match="only exact CURRENT_V4"):
        replace(result, run=legacy.run)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="exactly four exact trace"):
        replace(result, trace=list(result.trace))  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="run/status/state joins"):
        replace(result, final_team_state="BLOCKED_PENDING_RESOLUTION")

    drifted_status_run = replace(
        result.run,
        overall_status=type(result.run.overall_status).CONTRADICTED,
    )
    with pytest.raises(ValueError, match="overall_status disagrees with its findings"):
        replace(result, run=drifted_status_run)

    different_source = replace(
        result.case_source,
        case_source_set_hash="0" * 64,
    )
    different_task = replace(
        result.task_context,
        case_source=different_source,
    )
    with pytest.raises(ValueError, match="task context source tuple disagrees"):
        replace(result, task_context=different_task)

    different_final = replace(result.final_decision, run_id="0" * 16)
    with pytest.raises(ValueError, match="run/status/state joins"):
        replace(result, final_decision=different_final)

    different_hashes = replace(
        result.shared_state.artifact_hashes,
        run_result="0" * 64,
    )
    different_shared = replace(
        result.shared_state,
        artifact_hashes=different_hashes,
    )
    with pytest.raises(ValueError, match="artifact hashes differ"):
        replace(result, shared_state=different_shared)

    different_trace = (
        *result.trace[:2],
        replace(result.trace[2], output_hash="0" * 64),
        result.trace[3],
    )
    with pytest.raises(ValueError, match="trace hash joins"):
        replace(result, trace=different_trace)
