from pathlib import Path

from qualityci.controlled_references import load_controlled_reference_bundle
from qualityci.loader import load_case
from qualityci.orchestration import (
    AGENT_IDENTITIES,
    LegacyTeamRunView,
    SKILL_CONTRACTS,
    agent_identity_manifest,
    run_agent_team,
    skill_manifest,
)
from validation_support import native_validation_case, validation_bundle


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "datasets" / "qualityci-bench" / "tacoma_24v152"


def test_agentteams_contract_has_distinct_roles_and_reusable_skills() -> None:
    assert len(AGENT_IDENTITIES) >= 3
    assert len({item.agent_id for item in AGENT_IDENTITIES}) == len(AGENT_IDENTITIES)
    assert len({item.role for item in AGENT_IDENTITIES}) == len(AGENT_IDENTITIES)
    assert all(
        item.capabilities
        and item.output_contracts
        and item.dependencies
        and item.decision_boundary
        and item.trace_contract
        and item.forbidden_actions
        for item in AGENT_IDENTITIES
    )
    assert len(SKILL_CONTRACTS) >= 4
    assert all(
        skill.skill_type
        and skill.use_cases
        and skill.inputs
        and skill.outputs
        and skill.dependencies
        and skill.failure_mode
        and skill.version
        for skill in SKILL_CONTRACTS
    )
    assert len(agent_identity_manifest()) == len(AGENT_IDENTITIES)
    assert len(skill_manifest()) == len(SKILL_CONTRACTS)


def test_agent_team_blocks_fault_and_emits_deterministic_trace() -> None:
    case = load_case(
        BENCH / "baseline.json",
        BENCH / "mutations" / "M001_stale_sop_conflict.json",
    )
    first = run_agent_team(case)
    second = run_agent_team(case)
    assert first.to_dict() == second.to_dict()
    assert first.final_team_state == "BLOCKED_PENDING_RESOLUTION"
    assert first.shared_state["current_state"] == first.final_team_state
    assert first.shared_state["run_id"] == first.run.run_id
    assert set(first.shared_state["artifact_hashes"]) == {
        "task_context",
        "dispatch_plan",
        "impact_plan",
        "run_result",
    }
    assert [item["agent_id"] for item in first.shared_state["dispatch_plan"]] == [
        "QCI-IMPACT",
        "QCI-EVIDENCE",
        "QCI-GATEKEEPER",
    ]
    assert all(len(value) == 64 for value in first.shared_state["artifact_hashes"].values())
    assert [event.sequence for event in first.trace] == [1, 2, 3, 4]
    assert [event.agent_id for event in first.trace] == [
        "QCI-MANAGER",
        "QCI-IMPACT",
        "QCI-EVIDENCE",
        "QCI-GATEKEEPER",
    ]
    assert all(
        earlier.output_hash == later.input_hash
        for earlier, later in zip(first.trace, first.trace[1:])
    )
    assert all(len(event.input_hash) == 64 and len(event.output_hash) == 64 for event in first.trace)


def test_clean_serialized_baseline_is_evaluation_only_and_stays_blocked() -> None:
    case = native_validation_case(load_case(BENCH / "baseline.json"))
    result = run_agent_team(
        case,
        reference_bundle=load_controlled_reference_bundle(
            BENCH / "reference_sources" / "manifest.json"
        ),
        validation_bundle=validation_bundle(case, "SOURCE"),
    )
    assert result.run.overall_status == "PASS"
    assert result.run.reference_assurance_state == "ATTESTED_REFERENCE_SET"
    assert len(result.run.reference_set_hash or "") == 64
    assert (
        result.run.reference_contract_version
        == "qualityci-controlled-reference-0.1"
    )
    assert type(result.run) is LegacyTeamRunView
    assert result.final_team_state == "BLOCKED_PENDING_RESOLUTION"
    assert result.trace[-1].state_to != "RELEASED"
