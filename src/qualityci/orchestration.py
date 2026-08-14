from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from .case_source_assurance import (
    CASE_SOURCE_BOUND,
    CASE_SOURCE_DERIVED,
    RUN_IDENTITY_VERSION,
    RUN_RESULT_CONTRACT_VERSION,
    CaseMutationBundle,
    CaseSourceAssurance,
    CaseSourceBundle,
)

from .controlled_references import (
    ControlledReferenceBundle,
    _ControlledReferenceContext,
    _is_sealed_reference_context,
    _prepare_controlled_reference_context,
)

from .engine import (
    _evaluate_case_source_bundle,
    _run_id_for_current_identity,
    _run_id_for_identity,
    _run_case_with_reference_context,
    legacy_run_result_projection,
    run_case,
)
from .impact import build_impact_plan
from .loader import canonical_hash, prepare_case
from .models import CheckStatus, Finding, ImpactPlan, RunResult
from .rules import RULESET_VERSION
from .validation_evidence import (
    ValidationEvidenceBundle,
    _ValidationEvidenceContext,
    _is_sealed_validation_context,
    _prepare_validation_evidence_context,
)


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    agent_id: str
    role: str
    responsibility: str
    capabilities: tuple[str, ...]
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    output_contracts: tuple[str, ...]
    dependencies: tuple[str, ...]
    allowed_skills: tuple[str, ...]
    decision_boundary: str
    trace_contract: str
    forbidden_actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SkillContract:
    skill_id: str
    skill_type: str
    purpose: str
    use_cases: tuple[str, ...]
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    preconditions: tuple[str, ...]
    dependencies: tuple[str, ...]
    failure_mode: str
    safety_boundary: str
    reusable_for: tuple[str, ...]
    version: str = "0.2.0.dev0"


@dataclass(frozen=True, slots=True)
class TeamTraceEvent:
    sequence: int
    agent_id: str
    skill_id: str
    state_from: str
    state_to: str
    input_hash: str
    output_hash: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_trace_fields(
            sequence=self.sequence,
            agent_id=self.agent_id,
            skill_id=self.skill_id,
            state_from=self.state_from,
            state_to=self.state_to,
            input_hash=self.input_hash,
            output_hash=self.output_hash,
            evidence=self.evidence,
            label="legacy Team trace",
        )


@dataclass(frozen=True, slots=True)
class LegacyTeamRunView:
    """Frozen RunResult-v3 object used only by legacy TeamRunResult 0.1."""

    run_id: str
    case_id: str
    case_hash: str
    ruleset_version: str
    reference_assurance_state: str
    reference_set_hash: str | None
    reference_contract_version: str | None
    validation_assurance_state: str
    validation_evidence_set_hash: str | None
    validation_evidence_contract_version: str | None
    overall_status: CheckStatus
    impact_plan: Any
    findings: tuple[Any, ...]

    def __post_init__(self) -> None:
        _validate_legacy_team_run_view(self)

    def to_dict(self) -> dict[str, Any]:
        return _json_native(asdict(self))


@dataclass(frozen=True, slots=True)
class TeamRunResult:
    run: LegacyTeamRunView
    trace: tuple[TeamTraceEvent, ...]
    final_team_state: str
    shared_state: dict[str, Any]
    runtime_mode: str = "LOCAL_DETERMINISTIC_CONTRACT"

    def __post_init__(self) -> None:
        _validate_legacy_team_result(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime_mode": self.runtime_mode,
            "final_team_state": self.final_team_state,
            "shared_state": self.shared_state,
            "run": self.run.to_dict(),
            "trace": [asdict(event) for event in self.trace],
        }


TEAM_RUN_CONTRACT_VERSION = "qualityci-team-run-0.2"
TEAM_TASK_CONTEXT_CONTRACT_VERSION = "qualityci-team-task-context-0.2"
TEAM_TRACE_EVENT_CONTRACT_VERSION = "qualityci-team-trace-event-0.2"
TEAM_SHARED_STATE_CONTRACT_VERSION = "qualityci-team-shared-state-0.2"
TEAM_FINAL_DECISION_CONTRACT_VERSION = "qualityci-team-final-decision-0.2"
TEAM_RUNTIME_MODE = "LOCAL_DETERMINISTIC_CONTRACT"

_TEAM_READY = "READY_FOR_HUMAN_RELEASE_REVIEW"
_TEAM_BLOCKED = "BLOCKED_PENDING_RESOLUTION"
_TEAM_FINAL_STATES = frozenset({_TEAM_READY, _TEAM_BLOCKED})
_CHECK_STATUS_VALUES = frozenset(str(item) for item in CheckStatus)
_SOURCE_TUPLE_KEYS = (
    "case_source_assurance_state",
    "case_source_pack_contract_version",
    "case_source_set_contract_version",
    "case_source_set_hash",
    "case_source_binding_hash",
    "case_source_lineage_contract_version",
    "case_source_lineage_hash",
)
_LEGACY_RUN_KEYS = frozenset(
    {
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
)
_CURRENT_RUN_KEYS = _LEGACY_RUN_KEYS | frozenset(
    {
        "run_result_contract_version",
        "run_identity_version",
        *_SOURCE_TUPLE_KEYS,
    }
)
_LEGACY_SHARED_STATE_KEYS = frozenset(
    {
        "case_id",
        "event_id",
        "current_state",
        "artifact_hashes",
        "dispatch_plan",
        "run_id",
        "ruleset_version",
    }
)
_LEGACY_ARTIFACT_HASH_KEYS = frozenset(
    {"task_context", "dispatch_plan", "impact_plan", "run_result"}
)
_DISPATCH_PROFILE = (
    (1, "QCI-IMPACT", "compile-impact-plan"),
    (2, "QCI-EVIDENCE", "run-evidence-regression"),
    (3, "QCI-GATEKEEPER", "enforce-release-gate"),
)


def _exact_text(value: Any, label: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{label} must be an exact string")
    if not value or value != value.strip():
        raise ValueError(f"{label} must be an exact non-empty trimmed string")
    return value


def _exact_constant(value: Any, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise ValueError(f"{label} is unsupported")
    return value


def _lower_hex(value: Any, length: int, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be one lowercase hexadecimal identity")
    return value


def _validate_trace_fields(
    *,
    sequence: Any,
    agent_id: Any,
    skill_id: Any,
    state_from: Any,
    state_to: Any,
    input_hash: Any,
    output_hash: Any,
    evidence: Any,
    label: str,
) -> None:
    if type(sequence) is not int or sequence <= 0:
        raise TypeError(f"{label} sequence must be an exact positive integer")
    for value, field_name in (
        (agent_id, "agent_id"),
        (skill_id, "skill_id"),
        (state_from, "state_from"),
        (state_to, "state_to"),
    ):
        _exact_text(value, f"{label} {field_name}")
    _lower_hex(input_hash, 64, f"{label} input_hash")
    _lower_hex(output_hash, 64, f"{label} output_hash")
    if type(evidence) is not tuple or any(type(item) is not str for item in evidence):
        raise TypeError(f"{label} evidence must be an exact string tuple")


def _validate_reference_profile(value: Any, label: str) -> None:
    if type(value.reference_assurance_state) is not str:
        raise TypeError(f"{label} reference assurance state must be an exact string")
    if value.reference_assurance_state == "UNATTESTED_JSON":
        if (
            value.reference_set_hash is not None
            or value.reference_contract_version is not None
        ):
            raise ValueError(f"{label} unattested reference profile requires nulls")
    elif value.reference_assurance_state == "ATTESTED_REFERENCE_SET":
        _lower_hex(value.reference_set_hash, 64, f"{label} reference set hash")
        _exact_constant(
            value.reference_contract_version,
            "qualityci-controlled-reference-0.1",
            f"{label} reference contract version",
        )
    else:
        raise ValueError(f"{label} reference assurance state is unsupported")

    if type(value.validation_assurance_state) is not str:
        raise TypeError(f"{label} validation assurance state must be an exact string")
    if value.validation_assurance_state == "UNATTESTED_VALIDATION_JSON":
        if (
            value.validation_evidence_set_hash is not None
            or value.validation_evidence_contract_version is not None
        ):
            raise ValueError(f"{label} unattested validation profile requires nulls")
    elif value.validation_assurance_state == "ATTESTED_VALIDATION_SET":
        _lower_hex(
            value.validation_evidence_set_hash,
            64,
            f"{label} validation evidence set hash",
        )
        _exact_constant(
            value.validation_evidence_contract_version,
            "qualityci-validation-evidence-0.1",
            f"{label} validation contract version",
        )
    else:
        raise ValueError(f"{label} validation assurance state is unsupported")


def _validate_result_value_types(
    *,
    overall_status: Any,
    impact_plan: Any,
    findings: Any,
    label: str,
) -> None:
    if type(overall_status) is not CheckStatus:
        raise TypeError(f"{label} overall_status must be exact CheckStatus")
    if type(impact_plan) is not ImpactPlan:
        raise TypeError(f"{label} impact_plan must be exact ImpactPlan")
    if type(findings) is not tuple or any(
        type(item) is not Finding for item in findings
    ):
        raise TypeError(f"{label} findings must be an exact Finding tuple")
    if any(type(item.status) is not CheckStatus for item in findings):
        raise TypeError(f"{label} Finding statuses must be exact CheckStatus")
    statuses = {item.status for item in findings}
    expected_status = (
        CheckStatus.CONTRADICTED
        if CheckStatus.CONTRADICTED in statuses
        else CheckStatus.UNVERIFIABLE
        if CheckStatus.UNVERIFIABLE in statuses
        else CheckStatus.PASS
    )
    if overall_status is not expected_status:
        raise ValueError(f"{label} overall_status disagrees with its findings")


def _validate_legacy_team_run_view(value: LegacyTeamRunView) -> None:
    if type(value) is not LegacyTeamRunView:
        raise TypeError("legacy Team run requires the exact LEGACY_V3 value type")
    _lower_hex(value.run_id, 16, "LEGACY_V3 run_id")
    _exact_text(value.case_id, "LEGACY_V3 case_id")
    _lower_hex(value.case_hash, 64, "LEGACY_V3 case_hash")
    _exact_constant(value.ruleset_version, RULESET_VERSION, "LEGACY_V3 ruleset_version")
    _validate_reference_profile(value, "LEGACY_V3")
    _validate_result_value_types(
        overall_status=value.overall_status,
        impact_plan=value.impact_plan,
        findings=value.findings,
        label="LEGACY_V3",
    )
    expected_run_id = _run_id_for_identity(
        value.case_hash,
        reference_assurance_state=value.reference_assurance_state,
        reference_set_hash=value.reference_set_hash,
        reference_contract_version=value.reference_contract_version,
        validation_assurance_state=value.validation_assurance_state,
        validation_evidence_set_hash=value.validation_evidence_set_hash,
        validation_evidence_contract_version=(
            value.validation_evidence_contract_version
        ),
    )
    if value.run_id != expected_run_id:
        raise ValueError("LEGACY_V3 run_id differs from its exact identity")
    if set(value.to_dict()) != _LEGACY_RUN_KEYS:
        raise ValueError("legacy Team run differs from the exact LEGACY_V3 profile")


def _legacy_dispatch_payload() -> tuple[dict[str, Any], ...]:
    return tuple(
        {"sequence": sequence, "agent_id": agent_id, "skill_id": skill_id}
        for sequence, agent_id, skill_id in _DISPATCH_PROFILE
    )


def _validate_legacy_team_result(value: TeamRunResult) -> None:
    if type(value) is not TeamRunResult:
        raise TypeError("legacy Team result requires the exact TeamRunResult type")
    if type(value.run) is not LegacyTeamRunView:
        raise TypeError("legacy Team result may contain only an exact LEGACY_V3 run")
    _validate_legacy_team_run_view(value.run)
    _exact_constant(value.runtime_mode, TEAM_RUNTIME_MODE, "legacy Team runtime mode")
    _exact_constant(
        value.final_team_state,
        _TEAM_BLOCKED,
        "legacy Team final state",
    )
    if type(value.trace) is not tuple or len(value.trace) != 4 or any(
        type(item) is not TeamTraceEvent for item in value.trace
    ):
        raise TypeError("legacy Team result requires exactly four legacy trace values")
    if (
        type(value.shared_state) is not dict
        or set(value.shared_state) != _LEGACY_SHARED_STATE_KEYS
        or any(type(key) is not str for key in value.shared_state)
    ):
        raise TypeError("legacy Team shared state has an invalid exact profile")
    shared = value.shared_state
    artifacts = shared["artifact_hashes"]
    if (
        type(artifacts) is not dict
        or set(artifacts) != _LEGACY_ARTIFACT_HASH_KEYS
        or any(type(key) is not str for key in artifacts)
    ):
        raise TypeError("legacy Team artifact hashes have an invalid exact profile")
    for name, identity in artifacts.items():
        _lower_hex(identity, 64, f"legacy Team artifact hash {name}")
    dispatch_plan = shared["dispatch_plan"]
    if (
        type(dispatch_plan) is not tuple
        or any(
            type(item) is not dict
            or set(item) != {"sequence", "agent_id", "skill_id"}
            or any(type(key) is not str for key in item)
            for item in dispatch_plan
        )
        or dispatch_plan != _legacy_dispatch_payload()
    ):
        raise ValueError("legacy Team dispatch plan differs from its exact profile")
    _exact_text(shared["case_id"], "legacy Team shared case_id")
    _lower_hex(shared["run_id"], 16, "legacy Team shared run_id")
    _exact_constant(
        shared["ruleset_version"],
        RULESET_VERSION,
        "legacy Team shared ruleset_version",
    )
    _exact_constant(
        shared["current_state"],
        _TEAM_BLOCKED,
        "legacy Team shared current_state",
    )
    if (
        shared["case_id"] != value.run.case_id
        or shared["run_id"] != value.run.run_id
        or shared["ruleset_version"] != value.run.ruleset_version
        or shared["current_state"] != value.final_team_state
    ):
        raise ValueError("legacy Team shared state differs from its run or final state")
    event_id = _exact_text(shared["event_id"], "legacy Team shared event_id")
    task_context = {
        "case_id": value.run.case_id,
        "event_id": event_id,
        "case_hash": value.run.case_hash,
        "synthetic": True,
    }
    manager_output = {
        "task_context": task_context,
        "dispatch_plan": dispatch_plan,
    }
    impact_plan = asdict(value.run.impact_plan)
    impact_artifact = {
        "case_hash": value.run.case_hash,
        "impact_plan": impact_plan,
    }
    run_payload = value.run.to_dict()
    run_hash = canonical_hash(run_payload)
    final_payload = {
        "decision": value.final_team_state,
        "run_id": value.run.run_id,
        "overall_status": str(value.run.overall_status),
    }
    expected_artifacts = {
        "task_context": canonical_hash(task_context),
        "dispatch_plan": canonical_hash(dispatch_plan),
        "impact_plan": canonical_hash(impact_plan),
        "run_result": run_hash,
    }
    if artifacts != expected_artifacts:
        raise ValueError("legacy Team artifact hashes differ from exact values")
    expected_trace = (
        (1, "QCI-MANAGER", "quality-task-intake", "RECEIVED", "SCOPED"),
        (2, "QCI-IMPACT", "compile-impact-plan", "SCOPED", "PLANNED"),
        (3, "QCI-EVIDENCE", "run-evidence-regression", "PLANNED", "CHECKED"),
        (
            4,
            "QCI-GATEKEEPER",
            "enforce-release-gate",
            "CHECKED",
            _TEAM_BLOCKED,
        ),
    )
    for event, expected in zip(value.trace, expected_trace, strict=True):
        if (
            event.sequence,
            event.agent_id,
            event.skill_id,
            event.state_from,
            event.state_to,
        ) != expected:
            raise ValueError("legacy Team trace profile is inconsistent")
    expected_hash_joins = (
        (value.run.case_hash, canonical_hash(manager_output)),
        (canonical_hash(manager_output), canonical_hash(impact_artifact)),
        (canonical_hash(impact_artifact), run_hash),
        (run_hash, canonical_hash(final_payload)),
    )
    if tuple((item.input_hash, item.output_hash) for item in value.trace) != (
        expected_hash_joins
    ):
        raise ValueError("legacy Team trace hash joins are inconsistent")


def _source_tuple(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not CaseSourceAssurance:
        raise TypeError(f"{label} requires exact CaseSourceAssurance")
    payload = value.to_dict()
    if set(payload) != set(_SOURCE_TUPLE_KEYS):
        raise ValueError(f"{label} source tuple has an invalid exact profile")
    if any(item is not None and type(item) is not str for item in payload.values()):
        raise TypeError(f"{label} source tuple values must be exact strings or null")
    if payload["case_source_assurance_state"] not in {
        CASE_SOURCE_BOUND,
        CASE_SOURCE_DERIVED,
    }:
        raise ValueError(f"{label} source tuple must be BOUND or SOURCE_ROOTED")
    return payload


def _run_source_tuple(value: RunResult) -> dict[str, Any]:
    payload = {key: getattr(value, key) for key in _SOURCE_TUPLE_KEYS}
    if any(item is not None and type(item) is not str for item in payload.values()):
        raise TypeError("CURRENT_V4 source tuple values must be exact strings or null")
    return payload


def _validate_current_team_run(
    value: RunResult,
    source: dict[str, Any],
    case_source: CaseSourceAssurance,
) -> None:
    if type(value) is not RunResult:
        raise TypeError("Team 0.2 result may contain only exact CURRENT_V4 RunResult")
    _exact_constant(
        value.run_result_contract_version,
        RUN_RESULT_CONTRACT_VERSION,
        "CURRENT_V4 RunResult contract version",
    )
    _exact_constant(
        value.run_identity_version,
        RUN_IDENTITY_VERSION,
        "CURRENT_V4 RunResult identity version",
    )
    _lower_hex(value.run_id, 16, "CURRENT_V4 RunResult run_id")
    _exact_text(value.case_id, "CURRENT_V4 RunResult case_id")
    _lower_hex(value.case_hash, 64, "CURRENT_V4 RunResult case_hash")
    _exact_constant(
        value.ruleset_version,
        RULESET_VERSION,
        "CURRENT_V4 RunResult ruleset_version",
    )
    if set(value.to_dict()) != _CURRENT_RUN_KEYS:
        raise ValueError("Team 0.2 nested run is not the exact CURRENT_V4 profile")
    run_source = _run_source_tuple(value)
    if run_source != source:
        raise ValueError("Team 0.2 nested run source tuple disagrees with the root")
    _validate_reference_profile(value, "CURRENT_V4")
    _validate_result_value_types(
        overall_status=value.overall_status,
        impact_plan=value.impact_plan,
        findings=value.findings,
        label="CURRENT_V4",
    )
    expected_run_id = _run_id_for_current_identity(
        value.case_hash,
        case_source_assurance=case_source,
        reference_assurance_state=value.reference_assurance_state,
        reference_set_hash=value.reference_set_hash,
        reference_contract_version=value.reference_contract_version,
        validation_assurance_state=value.validation_assurance_state,
        validation_evidence_set_hash=value.validation_evidence_set_hash,
        validation_evidence_contract_version=(
            value.validation_evidence_contract_version
        ),
    )
    if value.run_id != expected_run_id:
        raise ValueError("CURRENT_V4 RunResult run_id differs from its exact identity")


def _validate_dispatch_plan(value: Any, label: str) -> None:
    if type(value) is not tuple or len(value) != len(_DISPATCH_PROFILE) or any(
        type(item) is not SourceRootedTeamDispatchStep for item in value
    ):
        raise TypeError(f"{label} dispatch plan must use exact Team 0.2 values")
    observed = tuple((item.sequence, item.agent_id, item.skill_id) for item in value)
    if observed != _DISPATCH_PROFILE:
        raise ValueError(f"{label} dispatch plan differs from its exact profile")


def _team_state_for_status(status: str) -> str:
    return _TEAM_READY if status == str(CheckStatus.PASS) else _TEAM_BLOCKED


def _validate_source_rooted_team_result(value: SourceRootedTeamRunResult) -> None:
    if type(value) is not SourceRootedTeamRunResult:
        raise TypeError("Team 0.2 result requires the exact root value type")
    _exact_constant(
        value.contract_version,
        TEAM_RUN_CONTRACT_VERSION,
        "Team 0.2 root contract version",
    )
    _exact_constant(value.runtime_mode, TEAM_RUNTIME_MODE, "Team 0.2 runtime mode")
    source = _source_tuple(value.case_source, "Team 0.2 root")
    if type(value.task_context) is not SourceRootedTeamTaskContext:
        raise TypeError("Team 0.2 result requires exact task context")
    _validate_current_team_run(value.run, source, value.case_source)
    if type(value.trace) is not tuple or len(value.trace) != 4 or any(
        type(item) is not SourceRootedTeamTraceEvent for item in value.trace
    ):
        raise TypeError("Team 0.2 result requires exactly four exact trace values")
    if type(value.final_decision) is not SourceRootedTeamFinalDecision:
        raise TypeError("Team 0.2 result requires exact final decision")
    if type(value.shared_state) is not SourceRootedTeamSharedState:
        raise TypeError("Team 0.2 result requires exact shared state")
    for nested_source, label in (
        (value.task_context.case_source, "task context"),
        (value.shared_state.case_source, "shared state"),
        (value.final_decision.case_source, "final decision"),
        *((item.case_source, f"trace[{index}]") for index, item in enumerate(value.trace)),
    ):
        if _source_tuple(nested_source, f"Team 0.2 {label}") != source:
            raise ValueError(f"Team 0.2 {label} source tuple disagrees with the root")
    if (
        value.task_context.case_id != value.run.case_id
        or value.shared_state.case_id != value.run.case_id
        or value.task_context.case_hash != value.run.case_hash
        or value.task_context.event_id != value.shared_state.event_id
        or value.task_context.synthetic is not True
    ):
        raise ValueError("Team 0.2 task/shared identity joins disagree with the run")
    status = str(value.run.overall_status)
    expected_state = _team_state_for_status(status)
    if type(value.final_team_state) is not str:
        raise TypeError("Team 0.2 final_team_state must be an exact string")
    if (
        value.final_team_state != expected_state
        or value.shared_state.current_state != expected_state
        or value.final_decision.decision != expected_state
        or value.final_decision.run_id != value.run.run_id
        or value.final_decision.overall_status != status
        or value.shared_state.run_id != value.run.run_id
        or value.shared_state.ruleset_version != value.run.ruleset_version
    ):
        raise ValueError("Team 0.2 run/status/state joins are inconsistent")
    _validate_dispatch_plan(value.shared_state.dispatch_plan, "Team 0.2 root")
    dispatch_payload = [item.to_dict() for item in value.shared_state.dispatch_plan]
    task_payload = value.task_context.to_dict()
    manager_output = {
        "task_context": task_payload,
        "dispatch_plan": dispatch_payload,
    }
    source_input = {
        "case_source": source,
        "case_hash": value.run.case_hash,
    }
    dispatch_artifact = {
        "case_source": source,
        "dispatch_plan": dispatch_payload,
    }
    impact_artifact = {
        "case_source": source,
        "case_hash": value.run.case_hash,
        "impact_plan": asdict(value.run.impact_plan),
    }
    run_payload = value.run.to_dict()
    final_payload = value.final_decision.to_dict()
    expected_artifacts = {
        "task_context": canonical_hash(task_payload),
        "dispatch_plan": canonical_hash(dispatch_artifact),
        "impact_plan": canonical_hash(impact_artifact),
        "run_result": canonical_hash(run_payload),
        "final_decision": canonical_hash(final_payload),
    }
    if value.shared_state.artifact_hashes.to_dict() != expected_artifacts:
        raise ValueError("Team 0.2 artifact hashes differ from exact nested values")
    expected_trace = (
        (1, "QCI-MANAGER", "quality-task-intake", "RECEIVED", "SCOPED"),
        (2, "QCI-IMPACT", "compile-impact-plan", "SCOPED", "PLANNED"),
        (3, "QCI-EVIDENCE", "run-evidence-regression", "PLANNED", "CHECKED"),
        (
            4,
            "QCI-GATEKEEPER",
            "enforce-release-gate",
            "CHECKED",
            expected_state,
        ),
    )
    for event, expected in zip(value.trace, expected_trace, strict=True):
        if (
            event.sequence,
            event.agent_id,
            event.skill_id,
            event.state_from,
            event.state_to,
        ) != expected:
            raise ValueError("Team 0.2 trace profile is inconsistent")
    expected_hash_joins = (
        (canonical_hash(source_input), canonical_hash(manager_output)),
        (canonical_hash(manager_output), canonical_hash(impact_artifact)),
        (canonical_hash(impact_artifact), canonical_hash(run_payload)),
        (canonical_hash(run_payload), canonical_hash(final_payload)),
    )
    if tuple((item.input_hash, item.output_hash) for item in value.trace) != (
        expected_hash_joins
    ):
        raise ValueError("Team 0.2 trace hash joins are inconsistent")


@dataclass(frozen=True, slots=True)
class SourceRootedTeamDispatchStep:
    sequence: int
    agent_id: str
    skill_id: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence <= 0:
            raise TypeError("Team 0.2 dispatch sequence must be an exact positive integer")
        _exact_text(self.agent_id, "Team 0.2 dispatch agent_id")
        _exact_text(self.skill_id, "Team 0.2 dispatch skill_id")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SourceRootedTeamTaskContext:
    contract_version: str
    case_source: CaseSourceAssurance
    case_id: str
    event_id: str
    case_hash: str
    synthetic: bool

    def __post_init__(self) -> None:
        _exact_constant(
            self.contract_version,
            TEAM_TASK_CONTEXT_CONTRACT_VERSION,
            "Team 0.2 task context contract version",
        )
        _source_tuple(self.case_source, "Team 0.2 task context")
        _exact_text(self.case_id, "Team 0.2 task context case_id")
        _exact_text(self.event_id, "Team 0.2 task context event_id")
        _lower_hex(self.case_hash, 64, "Team 0.2 task context case_hash")
        if type(self.synthetic) is not bool:
            raise TypeError("Team 0.2 task context synthetic must be an exact bool")

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "case_source": self.case_source.to_dict(),
            "case_id": self.case_id,
            "event_id": self.event_id,
            "case_hash": self.case_hash,
            "synthetic": self.synthetic,
        }


@dataclass(frozen=True, slots=True)
class SourceRootedTeamTraceEvent:
    contract_version: str
    case_source: CaseSourceAssurance
    sequence: int
    agent_id: str
    skill_id: str
    state_from: str
    state_to: str
    input_hash: str
    output_hash: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        _exact_constant(
            self.contract_version,
            TEAM_TRACE_EVENT_CONTRACT_VERSION,
            "Team 0.2 trace contract version",
        )
        _source_tuple(self.case_source, "Team 0.2 trace")
        _validate_trace_fields(
            sequence=self.sequence,
            agent_id=self.agent_id,
            skill_id=self.skill_id,
            state_from=self.state_from,
            state_to=self.state_to,
            input_hash=self.input_hash,
            output_hash=self.output_hash,
            evidence=self.evidence,
            label="Team 0.2 trace",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "case_source": self.case_source.to_dict(),
            "sequence": self.sequence,
            "agent_id": self.agent_id,
            "skill_id": self.skill_id,
            "state_from": self.state_from,
            "state_to": self.state_to,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class SourceRootedTeamArtifactHashes:
    task_context: str
    dispatch_plan: str
    impact_plan: str
    run_result: str
    final_decision: str

    def __post_init__(self) -> None:
        for name in (
            "task_context",
            "dispatch_plan",
            "impact_plan",
            "run_result",
            "final_decision",
        ):
            _lower_hex(
                getattr(self, name),
                64,
                f"Team 0.2 artifact hash {name}",
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SourceRootedTeamFinalDecision:
    contract_version: str
    case_source: CaseSourceAssurance
    decision: str
    run_id: str
    overall_status: str

    def __post_init__(self) -> None:
        _exact_constant(
            self.contract_version,
            TEAM_FINAL_DECISION_CONTRACT_VERSION,
            "Team 0.2 final decision contract version",
        )
        _source_tuple(self.case_source, "Team 0.2 final decision")
        if type(self.decision) is not str or self.decision not in _TEAM_FINAL_STATES:
            raise ValueError("Team 0.2 final decision state is unsupported")
        _lower_hex(self.run_id, 16, "Team 0.2 final decision run_id")
        if (
            type(self.overall_status) is not str
            or self.overall_status not in _CHECK_STATUS_VALUES
        ):
            raise ValueError("Team 0.2 final decision status is unsupported")
        if self.decision != _team_state_for_status(self.overall_status):
            raise ValueError("Team 0.2 final decision differs from overall status")

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "case_source": self.case_source.to_dict(),
            "decision": self.decision,
            "run_id": self.run_id,
            "overall_status": self.overall_status,
        }


@dataclass(frozen=True, slots=True)
class SourceRootedTeamSharedState:
    contract_version: str
    case_source: CaseSourceAssurance
    case_id: str
    event_id: str
    current_state: str
    artifact_hashes: SourceRootedTeamArtifactHashes
    dispatch_plan: tuple[SourceRootedTeamDispatchStep, ...]
    run_id: str
    ruleset_version: str

    def __post_init__(self) -> None:
        _exact_constant(
            self.contract_version,
            TEAM_SHARED_STATE_CONTRACT_VERSION,
            "Team 0.2 shared state contract version",
        )
        _source_tuple(self.case_source, "Team 0.2 shared state")
        _exact_text(self.case_id, "Team 0.2 shared state case_id")
        _exact_text(self.event_id, "Team 0.2 shared state event_id")
        if type(self.current_state) is not str or self.current_state not in _TEAM_FINAL_STATES:
            raise ValueError("Team 0.2 shared state current_state is unsupported")
        if type(self.artifact_hashes) is not SourceRootedTeamArtifactHashes:
            raise TypeError("Team 0.2 shared state requires exact artifact hashes")
        _validate_dispatch_plan(self.dispatch_plan, "Team 0.2 shared state")
        _lower_hex(self.run_id, 16, "Team 0.2 shared state run_id")
        _exact_text(self.ruleset_version, "Team 0.2 shared state ruleset_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "case_source": self.case_source.to_dict(),
            "case_id": self.case_id,
            "event_id": self.event_id,
            "current_state": self.current_state,
            "artifact_hashes": self.artifact_hashes.to_dict(),
            "dispatch_plan": [item.to_dict() for item in self.dispatch_plan],
            "run_id": self.run_id,
            "ruleset_version": self.ruleset_version,
        }


@dataclass(frozen=True, slots=True)
class SourceRootedTeamRunResult:
    """Explicit Team 0.2 profile; it may contain only a CURRENT_V4 RunResult."""

    contract_version: str
    case_source: CaseSourceAssurance
    task_context: SourceRootedTeamTaskContext
    run: RunResult
    trace: tuple[SourceRootedTeamTraceEvent, ...]
    final_team_state: str
    final_decision: SourceRootedTeamFinalDecision
    shared_state: SourceRootedTeamSharedState
    runtime_mode: str = "LOCAL_DETERMINISTIC_CONTRACT"

    def __post_init__(self) -> None:
        _validate_source_rooted_team_result(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "runtime_mode": self.runtime_mode,
            "case_source": self.case_source.to_dict(),
            "task_context": self.task_context.to_dict(),
            "final_team_state": self.final_team_state,
            "final_decision": self.final_decision.to_dict(),
            "shared_state": self.shared_state.to_dict(),
            "run": self.run.to_dict(),
            "trace": [event.to_dict() for event in self.trace],
        }


def _json_native(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {key: _json_native(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_native(item) for item in value]
    return value


def _legacy_team_run_view(result: RunResult) -> LegacyTeamRunView:
    projection = legacy_run_result_projection(result)
    view = LegacyTeamRunView(
        run_id=projection["run_id"],
        case_id=result.case_id,
        case_hash=result.case_hash,
        ruleset_version=result.ruleset_version,
        reference_assurance_state=result.reference_assurance_state,
        reference_set_hash=result.reference_set_hash,
        reference_contract_version=result.reference_contract_version,
        validation_assurance_state=result.validation_assurance_state,
        validation_evidence_set_hash=result.validation_evidence_set_hash,
        validation_evidence_contract_version=(
            result.validation_evidence_contract_version
        ),
        overall_status=result.overall_status,
        impact_plan=result.impact_plan,
        findings=result.findings,
    )
    if view.to_dict() != projection:
        raise AssertionError("legacy Team Run object differs from its frozen payload")
    return view


AGENT_IDENTITIES = (
    AgentIdentity(
        agent_id="QCI-MANAGER",
        role="质量任务协调 Agent",
        responsibility="接收ECO/NCR任务，校验边界，拆解并路由到专业Worker。",
        capabilities=("Schema与数据边界校验", "任务拆解", "Worker路由"),
        inputs=("CaseEnvelope", "data_boundary"),
        outputs=("task_context", "dispatch_plan"),
        output_contracts=("JSON对象", "必须含case_id/event_id/case_hash", "同输入同哈希"),
        dependencies=("validate_case", "quality-task-intake", "发布版CaseEnvelope JSON Schema"),
        allowed_skills=("quality-task-intake",),
        decision_boundary="只能决定是否接收与如何拆解；不能形成质量放行结论。",
        trace_contract="记录RECEIVED→SCOPED、输入/输出哈希与边界证据。",
        forbidden_actions=("修改受控文件", "批准工艺参数", "绕过人工审批"),
    ),
    AgentIdentity(
        agent_id="QCI-IMPACT",
        role="影响分析 Agent",
        responsibility="把事件范围编译为受影响工序、特性、文档和规则计划。",
        capabilities=("工序/特性映射", "必需文档选择", "规则计划编译"),
        inputs=("task_context", "event", "document_index"),
        outputs=("ImpactPlan",),
        output_contracts=("ImpactPlan JSON对象", "集合去重并排序", "缺范围显式保留"),
        dependencies=("build_impact_plan", "compile-impact-plan", "document_index"),
        allowed_skills=("compile-impact-plan",),
        decision_boundary="只确定检查范围，不判断规格正确性或批准变更。",
        trace_contract="记录SCOPED→PLANNED、ImpactPlan哈希与事件范围证据。",
        forbidden_actions=("臆测缺失范围", "修改源文档", "形成放行结论"),
    ),
    AgentIdentity(
        agent_id="QCI-EVIDENCE",
        role="证据回归 Agent",
        responsibility="运行确定性规则并输出三态、证据锚点、建议和验收条件。",
        capabilities=("规则执行", "证据锚定", "三态判定", "整改条件生成"),
        inputs=("CaseEnvelope", "ImpactPlan", "ruleset_version"),
        outputs=("RunResult",),
        output_contracts=("RunResult JSON对象", "每条规则恰有一个三态", "非PASS携带证据或缺失定位"),
        dependencies=("run_case", "run-evidence-regression", "EvidenceRef", "固定ruleset_version"),
        allowed_skills=("run-evidence-regression",),
        decision_boundary="只能判断当前规则与证据状态；不能批准参数或发布文件。",
        trace_contract="记录PLANNED→CHECKED、RunResult哈希、规则版本与证据定位符。",
        forbidden_actions=("把证据不足判为PASS", "自动写回文件", "控制生产设备"),
    ),
    AgentIdentity(
        agent_id="QCI-GATEKEEPER",
        role="审批与基线守门 Agent",
        responsibility="根据回归状态阻断风险，并在后续流程中核验人审、复跑和审计。",
        capabilities=("非PASS阻断", "批准主体核验", "修订复跑", "基线与本地审计记录"),
        inputs=("RunResult", "approval_bundle", "resolution_digest"),
        outputs=("gate_decision", "audit_event", "BaselineRecord"),
        output_contracts=("gate_decision枚举", "BaselineRecord仅在复跑PASS时生成", "审批主体与候选基线可追溯"),
        dependencies=("enforce-release-gate", "verify-and-replay", "QualityCIStore（可选本地持久化）"),
        allowed_skills=("enforce-release-gate", "verify-and-replay"),
        decision_boundary="可以阻断但不能代替人类签批；PASS只进入人工放行复核。",
        trace_contract="主Trace记录CHECKED→门禁；复跑/基线事件由Workflow/Store另行记录。",
        forbidden_actions=("代替人类审批", "未复跑即建基线", "删除审计事件"),
    ),
)


SKILL_CONTRACTS = (
    SkillContract(
        skill_id="quality-task-intake",
        skill_type="BOUNDARY_VALIDATION",
        purpose="校验输入是授权范围内且显式标注的案例，并生成共享任务上下文。",
        use_cases=("ECO任务接收", "NCR任务接收", "合成案例边界校验"),
        inputs=("CaseEnvelope",),
        outputs=("task_context",),
        preconditions=("输入通过runtime结构校验", "当前原型仅接受synthetic_for_competition=true"),
        dependencies=("validate_case", "发布版CaseEnvelope JSON Schema交换契约"),
        failure_mode="拒绝任务并记录原因，不进入下游Agent。",
        safety_boundary="不读取请求给出的任意路径，不连接客户系统。",
        reusable_for=("ENGINEERING_CHANGE", "QUALITY_EVENT"),
    ),
    SkillContract(
        skill_id="compile-impact-plan",
        skill_type="PLANNING",
        purpose="把事件映射为工序、特性、必需文档和选中规则。",
        use_cases=("工程变更影响分析", "质量异常回归规划"),
        inputs=("task_context", "event", "document_index"),
        outputs=("ImpactPlan",),
        preconditions=("event_id、revision、risk_level存在",),
        dependencies=("build_impact_plan", "document_index"),
        failure_mode="范围缺失时输出UNVERIFIABLE路径，不自行补全事实。",
        safety_boundary="只读分析，不修改受控文件。",
        reusable_for=("工程变更", "质量异常", "供应商纠正措施"),
    ),
    SkillContract(
        skill_id="run-evidence-regression",
        skill_type="DETERMINISTIC_EXECUTION",
        purpose="执行固定版本规则，输出PASS/CONTRADICTED/UNVERIFIABLE及证据。",
        use_cases=("跨文档规格回归", "版本/引用检查", "验证证据检查"),
        inputs=("CaseEnvelope", "ImpactPlan", "ruleset_version"),
        outputs=("RunResult",),
        preconditions=("证据带文档、版本和定位符",),
        dependencies=("run_case", "EvidenceRef", "固定ruleset_version"),
        failure_mode="缺证据时UNVERIFIABLE；冲突时CONTRADICTED。",
        safety_boundary="规则结论不等于参数获得专业批准。",
        reusable_for=("PFMEA", "控制计划", "SOP", "检验记录"),
    ),
    SkillContract(
        skill_id="enforce-release-gate",
        skill_type="SAFETY_GATE",
        purpose="把非PASS结果硬阻断，把PASS结果送交人工放行复核。",
        use_cases=("变更审查门禁", "质量异常关闭门禁"),
        inputs=("RunResult",),
        outputs=("gate_decision",),
        preconditions=("RunResult哈希和ruleset_version完整",),
        dependencies=("CheckStatus", "RunResult"),
        failure_mode="任何不确定状态均默认阻断。",
        safety_boundary="PASS仅代表当前规则与证据一致，不能替代质量负责人放行。",
        reusable_for=("变更审查", "纠正措施验证", "基线回归"),
    ),
    SkillContract(
        skill_id="verify-and-replay",
        skill_type="HUMAN_GATED_REPLAY",
        purpose="核验审批与修订摘要绑定，应用提案后复跑，满足条件才形成新基线。",
        use_cases=("高风险修订复跑", "纠正措施关闭", "候选基线生成"),
        inputs=("resolution", "approval_bundle", "prior_run"),
        outputs=("ReplayResult", "BaselineRecord", "audit_event"),
        preconditions=("审批角色、事件版本和修订摘要均匹配",),
        dependencies=("apply_approved_resolution", "replay_with_resolution", "QualityCIStore（可选）"),
        failure_mode="缺少任何必要审批或复跑未PASS时不建基线。",
        safety_boundary="不能自动生成或伪造人类批准。",
        reusable_for=("高风险变更", "偏差关闭", "纠正措施关闭"),
    ),
)


def agent_identity_manifest() -> list[dict[str, Any]]:
    return [asdict(identity) for identity in AGENT_IDENTITIES]


def skill_manifest() -> list[dict[str, Any]]:
    return [asdict(skill) for skill in SKILL_CONTRACTS]


def _run_agent_team(
    case: dict[str, Any],
    reference_context: _ControlledReferenceContext | None,
    validation_context: _ValidationEvidenceContext | None = None,
) -> TeamRunResult:
    """Run the local deterministic choreography behind the AgentTeams design.

    This is an executable contract and trace generator, not a claim that the
    AgentTeams/Matrix runtime is already integrated. The adapter remains a
    separately labelled competition milestone.
    """

    if not isinstance(case, dict):
        raise TypeError("agent orchestration requires an actual case object")
    case = prepare_case(case)
    case_hash = canonical_hash(case)
    task_context = {
        "case_id": case["case_id"],
        "event_id": case["event"]["event_id"],
        "case_hash": case_hash,
        "synthetic": True,
    }
    dispatch_plan = (
        {"sequence": 1, "agent_id": "QCI-IMPACT", "skill_id": "compile-impact-plan"},
        {"sequence": 2, "agent_id": "QCI-EVIDENCE", "skill_id": "run-evidence-regression"},
        {"sequence": 3, "agent_id": "QCI-GATEKEEPER", "skill_id": "enforce-release-gate"},
    )
    manager_output = {"task_context": task_context, "dispatch_plan": dispatch_plan}
    plan = build_impact_plan(case)
    plan_dict = asdict(plan)
    impact_artifact = {"case_hash": case_hash, "impact_plan": plan_dict}
    current_run = (
        _run_case_with_reference_context(
            case, reference_context, validation_context
        )
        if reference_context is not None
        else run_case(case)
    )
    run = _legacy_team_run_view(current_run)
    # Team 0.1 is an evaluation profile.  Rule PASS remains visible, but an
    # unbound serialized Case cannot become a trusted release-ready decision.
    gate = "BLOCKED_PENDING_RESOLUTION"
    trace = (
        TeamTraceEvent(
            sequence=1,
            agent_id="QCI-MANAGER",
            skill_id="quality-task-intake",
            state_from="RECEIVED",
            state_to="SCOPED",
            input_hash=case_hash,
            output_hash=canonical_hash(manager_output),
            evidence=("case_id", "event.event_id", "synthetic_for_competition"),
        ),
        TeamTraceEvent(
            sequence=2,
            agent_id="QCI-IMPACT",
            skill_id="compile-impact-plan",
            state_from="SCOPED",
            state_to="PLANNED",
            input_hash=canonical_hash(manager_output),
            output_hash=canonical_hash(impact_artifact),
            evidence=("event.affected_process_steps", "event.affected_characteristics"),
        ),
        TeamTraceEvent(
            sequence=3,
            agent_id="QCI-EVIDENCE",
            skill_id="run-evidence-regression",
            state_from="PLANNED",
            state_to="CHECKED",
            input_hash=canonical_hash(impact_artifact),
            output_hash=canonical_hash(run.to_dict()),
            evidence=tuple(
                sorted(
                    {
                        ref.locator
                        for finding in run.findings
                        for ref in finding.evidence
                        if ref.locator
                    }
                )
            ),
        ),
        TeamTraceEvent(
            sequence=4,
            agent_id="QCI-GATEKEEPER",
            skill_id="enforce-release-gate",
            state_from="CHECKED",
            state_to=gate,
            input_hash=canonical_hash(run.to_dict()),
            output_hash=canonical_hash(
                {"decision": gate, "run_id": run.run_id, "overall_status": str(run.overall_status)}
            ),
            evidence=("run_id", "case_hash", "ruleset_version", "overall_status"),
        ),
    )
    shared_state = {
        "case_id": case["case_id"],
        "event_id": case["event"]["event_id"],
        "current_state": gate,
        "artifact_hashes": {
            "task_context": canonical_hash(task_context),
            "dispatch_plan": canonical_hash(dispatch_plan),
            "impact_plan": canonical_hash(plan_dict),
            "run_result": canonical_hash(run.to_dict()),
        },
        "dispatch_plan": dispatch_plan,
        "run_id": run.run_id,
        "ruleset_version": run.ruleset_version,
    }
    return TeamRunResult(
        run=run,
        trace=trace,
        final_team_state=gate,
        shared_state=shared_state,
    )


def run_agent_team_with_source_bundle(
    bundle: CaseSourceBundle,
    *,
    mutation_bundle: CaseMutationBundle | None = None,
    validation_bundle: ValidationEvidenceBundle | None = None,
) -> SourceRootedTeamRunResult:
    """Run Team 0.2 from one exact raw Case source bundle.

    The public entry accepts no Case object, duplicate reference bundle, source
    identity, marker, or prepared context.  Core rebuilds the Case and the A03
    context from the same owned snapshot before this choreography begins.
    """

    if type(bundle) is not CaseSourceBundle:
        raise TypeError("source-rooted orchestration requires exact CaseSourceBundle")
    if validation_bundle is not None and type(validation_bundle) is not (
        ValidationEvidenceBundle
    ):
        raise TypeError(
            "source-rooted orchestration requires exact validation raw bytes"
        )
    if mutation_bundle is not None and type(mutation_bundle) is not CaseMutationBundle:
        raise TypeError("source-rooted orchestration requires exact mutation raw bytes")
    evaluation = _evaluate_case_source_bundle(
        bundle,
        mutation_bundle=mutation_bundle,
        validation_bundle=validation_bundle,
    )
    case = evaluation.case()
    run = evaluation.run
    case_source = CaseSourceAssurance(
        case_source_assurance_state=run.case_source_assurance_state,
        case_source_pack_contract_version=run.case_source_pack_contract_version,
        case_source_set_contract_version=run.case_source_set_contract_version,
        case_source_set_hash=run.case_source_set_hash,
        case_source_binding_hash=run.case_source_binding_hash,
        case_source_lineage_contract_version=(
            run.case_source_lineage_contract_version
        ),
        case_source_lineage_hash=run.case_source_lineage_hash,
    )
    if case_source.case_source_assurance_state not in {
        CASE_SOURCE_BOUND,
        CASE_SOURCE_DERIVED,
    }:
        raise AssertionError("source-rooted Team requires a bound or derived Run")

    case_hash = canonical_hash(case)
    if case_hash != run.case_hash:
        raise AssertionError("source-rooted Team Case differs from current Run")
    task_context = SourceRootedTeamTaskContext(
        contract_version=TEAM_TASK_CONTEXT_CONTRACT_VERSION,
        case_source=case_source,
        case_id=case["case_id"],
        event_id=case["event"]["event_id"],
        case_hash=case_hash,
        synthetic=True,
    )
    source_input = {
        "case_source": case_source.to_dict(),
        "case_hash": case_hash,
    }
    dispatch_plan = (
        SourceRootedTeamDispatchStep(1, "QCI-IMPACT", "compile-impact-plan"),
        SourceRootedTeamDispatchStep(
            2,
            "QCI-EVIDENCE",
            "run-evidence-regression",
        ),
        SourceRootedTeamDispatchStep(3, "QCI-GATEKEEPER", "enforce-release-gate"),
    )
    dispatch_plan_payload = [item.to_dict() for item in dispatch_plan]
    manager_output = {
        "task_context": task_context.to_dict(),
        "dispatch_plan": dispatch_plan_payload,
    }
    plan_dict = asdict(run.impact_plan)
    dispatch_artifact = {
        "case_source": case_source.to_dict(),
        "dispatch_plan": dispatch_plan_payload,
    }
    impact_artifact = {
        "case_source": case_source.to_dict(),
        "case_hash": case_hash,
        "impact_plan": plan_dict,
    }
    gate = (
        "READY_FOR_HUMAN_RELEASE_REVIEW"
        if run.overall_status == CheckStatus.PASS
        else "BLOCKED_PENDING_RESOLUTION"
    )
    final_decision = SourceRootedTeamFinalDecision(
        contract_version=TEAM_FINAL_DECISION_CONTRACT_VERSION,
        case_source=case_source,
        decision=gate,
        run_id=run.run_id,
        overall_status=str(run.overall_status),
    )
    trace = (
        SourceRootedTeamTraceEvent(
            contract_version=TEAM_TRACE_EVENT_CONTRACT_VERSION,
            case_source=case_source,
            sequence=1,
            agent_id="QCI-MANAGER",
            skill_id="quality-task-intake",
            state_from="RECEIVED",
            state_to="SCOPED",
            input_hash=canonical_hash(source_input),
            output_hash=canonical_hash(manager_output),
            evidence=("case_id", "event.event_id", "synthetic_for_competition"),
        ),
        SourceRootedTeamTraceEvent(
            contract_version=TEAM_TRACE_EVENT_CONTRACT_VERSION,
            case_source=case_source,
            sequence=2,
            agent_id="QCI-IMPACT",
            skill_id="compile-impact-plan",
            state_from="SCOPED",
            state_to="PLANNED",
            input_hash=canonical_hash(manager_output),
            output_hash=canonical_hash(impact_artifact),
            evidence=("event.affected_process_steps", "event.affected_characteristics"),
        ),
        SourceRootedTeamTraceEvent(
            contract_version=TEAM_TRACE_EVENT_CONTRACT_VERSION,
            case_source=case_source,
            sequence=3,
            agent_id="QCI-EVIDENCE",
            skill_id="run-evidence-regression",
            state_from="PLANNED",
            state_to="CHECKED",
            input_hash=canonical_hash(impact_artifact),
            output_hash=canonical_hash(run.to_dict()),
            evidence=tuple(
                sorted(
                    {
                        ref.locator
                        for finding in run.findings
                        for ref in finding.evidence
                        if ref.locator
                    }
                )
            ),
        ),
        SourceRootedTeamTraceEvent(
            contract_version=TEAM_TRACE_EVENT_CONTRACT_VERSION,
            case_source=case_source,
            sequence=4,
            agent_id="QCI-GATEKEEPER",
            skill_id="enforce-release-gate",
            state_from="CHECKED",
            state_to=gate,
            input_hash=canonical_hash(run.to_dict()),
            output_hash=canonical_hash(final_decision.to_dict()),
            evidence=(
                "run_id",
                "case_hash",
                "ruleset_version",
                "overall_status",
                "case_source",
            ),
        ),
    )
    shared_state = SourceRootedTeamSharedState(
        contract_version=TEAM_SHARED_STATE_CONTRACT_VERSION,
        case_source=case_source,
        case_id=case["case_id"],
        event_id=case["event"]["event_id"],
        current_state=gate,
        artifact_hashes=SourceRootedTeamArtifactHashes(
            task_context=canonical_hash(task_context.to_dict()),
            dispatch_plan=canonical_hash(dispatch_artifact),
            impact_plan=canonical_hash(impact_artifact),
            run_result=canonical_hash(run.to_dict()),
            final_decision=canonical_hash(final_decision.to_dict()),
        ),
        dispatch_plan=dispatch_plan,
        run_id=run.run_id,
        ruleset_version=run.ruleset_version,
    )
    result = SourceRootedTeamRunResult(
        contract_version=TEAM_RUN_CONTRACT_VERSION,
        case_source=case_source,
        task_context=task_context,
        run=run,
        trace=trace,
        final_team_state=gate,
        final_decision=final_decision,
        shared_state=shared_state,
    )
    payload = result.to_dict()
    if payload["run"] != run.to_dict():
        raise AssertionError("source-rooted Team must nest exact CURRENT_V4 RunResult")
    for nested in (
        payload["task_context"],
        payload["shared_state"],
        payload["final_decision"],
        *payload["trace"],
    ):
        if nested["case_source"] != case_source.to_dict():
            raise AssertionError("source-rooted Team source tuple disagreement")
    return result


def run_agent_team(
    case: dict[str, Any],
    *,
    reference_bundle: ControlledReferenceBundle | None = None,
    validation_bundle: ValidationEvidenceBundle | None = None,
    validation_phase: str = "SOURCE",
) -> TeamRunResult:
    """Run orchestration; only captured raw bytes can enable native R005 PASS."""

    if reference_bundle is None:
        if validation_bundle is not None:
            raise TypeError(
                "validation evidence requires a controlled-reference raw bundle"
            )
        return _run_agent_team(case, None)
    if type(reference_bundle) is not ControlledReferenceBundle:
        raise TypeError("agent orchestration rejects controlled-reference context markers")
    validation_context = None
    if validation_bundle is not None:
        if type(validation_bundle) is not ValidationEvidenceBundle:
            raise TypeError("agent orchestration rejects validation context markers")
        validation_context = _prepare_validation_evidence_context(
            validation_bundle,
            prepare_case(case),
            expected_phase=validation_phase,
        )
    return _run_agent_team(
        case,
        _prepare_controlled_reference_context(reference_bundle),
        validation_context,
    )


def _run_agent_team_with_reference_context(
    case: dict[str, Any],
    context: _ControlledReferenceContext,
    validation_context: _ValidationEvidenceContext | None = None,
) -> TeamRunResult:
    if not _is_sealed_reference_context(context):
        raise TypeError("internal agent orchestration requires sealed reference context")
    if validation_context is not None and not _is_sealed_validation_context(
        validation_context
    ):
        raise TypeError("internal agent orchestration requires sealed validation context")
    return _run_agent_team(case, context, validation_context)
