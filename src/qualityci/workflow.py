from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from .approval_subject import (
    GLOBAL_SINGLE_USE_UNVERIFIED,
    SOURCE_APPROVAL_SUBJECT_CONTRACT_VERSION,
    StatelessApprovalValidation,
    approval_subject_hash,
    derive_approval_subject,
    validate_approval_assertions,
    validate_approval_subject,
)
from .case_source_assurance import (
    CASE_SOURCE_DERIVED,
    CASE_SOURCE_NATIVE_REPLAY_OPERATION_CONTRACT_VERSION,
    CaseMutationBundle,
    CaseSourceBundle,
    _CaseSourceContext,
    _derive_case_source_mutation,
    _derive_case_source_native_replay,
    _is_sealed_case_source_context,
    _prepare_case_source_context,
)
from .authorization_records import AuthorizationRecordBundle
from .authorization_authenticity import (
    AUTHORIZATION_AUTHENTICITY_PASS,
    AuthorizationAuthenticityContext,
    AuthorizationTrustSnapshotBundle,
    authorization_authenticity_binding_hash,
    prepare_authorization_authenticity_context,
    require_authenticated_assertion_records,
)
from .controlled_references import (
    ControlledReferenceBundle,
    _ControlledReferenceContext,
    _prepare_controlled_reference_context,
)
from .engine import (
    _evaluate_source_rooted_case,
    _run_case_with_reference_context,
    run_case,
)
from .loader import (
    apply_mutation,
    canonical_hash,
    prepare_case,
    strict_json_loads,
    validate_case,
)
from .models import CheckStatus, RunResult
from .validation_evidence import (
    VALIDATION_EVIDENCE_CONTRACT_VERSION,
    ValidationEvidenceBundle,
    _ValidationCaseIdentity,
    _ValidationEvidenceContext,
    _prepare_validation_case_identity,
    _prepare_validation_evidence_context,
    validation_approval_policy,
    validation_evidence_pair_hash,
)
from .revision_artifacts import (
    ArtifactContext,
    RevisionArtifactBundle,
    RevisionArtifactError,
    artifact_context_matches_bundle,
    prepare_artifact_context,
    resolve_case_from_artifact_context,
    validate_resolution_operation_paths,
)


REQUIRED_APPROVAL_ROLES = {"QUALITY_MANAGER", "PROCESS_OWNER"}
NATIVE_RESOLUTION_KEYS = frozenset(
    {"resolution_id", "description", "replacement_set_id", "operations"}
)
_NATIVE_SET_OPERATION_KEYS = frozenset({"op", "document_id", "path", "value"})
_NATIVE_REPLAY_SEAL = object()
_APPROVAL_ASSERTION_SET_DOMAIN = b"QualityCI/approval-assertion-set/v1\0"


class ApprovalGateError(ValueError):
    """Raised when a proposed revision has not passed the human approval gate."""


class ArtifactGateError(ApprovalGateError):
    """Raised when an actual replay lacks rebuilt replacement-artifact bytes."""


@dataclass(frozen=True, slots=True)
class CaseMutationDerivationBundle:
    """One exact raw mutation step; it carries no lineage or trust claim."""

    mutation_bundle: CaseMutationBundle

    def __post_init__(self) -> None:
        if type(self.mutation_bundle) is not CaseMutationBundle:
            raise TypeError(
                "mutation derivation requires an exact CaseMutationBundle"
            )


@dataclass(frozen=True, slots=True)
class NativeReplayDerivationBundle:
    """All exact raw inputs needed to rebuild one native replay step."""

    native_resolution_bytes: bytes
    approval_subject_bytes: bytes
    approval_assertions_bytes: bytes
    authorization_bundle: AuthorizationRecordBundle
    authorization_trust_bundle: AuthorizationTrustSnapshotBundle
    artifact_bundle: RevisionArtifactBundle
    source_validation_bundle: ValidationEvidenceBundle
    resolved_validation_bundle: ValidationEvidenceBundle

    def __post_init__(self) -> None:
        for field_name in (
            "native_resolution_bytes",
            "approval_subject_bytes",
            "approval_assertions_bytes",
        ):
            value = getattr(self, field_name)
            if type(value) is not bytes:
                raise TypeError(f"{field_name} must be exact raw bytes")
            object.__setattr__(self, field_name, bytes(value))
        exact_types = (
            ("authorization_bundle", AuthorizationRecordBundle),
            ("authorization_trust_bundle", AuthorizationTrustSnapshotBundle),
            ("artifact_bundle", RevisionArtifactBundle),
            ("source_validation_bundle", ValidationEvidenceBundle),
            ("resolved_validation_bundle", ValidationEvidenceBundle),
        )
        for field_name, exact_type in exact_types:
            if type(getattr(self, field_name)) is not exact_type:
                raise TypeError(
                    f"{field_name} must be exact {exact_type.__name__} raw material"
                )


CaseDerivationBundle = CaseMutationDerivationBundle | NativeReplayDerivationBundle


@dataclass(frozen=True)
class ProposalPreview:
    """Untrusted rule preview for a structured patch, never an actual run."""

    resolution_id: str
    proposal_id: str
    preview_findings: tuple[dict[str, str], ...]
    state: str = "PROPOSED_UNATTESTED"
    trusted: bool = False
    eligible_for_baseline: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "trusted": self.trusted,
            "eligible_for_baseline": self.eligible_for_baseline,
            "resolution_id": self.resolution_id,
            "proposal_id": self.proposal_id,
            "preview_findings": [dict(item) for item in self.preview_findings],
        }


@dataclass(frozen=True)
class BaselineRecord:
    baseline_id: str
    case_id: str
    source_run_id: str
    case_hash: str
    ruleset_version: str
    resolution_id: str
    approved_case_hash: str
    approved_event_id: str
    approved_event_revision: str
    approved_patch_hash: str
    approved_roles: tuple[str, ...]
    artifact_set_hash: str
    controlled_reference_set_hash: str
    reference_contract_version: str
    source_validation_evidence_set_hash: str
    resolved_validation_evidence_set_hash: str
    validation_evidence_pair_hash: str
    validation_evidence_contract_version: str
    artifact_contract_version: str
    case_schema_version: str
    parser_contract_version: str
    mapping_contract_version: str
    security_root_policy_version: str
    touched_document_artifacts: tuple[dict[str, Any], ...]
    status: str = "BASELINED"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReplayResult:
    before: RunResult
    after: RunResult
    baseline: BaselineRecord | None
    resolution_id: str
    artifact_set_hash: str
    controlled_reference_set_hash: str
    source_validation_evidence_set_hash: str
    resolved_validation_evidence_set_hash: str
    validation_evidence_pair_hash: str
    assurance_state: str = "ATTESTED_REPLACEMENT"

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolution_id": self.resolution_id,
            "assurance_state": self.assurance_state,
            "artifact_set_hash": self.artifact_set_hash,
            "controlled_reference_set_hash": self.controlled_reference_set_hash,
            "source_validation_evidence_set_hash": self.source_validation_evidence_set_hash,
            "resolved_validation_evidence_set_hash": self.resolved_validation_evidence_set_hash,
            "validation_evidence_pair_hash": self.validation_evidence_pair_hash,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "baseline": self.baseline.to_dict() if self.baseline else None,
        }


@dataclass(frozen=True)
class ReplayApprovalSidecar:
    """A05/A06 approval identity kept outside Case and RunResult identity."""

    approval_subject_hash: str
    assertion_hashes: tuple[str, ...]
    approved_roles: tuple[str, ...]
    authorization_record_set_hash: str
    authorization_record_set_contract_version: str
    authorization_authenticity_state: str
    authorization_authenticity_context_hash: str
    authorization_authenticity_binding_hash: str
    authorization_trust_snapshot_hash: str
    authorization_trust_snapshot_contract_version: str
    authorization_trust_policy_hash: str
    authorization_trust_policy_version: str
    execution_nonce: str
    use_policy: str = "SINGLE_REPLAY"
    single_use_status: str = GLOBAL_SINGLE_USE_UNVERIFIED
    global_single_use_verified: bool = False
    eligible_as_consumption_evidence: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StatelessApprovalReplayResult:
    """A replay plus deterministic A05 refs, without a persistence claim."""

    replay: ReplayResult
    replay_approval: ReplayApprovalSidecar

    @property
    def before(self) -> RunResult:
        return self.replay.before

    @property
    def after(self) -> RunResult:
        return self.replay.after

    @property
    def baseline(self) -> BaselineRecord | None:
        return self.replay.baseline

    def to_dict(self) -> dict[str, Any]:
        value = self.replay.to_dict()
        value["replay_approval"] = self.replay_approval.to_dict()
        return value


@dataclass(frozen=True)
class _AttestedResolution:
    """Internal immutable result of one complete artifact/approval admission."""

    resolved_case_json: bytes
    roles: tuple[str, ...]
    context: ArtifactContext
    before_reference_context: _ControlledReferenceContext
    source_validation_identity: _ValidationCaseIdentity
    resolved_validation_identity: _ValidationCaseIdentity
    subject_json: bytes
    patch_hash: str

    def resolved_case(self) -> dict[str, Any]:
        value = strict_json_loads(self.resolved_case_json.decode("utf-8"))
        if not isinstance(value, dict):
            raise ArtifactGateError("internal attested resolved case is invalid")
        return value

    def subject(self) -> dict[str, Any]:
        value = strict_json_loads(self.subject_json.decode("utf-8"))
        if not isinstance(value, dict):
            raise ArtifactGateError("internal attested approval subject is invalid")
        return value


def _resolved_case_from_context(
    case: dict[str, Any],
    resolution: dict[str, Any],
    operations: list[dict[str, Any]],
    context: ArtifactContext,
) -> dict[str, Any]:
    """Build the exact post-resolution case from authoritative artifact facts."""
    try:
        return resolve_case_from_artifact_context(
            case,
            resolution["resolution_id"],
            operations,
            context,
        )
    except RevisionArtifactError as error:
        message = str(error)
        if message.startswith("resolution blocked;"):
            raise ApprovalGateError(message) from error
        raise


def _subject_from_context(
    resolution: dict[str, Any],
    case: dict[str, Any],
    resolved_case: dict[str, Any],
    context: ArtifactContext,
    source_validation_identity: _ValidationCaseIdentity,
    resolved_validation_identity: _ValidationCaseIdentity,
) -> dict[str, Any]:
    event = case["event"]
    subject = {
        "resolution_id": resolution.get("resolution_id"),
        "case_id": case.get("case_id"),
        "event_id": event.get("event_id"),
        "event_revision": event.get("revision"),
        "approved_case_hash": canonical_hash(case),
        "operations": resolution.get("operations", []),
    }
    subject.update(context.subject_fields())
    subject["validation_policy"] = validation_approval_policy(
        case,
        resolved_case,
        _source_identity=source_validation_identity,
        _resolved_identity=resolved_validation_identity,
    )
    return subject


def resolution_approval_subject(
    resolution: dict[str, Any],
    case: dict[str, Any],
    *,
    artifact_bundle: RevisionArtifactBundle | None = None,
    reference_bundle: ControlledReferenceBundle | None = None,
) -> dict[str, Any]:
    """Return the exact pre-resolution snapshot and operations being approved.

    ``approved_case_hash`` is the canonical hash of the complete validated case
    *after* the selected mutation/context has been applied and *before* any
    resolution operation runs. It therefore binds approvals to case metadata,
    the event, every document, and ``active_mutation`` when present.
    """

    if not isinstance(case, dict):
        raise ApprovalGateError("approval subject requires an actual case object")
    if type(artifact_bundle) is not RevisionArtifactBundle:
        raise ArtifactGateError(
            "approval subject requires captured replacement artifact bytes; "
            "unattested proposals cannot be approved"
        )
    case = prepare_case(case)
    if type(reference_bundle) is not ControlledReferenceBundle:
        raise ArtifactGateError(
            "approval subject requires captured controlled-reference target bytes"
        )
    context = prepare_artifact_context(
        artifact_bundle,
        case,
        resolution.get("operations"),
        reference_bundle=reference_bundle,
    )
    return _resolution_approval_subject_from_context(
        resolution,
        case,
        context,
        _native_replay_seal=_NATIVE_REPLAY_SEAL,
    )


def _resolution_approval_subject_from_context(
    resolution: dict[str, Any],
    case: dict[str, Any],
    context: ArtifactContext,
    *,
    _native_replay_seal: object,
) -> dict[str, Any]:
    """Derive the legacy-compatible subject from one sealed local rebuild.

    The context is deliberately accepted only behind the module-local native
    replay seal.  Public callers must provide raw bundles and can never inject
    a prepared context across calls or trust boundaries.
    """

    if _native_replay_seal is not _NATIVE_REPLAY_SEAL:
        raise ArtifactGateError("approval subject context requires an internal seal")
    if type(context) is not ArtifactContext or not context.is_internal():
        raise ArtifactGateError("approval subject context is not exact and sealed")
    case = prepare_case(case)
    operations = _validate_resolution_operations(resolution.get("operations"))
    if resolution.get("replacement_set_id") != context.replacement_set_id:
        raise ArtifactGateError(
            "resolution artifact rejected: replacement_set_id differs from sealed context"
        )
    touched = set(validate_resolution_operation_paths(operations))
    rebuilt_ids = {item.document_id for item in context.artifact_index}
    if touched != rebuilt_ids:
        raise ArtifactGateError(
            "resolution artifact rejected: sealed context does not exactly cover operations"
        )
    try:
        resolved_case = _resolved_case_from_context(
            case, resolution, operations, context
        )
    except RevisionArtifactError as error:
        raise ArtifactGateError(f"resolution artifact rejected: {error}") from error
    return _subject_from_context(
        resolution,
        case,
        resolved_case,
        context,
        _prepare_validation_case_identity(case),
        _prepare_validation_case_identity(resolved_case),
    )


_A05_ARTIFACT_SUBJECT_KEYS = (
    "replacement_set_id",
    "artifact_set_hash",
    "artifact_contract_version",
    "case_schema_version",
    "parser_contract_version",
    "mapping_contract_version",
    "security_root_policy_version",
    "touched_document_artifacts",
)
_A05_REFERENCE_POLICY_KEYS = (
    "reference_contract_version",
    "controlled_reference_set_hash",
    "controlled_reference_source_set_hash",
)


def native_resolution_approval_subject(
    resolution: dict[str, Any],
    case: dict[str, Any],
    *,
    execution_nonce: str,
    artifact_bundle: RevisionArtifactBundle | None = None,
    reference_bundle: ControlledReferenceBundle | None = None,
) -> dict[str, Any]:
    """Derive the exact native A05 subject from captured A02--A04 facts."""

    resolution = validate_native_resolution(resolution)
    if not isinstance(case, dict):
        raise ApprovalGateError("approval subject requires an actual case object")
    if type(artifact_bundle) is not RevisionArtifactBundle:
        raise ArtifactGateError(
            "approval subject requires captured replacement artifact bytes; "
            "unattested proposals cannot be approved"
        )
    if type(reference_bundle) is not ControlledReferenceBundle:
        raise ArtifactGateError(
            "approval subject requires captured controlled-reference target bytes"
        )
    case = prepare_case(case)
    context = prepare_artifact_context(
        artifact_bundle,
        case,
        resolution["operations"],
        reference_bundle=reference_bundle,
    )
    subject, _legacy_projection = _native_subject_and_legacy_projection_from_context(
        resolution,
        case,
        execution_nonce=execution_nonce,
        context=context,
        _native_replay_seal=_NATIVE_REPLAY_SEAL,
    )
    return subject


def native_source_resolution_approval_subject(
    root_source_bundle: CaseSourceBundle,
    prior_derivations: tuple[CaseDerivationBundle, ...],
    native_resolution_bytes: bytes,
    *,
    execution_nonce: str,
    artifact_bundle: RevisionArtifactBundle,
) -> dict[str, Any]:
    """Derive ApprovalSubject 0.2 from a complete raw pre-case closure."""

    if type(root_source_bundle) is not CaseSourceBundle:
        raise TypeError("source approval requires an exact CaseSourceBundle")
    if type(prior_derivations) is not tuple:
        raise TypeError("source approval requires an exact ordered derivation tuple")
    if type(native_resolution_bytes) is not bytes:
        raise TypeError("source approval requires exact native resolution bytes")
    if type(artifact_bundle) is not RevisionArtifactBundle:
        raise TypeError("source approval requires exact replacement artifact bytes")
    try:
        resolution = _native_resolution_from_bytes(native_resolution_bytes)
        context = _rebuild_prior_case_source_context(
            root_source_bundle,
            prior_derivations,
        )
        case = context.case()
        artifact_context = prepare_artifact_context(
            artifact_bundle,
            case,
            resolution["operations"],
            _baseline_reference_context=context._reference_context,
        )
        subject, _legacy_projection = _source_subject_from_context(
            resolution,
            context,
            artifact_context,
            execution_nonce=execution_nonce,
        )
    except ApprovalGateError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ApprovalGateError(
            f"source approval subject derivation failed: {error}"
        ) from error
    if subject["contract_version"] != SOURCE_APPROVAL_SUBJECT_CONTRACT_VERSION:
        raise AssertionError("source approval did not produce Subject 0.2")
    return subject


def _source_subject_from_context(
    resolution: dict[str, Any],
    context: _CaseSourceContext,
    artifact_context: ArtifactContext,
    *,
    execution_nonce: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not _is_sealed_case_source_context(context):
        raise TypeError("source approval requires a sealed pre-case context")
    _legacy_subject, legacy_projection = (
        _native_subject_and_legacy_projection_from_context(
            resolution,
            context.case(),
            execution_nonce=execution_nonce,
            context=artifact_context,
            _native_replay_seal=_NATIVE_REPLAY_SEAL,
        )
    )
    subject = derive_approval_subject(
        resolution_id=resolution["resolution_id"],
        description=resolution["description"],
        operations=legacy_projection["operations"],
        case_id=legacy_projection["case_id"],
        event_id=legacy_projection["event_id"],
        event_revision=legacy_projection["event_revision"],
        pre_case_subject_hash=legacy_projection["approved_case_hash"],
        artifact_subject={
            key: legacy_projection[key] for key in _A05_ARTIFACT_SUBJECT_KEYS
        },
        controlled_reference_policy={
            key: legacy_projection[key] for key in _A05_REFERENCE_POLICY_KEYS
        },
        validation_approval_policy=legacy_projection["validation_policy"],
        required_role_claims=sorted(REQUIRED_APPROVAL_ROLES),
        execution_nonce=execution_nonce,
        pre_case_source=context.assurance().to_dict(),
    )
    return subject, legacy_projection


def _native_resolution_from_bytes(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise TypeError("native resolution must be exact raw bytes")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeError, TypeError, ValueError) as error:
        raise ApprovalGateError("native resolution bytes are invalid JSON") from error
    return validate_native_resolution(value)


def _raw_exact_object(raw: bytes, label: str) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise TypeError(f"{label} must be exact raw bytes")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeError, TypeError, ValueError) as error:
        raise ApprovalGateError(f"{label} bytes are invalid JSON") from error
    if type(value) is not dict:
        raise ApprovalGateError(f"{label} must be an exact JSON object")
    return value


def _approval_assertions_from_bytes(raw: bytes) -> tuple[dict[str, Any], ...]:
    document = _raw_exact_object(raw, "approval assertions")
    if set(document) != {"assertions"} or type(document["assertions"]) is not list:
        raise ApprovalGateError(
            "approval assertions must contain only an exact assertions array"
        )
    if not document["assertions"] or any(
        type(item) is not dict for item in document["assertions"]
    ):
        raise ApprovalGateError("approval assertions must contain exact objects")
    return tuple(document["assertions"])


def _rebuild_prior_case_source_context(
    root_source_bundle: CaseSourceBundle,
    prior_derivations: tuple[CaseDerivationBundle, ...],
) -> _CaseSourceContext:
    if type(root_source_bundle) is not CaseSourceBundle:
        raise TypeError("source replay requires an exact CaseSourceBundle")
    if type(prior_derivations) is not tuple:
        raise TypeError("source replay requires an exact ordered derivation tuple")
    context = _prepare_case_source_context(root_source_bundle)
    if not _is_sealed_case_source_context(context):
        raise TypeError("source replay root context is not sealed")
    for derivation in prior_derivations:
        if type(derivation) is CaseMutationDerivationBundle:
            context = _derive_case_source_mutation(
                context,
                derivation.mutation_bundle,
            )
        elif type(derivation) is NativeReplayDerivationBundle:
            context, _replay = _replay_one_source_derivation(context, derivation)
        else:
            raise TypeError("source replay rejects unknown derivation carriers")
    return context


def _native_subject_and_legacy_projection_from_context(
    resolution: dict[str, Any],
    case: dict[str, Any],
    *,
    execution_nonce: str,
    context: ArtifactContext,
    _native_replay_seal: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if _native_replay_seal is not _NATIVE_REPLAY_SEAL:
        raise ArtifactGateError("native approval context requires an internal seal")
    legacy_projection = _resolution_approval_subject_from_context(
        resolution,
        case,
        context,
        _native_replay_seal=_NATIVE_REPLAY_SEAL,
    )
    try:
        subject = derive_approval_subject(
            resolution_id=resolution["resolution_id"],
            description=resolution["description"],
            operations=legacy_projection["operations"],
            case_id=legacy_projection["case_id"],
            event_id=legacy_projection["event_id"],
            event_revision=legacy_projection["event_revision"],
            pre_case_subject_hash=legacy_projection["approved_case_hash"],
            artifact_subject={
                key: legacy_projection[key]
                for key in _A05_ARTIFACT_SUBJECT_KEYS
            },
            controlled_reference_policy={
                key: legacy_projection[key]
                for key in _A05_REFERENCE_POLICY_KEYS
            },
            validation_approval_policy=legacy_projection["validation_policy"],
            required_role_claims=sorted(REQUIRED_APPROVAL_ROLES),
            execution_nonce=execution_nonce,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ApprovalGateError(
            f"native approval subject derivation failed: {error}"
        ) from error
    return subject, legacy_projection


def validate_native_resolution(resolution: dict[str, Any]) -> dict[str, Any]:
    """Validate the concrete approval-free resolution surface used by A05."""

    if type(resolution) is not dict or set(resolution) != NATIVE_RESOLUTION_KEYS:
        if type(resolution) is dict and "approvals" in resolution:
            raise ApprovalGateError(
                "LEGACY_APPROVAL_UNATTESTED: native resolution must not contain "
                "legacy approvals"
            )
        raise ApprovalGateError(
            "native resolution must contain the exact approval-free key set"
        )
    try:
        value = json.loads(
            json.dumps(
                resolution,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
    except (TypeError, ValueError) as error:
        raise ApprovalGateError("native resolution is not canonical JSON") from error
    if type(value["resolution_id"]) is not str or not value["resolution_id"].strip():
        raise ApprovalGateError("native resolution_id must be an exact non-empty string")
    if type(value["description"]) is not str or not value["description"].strip():
        raise ApprovalGateError("native resolution description must be non-empty")
    if (
        type(value["replacement_set_id"]) is not str
        or not value["replacement_set_id"].strip()
    ):
        raise ApprovalGateError("native replacement_set_id must be non-empty")
    _validate_native_resolution_operations(value["operations"])
    return value


def migrate_legacy_resolution_to_native(resolution: dict[str, Any]) -> dict[str, Any]:
    """Explicitly remove R001-style legacy approval declarations.

    This helper does not upgrade, translate, or attest the old approvals.  The
    caller must independently derive an A05 subject and provide new assertions.
    """

    if type(resolution) is not dict or set(resolution) != NATIVE_RESOLUTION_KEYS | {
        "approvals"
    }:
        raise ApprovalGateError(
            "legacy resolution migration requires the exact R001-style key set"
        )
    approvals = resolution["approvals"]
    if type(approvals) is not list or not approvals:
        raise ApprovalGateError("legacy resolution migration requires legacy approvals")
    return validate_native_resolution(
        {key: copy_value for key, copy_value in resolution.items() if key != "approvals"}
    )


def resolution_patch_hash(
    resolution: dict[str, Any],
    case: dict[str, Any],
    *,
    artifact_bundle: RevisionArtifactBundle | None = None,
    reference_bundle: ControlledReferenceBundle | None = None,
) -> str:
    """Hash the exact case/event snapshot and operations an approval authorizes."""

    return canonical_hash(
        resolution_approval_subject(
            resolution,
            case,
            artifact_bundle=artifact_bundle,
            reference_bundle=reference_bundle,
        )
    )


def resolution_patch_hash_for_subject(
    resolution: dict[str, Any],
    *,
    case_id: str,
    event_id: str,
    event_revision: str,
    approved_case_hash: str,
    artifact_subject: dict[str, Any] | None = None,
    validation_policy: dict[str, Any] | None = None,
) -> str:
    """Recompute a patch hash when the exact case is represented by stored identity fields."""

    subject = {
        "resolution_id": resolution.get("resolution_id"),
        "case_id": case_id,
        "event_id": event_id,
        "event_revision": event_revision,
        "approved_case_hash": approved_case_hash,
        "operations": resolution.get("operations", []),
    }
    if artifact_subject:
        subject.update(artifact_subject)
    if validation_policy:
        subject["validation_policy"] = validation_policy
    return canonical_hash(subject)


def _approved_roles(
    resolution: dict[str, Any],
    subject: dict[str, Any],
    patch_hash: str,
) -> set[str]:
    return {
        item.get("role", "")
        for item in resolution.get("approvals", [])
        if isinstance(item, dict)
        and item.get("role") in REQUIRED_APPROVAL_ROLES
        and item.get("decision") == "APPROVED"
        and item.get("case_id") == subject["case_id"]
        and item.get("event_id") == subject["event_id"]
        and item.get("event_revision") == subject["event_revision"]
        and item.get("approved_case_hash") == subject["approved_case_hash"]
        and item.get("approved_patch_hash") == patch_hash
    }


def _validate_resolution_approvals(
    resolution: dict[str, Any],
    subject: dict[str, Any],
    patch_hash: str,
) -> set[str]:
    approvals = resolution.get("approvals")
    if not isinstance(approvals, list) or not approvals or any(
        not isinstance(item, dict) for item in approvals
    ):
        raise ApprovalGateError("resolution blocked; approvals must be a non-empty list of records")
    required = {
        "role",
        "decision",
        "case_id",
        "event_id",
        "event_revision",
        "approved_case_hash",
        "approved_patch_hash",
    }
    seen_roles: set[str] = set()
    for index, item in enumerate(approvals):
        missing = required - set(item)
        if missing:
            raise ApprovalGateError(
                f"resolution blocked; approval[{index}] missing fields: {sorted(missing)}"
            )
        role = item["role"]
        if role not in REQUIRED_APPROVAL_ROLES:
            raise ApprovalGateError(
                f"resolution blocked; approval[{index}] has unauthorized-role {role!r}"
            )
        if role in seen_roles:
            raise ApprovalGateError(f"resolution blocked; duplicate approval role: {role}")
        seen_roles.add(role)
        if item["decision"] != "APPROVED":
            raise ApprovalGateError(
                f"resolution blocked; approval[{index}] decision is not APPROVED"
            )
        if item["case_id"] != subject["case_id"] or item["event_id"] != subject["event_id"]:
            raise ApprovalGateError(
                "resolution blocked; approval is bound to a different case/event subject"
            )
        if item["event_revision"] != subject["event_revision"]:
            raise ApprovalGateError(
                "resolution blocked; approval is bound to a different event revision"
            )
        if item["approved_case_hash"] != subject["approved_case_hash"]:
            raise ApprovalGateError(
                "resolution blocked; approval is bound to a different exact case snapshot"
            )
        if item["approved_patch_hash"] != patch_hash:
            raise ApprovalGateError(
                "resolution blocked; approval patch hash does not bind the supplied operations"
            )
        if "comment" in item and not isinstance(item["comment"], str):
            raise ApprovalGateError(
                f"resolution blocked; approval[{index}] comment must be a string"
            )
    return _approved_roles(resolution, subject, patch_hash)


def _validate_resolution_operations(operations: Any) -> list[dict[str, Any]]:
    if not isinstance(operations, list):
        raise ApprovalGateError("resolution blocked; operations must be a list")
    if not operations:
        raise ApprovalGateError("resolution blocked; an approved resolution must contain operations")
    for index, operation in enumerate(operations):
        if not isinstance(operation, dict):
            raise ApprovalGateError(
                f"resolution blocked; operation[{index}] must be an object"
            )
        if operation.get("target", "document") != "document":
            raise ApprovalGateError(
                "resolution blocked; v0.1 resolutions may modify documents only; "
                "case/event changes require a new event revision and approval subject"
            )
        document_id = operation.get("document_id")
        if not isinstance(document_id, str) or not document_id.strip():
            raise ApprovalGateError(
                f"resolution blocked; operation[{index}] requires a document_id"
            )
        if operation.get("op") not in {"set", "delete"}:
            raise ApprovalGateError(
                f"resolution blocked; operation[{index}] has unsupported op"
            )
        path = operation.get("path")
        if not isinstance(path, str) or not path:
            raise ApprovalGateError(
                f"resolution blocked; operation[{index}] requires a non-empty path"
            )
        if operation["op"] == "set" and "value" not in operation:
            raise ApprovalGateError(
                f"resolution blocked; operation[{index}] set requires value"
            )
    return operations


def _validate_native_resolution_operations(
    operations: Any,
) -> list[dict[str, Any]]:
    """Close A05 operations to the one approval-bearing set shape."""

    if type(operations) is not list:
        raise ApprovalGateError(
            "native resolution operations must be an exact list"
        )
    _validate_resolution_operations(operations)
    for index, operation in enumerate(operations):
        if type(operation) is not dict or set(operation) != _NATIVE_SET_OPERATION_KEYS:
            raise ApprovalGateError(
                f"native resolution operation[{index}] must contain the exact "
                "set-operation key set"
            )
        if operation["op"] != "set":
            raise ApprovalGateError(
                f"native resolution operation[{index}] op must be set"
            )
    return operations


def preview_resolution(case: dict[str, Any], resolution: dict[str, Any]) -> ProposalPreview:
    """Preview a structured proposal without creating a trusted RunResult shape."""

    case = prepare_case(case)
    if not isinstance(resolution, dict):
        raise ApprovalGateError("resolution blocked; resolution must be an object")
    resolution_id = resolution.get("resolution_id")
    if not isinstance(resolution_id, str) or not resolution_id.strip():
        raise ApprovalGateError("resolution blocked; resolution_id is missing")
    description = resolution.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ApprovalGateError("resolution blocked; description must be a non-empty string")
    operations = _validate_resolution_operations(resolution.get("operations"))
    proposed = apply_mutation(
        case,
        {"mutation_id": f"proposal:{resolution_id}", "operations": operations},
    )
    validate_case(proposed)
    result = run_case(proposed)
    findings = tuple(
        {
            "rule_id": item.rule_id,
            "estimated_status": str(item.status),
            "summary": item.summary,
        }
        for item in result.findings
    )
    proposal_id = hashlib.sha256(
        (
            "QualityCI/proposal-preview/v1\0"
            + canonical_hash(
                {
                    "state": "PROPOSED_UNATTESTED",
                    "case_id": case["case_id"],
                    "event_id": case["event"]["event_id"],
                    "event_revision": case["event"]["revision"],
                    "case_hash": canonical_hash(case),
                    "resolution_id": resolution_id,
                    "operations": operations,
                }
            )
        ).encode("utf-8")
    ).hexdigest()[:16]
    return ProposalPreview(
        resolution_id=resolution_id,
        proposal_id=proposal_id,
        preview_findings=findings,
    )


def _attest_approved_resolution(
    case: dict[str, Any],
    resolution: dict[str, Any],
    *,
    artifact_bundle: RevisionArtifactBundle | None = None,
    reference_bundle: ControlledReferenceBundle | None = None,
    _artifact_context: ArtifactContext | None = None,
    _source_validation_identity: _ValidationCaseIdentity | None = None,
    _resolved_validation_identity: _ValidationCaseIdentity | None = None,
) -> _AttestedResolution:
    case = prepare_case(case)
    if type(artifact_bundle) is not RevisionArtifactBundle:
        raise ArtifactGateError(
            "resolution blocked; actual replay requires an internal replacement artifact bundle; "
            "use preview_resolution for an untrusted proposal"
        )
    if type(reference_bundle) is not ControlledReferenceBundle:
        raise ArtifactGateError(
            "resolution blocked; actual replay requires controlled-reference raw bytes"
        )
    before_reference_context = _prepare_controlled_reference_context(reference_bundle)
    if not isinstance(resolution, dict):
        raise ApprovalGateError("resolution blocked; resolution must be an object")
    event = case["event"]
    risk_level = event.get("risk_level")
    if risk_level not in {"LOW", "MEDIUM", "HIGH"}:
        raise ApprovalGateError("resolution blocked; event risk_level is missing or unsupported")
    resolution_id = resolution.get("resolution_id")
    if not isinstance(resolution_id, str) or not resolution_id.strip():
        raise ApprovalGateError("resolution blocked; resolution_id is missing")
    description = resolution.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ApprovalGateError("resolution blocked; description must be a non-empty string")
    operations = _validate_resolution_operations(resolution.get("operations"))
    try:
        validate_resolution_operation_paths(operations)
        if _artifact_context is None:
            context = prepare_artifact_context(
                artifact_bundle,
                case,
                operations,
                reference_bundle=reference_bundle,
            )
        elif artifact_context_matches_bundle(_artifact_context, artifact_bundle):
            context = _artifact_context
            touched = set(validate_resolution_operation_paths(operations))
            rebuilt_ids = {item.document_id for item in context.artifact_index}
            if touched != rebuilt_ids:
                raise RevisionArtifactError(
                    "internal artifact context does not cover the exact operations"
                )
        else:
            raise RevisionArtifactError("internal artifact context has an invalid type")
        if resolution.get("replacement_set_id") != context.replacement_set_id:
            raise RevisionArtifactError(
                "resolution replacement_set_id does not match captured artifact bundle"
            )
    except RevisionArtifactError as error:
        raise ArtifactGateError(f"resolution artifact rejected: {error}") from error
    try:
        resolved = _resolved_case_from_context(
            case, resolution, operations, context
        )
    except RevisionArtifactError as error:
        raise ArtifactGateError(
            f"resolution artifact rejected: {error}"
        ) from error
    except (KeyError, TypeError, ValueError) as error:
        raise ApprovalGateError(
            f"resolution blocked; resolved case fails validation: {error}"
        ) from error
    source_validation_identity = (
        _source_validation_identity
        if type(_source_validation_identity) is _ValidationCaseIdentity
        and _source_validation_identity.is_sealed()
        else _prepare_validation_case_identity(case)
    )
    resolved_validation_identity = (
        _resolved_validation_identity
        if type(_resolved_validation_identity) is _ValidationCaseIdentity
        and _resolved_validation_identity.is_sealed()
        else _prepare_validation_case_identity(resolved)
    )
    subject = _subject_from_context(
        resolution,
        case,
        resolved,
        context,
        source_validation_identity,
        resolved_validation_identity,
    )
    patch_hash = canonical_hash(subject)
    roles = _validate_resolution_approvals(resolution, subject, patch_hash)
    if not roles:
        raise ApprovalGateError(
            "resolution blocked; no authorized-role approval is bound to the current event revision and patch hash"
        )
    if risk_level == "HIGH" and not REQUIRED_APPROVAL_ROLES.issubset(roles):
        missing = sorted(REQUIRED_APPROVAL_ROLES - roles)
        raise ApprovalGateError(
            "resolution blocked; missing current-event, patch-bound approvals: " + ", ".join(missing)
        )
    sorted_roles = tuple(sorted(roles))
    return _AttestedResolution(
        resolved_case_json=json.dumps(
            resolved,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8"),
        roles=sorted_roles,
        context=context,
        before_reference_context=before_reference_context,
        source_validation_identity=source_validation_identity,
        resolved_validation_identity=resolved_validation_identity,
        subject_json=json.dumps(
            subject,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8"),
        patch_hash=patch_hash,
    )


def attest_approved_resolution(
    case: dict[str, Any],
    resolution: dict[str, Any],
    *,
    artifact_bundle: RevisionArtifactBundle | None = None,
    reference_bundle: ControlledReferenceBundle | None = None,
) -> _AttestedResolution:
    raise ApprovalGateError(
        "LEGACY_APPROVAL_UNATTESTED: public legacy attestation is disabled; "
        "use replay_with_native_approval"
    )


def apply_approved_resolution(
    case: dict[str, Any],
    resolution: dict[str, Any],
    *,
    artifact_bundle: RevisionArtifactBundle | None = None,
    reference_bundle: ControlledReferenceBundle | None = None,
) -> tuple[dict[str, Any], tuple[str, ...], ArtifactContext]:
    raise ApprovalGateError(
        "LEGACY_APPROVAL_UNATTESTED: public legacy apply is disabled; "
        "use replay_with_native_approval"
    )


def _replay_attested_resolution(
    case: dict[str, Any],
    resolution: dict[str, Any],
    attested: _AttestedResolution,
    *,
    source_validation_context: _ValidationEvidenceContext,
    resolved_validation_context: _ValidationEvidenceContext,
) -> ReplayResult:
    if type(attested) is not _AttestedResolution:
        raise ArtifactGateError("actual replay requires an internal AttestedResolution")
    case = prepare_case(case)
    before = _run_case_with_reference_context(
        case,
        attested.before_reference_context,
        source_validation_context,
    )
    resolved_case = attested.resolved_case()
    roles = attested.roles
    context = attested.context
    subject = attested.subject()
    patch_hash = attested.patch_hash
    if context.reference_context is None:
        after = run_case(resolved_case)
    else:
        after = _run_case_with_reference_context(
            resolved_case,
            context.reference_context,
            resolved_validation_context,
        )
    validation_pair_hash = validation_evidence_pair_hash(
        source_validation_context, resolved_validation_context
    )
    baseline: BaselineRecord | None = None
    if after.overall_status == CheckStatus.PASS:
        seed = f"{after.run_id}:{resolution['resolution_id']}:{patch_hash}:{canonical_hash(roles)}"
        baseline = BaselineRecord(
            baseline_id=hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16],
            case_id=after.case_id,
            source_run_id=after.run_id,
            case_hash=after.case_hash,
            ruleset_version=after.ruleset_version,
            resolution_id=resolution["resolution_id"],
            approved_case_hash=subject["approved_case_hash"],
            approved_event_id=subject["event_id"],
            approved_event_revision=subject["event_revision"],
            approved_patch_hash=patch_hash,
            approved_roles=roles,
            artifact_set_hash=context.artifact_set_hash,
            controlled_reference_set_hash=context.reference_context.reference_set_hash,
            reference_contract_version=context.reference_context.contract_version,
            source_validation_evidence_set_hash=source_validation_context.evidence_set_hash,
            resolved_validation_evidence_set_hash=resolved_validation_context.evidence_set_hash,
            validation_evidence_pair_hash=validation_pair_hash,
            validation_evidence_contract_version=VALIDATION_EVIDENCE_CONTRACT_VERSION,
            artifact_contract_version=context.artifact_contract_version,
            case_schema_version=context.case_schema_version,
            parser_contract_version=context.parser_contract_version,
            mapping_contract_version=context.mapping_contract_version,
            security_root_policy_version=context.security_root_policy_version,
            touched_document_artifacts=tuple(
                item.to_dict() for item in context.artifact_index
            ),
        )
    return ReplayResult(
        before=before,
        after=after,
        baseline=baseline,
        resolution_id=resolution["resolution_id"],
        artifact_set_hash=context.artifact_set_hash,
        controlled_reference_set_hash=context.reference_context.reference_set_hash,
        source_validation_evidence_set_hash=source_validation_context.evidence_set_hash,
        resolved_validation_evidence_set_hash=resolved_validation_context.evidence_set_hash,
        validation_evidence_pair_hash=validation_pair_hash,
    )


def _replay_with_validated_native_approval(
    case: dict[str, Any],
    resolution: dict[str, Any],
    *,
    _native_replay_seal: object,
    _artifact_context: ArtifactContext,
    artifact_bundle: RevisionArtifactBundle | None = None,
    reference_bundle: ControlledReferenceBundle | None = None,
    source_validation_bundle: ValidationEvidenceBundle | None = None,
    resolved_validation_bundle: ValidationEvidenceBundle | None = None,
) -> ReplayResult:
    if _native_replay_seal is not _NATIVE_REPLAY_SEAL:
        raise ApprovalGateError(
            "native replay core requires prior exact ApprovalSubject validation"
        )
    if type(artifact_bundle) is not RevisionArtifactBundle:
        raise ArtifactGateError(
            "resolution blocked; actual replay requires an internal replacement artifact bundle; "
            "use preview_resolution for an untrusted proposal"
        )
    if type(reference_bundle) is not ControlledReferenceBundle:
        raise ArtifactGateError(
            "resolution blocked; actual replay requires controlled-reference raw bytes"
        )
    if not artifact_context_matches_bundle(_artifact_context, artifact_bundle):
        raise ArtifactGateError(
            "resolution blocked; internal artifact context differs from raw bundle"
        )
    case = prepare_case(case)
    attested = _attest_approved_resolution(
        case,
        resolution,
        artifact_bundle=artifact_bundle,
        reference_bundle=reference_bundle,
        _artifact_context=_artifact_context,
    )
    if (
        type(source_validation_bundle) is not ValidationEvidenceBundle
        or type(resolved_validation_bundle) is not ValidationEvidenceBundle
    ):
        raise ArtifactGateError(
            "resolution blocked; actual replay requires exact SOURCE and RESOLVED "
            "validation raw bundles"
        )
    resolved_case = attested.resolved_case()
    try:
        source_validation_context = _prepare_validation_evidence_context(
            source_validation_bundle,
            case,
            expected_phase="SOURCE",
            _case_identity=attested.source_validation_identity,
        )
        resolved_validation_context = _prepare_validation_evidence_context(
            resolved_validation_bundle,
            resolved_case,
            expected_phase="RESOLVED",
            _case_identity=attested.resolved_validation_identity,
        )
    except (TypeError, ValueError) as error:
        raise ArtifactGateError(
            f"resolution validation artifacts rejected: {error}"
        ) from error
    return _replay_attested_resolution(
        case,
        resolution,
        attested,
        source_validation_context=source_validation_context,
        resolved_validation_context=resolved_validation_context,
    )


def replay_with_resolution(
    case: dict[str, Any],
    resolution: dict[str, Any],
    *,
    artifact_bundle: RevisionArtifactBundle | None = None,
    reference_bundle: ControlledReferenceBundle | None = None,
    source_validation_bundle: ValidationEvidenceBundle | None = None,
    resolved_validation_bundle: ValidationEvidenceBundle | None = None,
) -> ReplayResult:
    """Reject the unversioned A02--A04 approval surface before execution."""

    raise ApprovalGateError(
        "LEGACY_APPROVAL_UNATTESTED: public legacy replay is disabled; "
        "use replay_with_native_approval"
    )


def replay_with_source_assurance(
    root_source_bundle: CaseSourceBundle,
    prior_derivations: tuple[CaseDerivationBundle, ...],
    current_replay: NativeReplayDerivationBundle,
) -> StatelessApprovalReplayResult:
    """Rebuild root -> ordered raw lineage -> one source-assured replay."""

    if type(root_source_bundle) is not CaseSourceBundle:
        raise TypeError("source replay requires an exact CaseSourceBundle")
    if type(prior_derivations) is not tuple:
        raise TypeError("source replay requires an exact ordered derivation tuple")
    if type(current_replay) is not NativeReplayDerivationBundle:
        raise TypeError("source replay requires an exact NativeReplayDerivationBundle")
    try:
        context = _rebuild_prior_case_source_context(
            root_source_bundle,
            prior_derivations,
        )
        _derived_context, result = _replay_one_source_derivation(
            context,
            current_replay,
        )
        return result
    except ApprovalGateError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ApprovalGateError(f"source replay rejected: {error}") from error


def _replay_one_source_derivation(
    context: _CaseSourceContext,
    replay_bundle: NativeReplayDerivationBundle,
) -> tuple[_CaseSourceContext, StatelessApprovalReplayResult]:
    if not _is_sealed_case_source_context(context):
        raise TypeError("source replay requires a sealed pre-case context")
    if type(replay_bundle) is not NativeReplayDerivationBundle:
        raise TypeError("source replay requires exact native raw material")

    resolution = _native_resolution_from_bytes(
        replay_bundle.native_resolution_bytes
    )
    candidate_subject = validate_approval_subject(
        _raw_exact_object(
            replay_bundle.approval_subject_bytes,
            "approval subject",
        )
    )
    if candidate_subject["contract_version"] != (
        SOURCE_APPROVAL_SUBJECT_CONTRACT_VERSION
    ):
        raise ApprovalGateError(
            "source replay requires ApprovalSubject 0.2"
        )
    assertions = _approval_assertions_from_bytes(
        replay_bundle.approval_assertions_bytes
    )
    authenticity_context = prepare_authorization_authenticity_context(
        replay_bundle.authorization_bundle,
        replay_bundle.authorization_trust_bundle,
    )
    if authenticity_context.state != AUTHORIZATION_AUTHENTICITY_PASS:
        raise ApprovalGateError(
            "authorization authenticity is not PASS: "
            f"{authenticity_context.state}"
        )

    pre_case = context.case()
    try:
        artifact_context = prepare_artifact_context(
            replay_bundle.artifact_bundle,
            pre_case,
            resolution["operations"],
            _baseline_reference_context=context._reference_context,
        )
    except RevisionArtifactError as error:
        raise ArtifactGateError(f"resolution artifact rejected: {error}") from error
    expected_subject, legacy_subject = _source_subject_from_context(
        resolution,
        context,
        artifact_context,
        execution_nonce=candidate_subject["execution_nonce"],
    )
    validate_approval_subject(candidate_subject, expected=expected_subject)
    validation = validate_approval_assertions(
        candidate_subject,
        assertions,
        authenticity_context.record_context,
    )
    require_authenticated_assertion_records(
        assertions,
        authenticity_context,
    )

    legacy_patch_hash = canonical_hash(legacy_subject)
    resolved_case = _resolved_case_from_context(
        pre_case,
        resolution,
        resolution["operations"],
        artifact_context,
    )
    attested = _AttestedResolution(
        resolved_case_json=json.dumps(
            resolved_case,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8"),
        roles=validation.approved_roles,
        context=artifact_context,
        before_reference_context=context._reference_context,
        source_validation_identity=_prepare_validation_case_identity(pre_case),
        resolved_validation_identity=(
            _prepare_validation_case_identity(resolved_case)
        ),
        subject_json=json.dumps(
            legacy_subject,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8"),
        patch_hash=legacy_patch_hash,
    )
    try:
        source_validation_context = _prepare_validation_evidence_context(
            replay_bundle.source_validation_bundle,
            pre_case,
            expected_phase="SOURCE",
            _case_identity=attested.source_validation_identity,
        )
        resolved_validation_context = _prepare_validation_evidence_context(
            replay_bundle.resolved_validation_bundle,
            resolved_case,
            expected_phase="RESOLVED",
            _case_identity=attested.resolved_validation_identity,
        )
    except (TypeError, ValueError) as error:
        raise ArtifactGateError(
            f"resolution validation artifacts rejected: {error}"
        ) from error
    validation_pair_hash = validation_evidence_pair_hash(
        source_validation_context,
        resolved_validation_context,
    )
    assertion_set_hash = _approval_assertion_set_hash(validation)
    output_reference_context = artifact_context.reference_context
    if type(output_reference_context) is not _ControlledReferenceContext:
        raise ArtifactGateError(
            "source replay did not rebuild an output controlled-reference context"
        )
    material = _native_replay_operation_material(
        resolution,
        replay_bundle.native_resolution_bytes,
        artifact_context=artifact_context,
        source_validation_context=source_validation_context,
        resolved_validation_context=resolved_validation_context,
        validation_pair_hash=validation_pair_hash,
        subject_hash=validation.approval_subject_hash,
        assertion_set_hash=assertion_set_hash,
        authenticity_context=authenticity_context,
    )
    derived_context = _derive_case_source_native_replay(
        context,
        operation_blob=replay_bundle.native_resolution_bytes,
        operation_material=material,
        artifact_context=artifact_context,
    )
    if derived_context.case() != resolved_case:
        raise AssertionError(
            "source replay Core output differs from attested artifact rebuild"
        )
    before = _evaluate_source_rooted_case(
        pre_case,
        context._reference_context,
        source_validation_context,
        context,
        expected_validation_phase="SOURCE",
    )
    after = _evaluate_source_rooted_case(
        resolved_case,
        derived_context._reference_context,
        resolved_validation_context,
        derived_context,
        expected_validation_phase="RESOLVED",
    )
    if after.case_source_assurance_state != CASE_SOURCE_DERIVED:
        raise AssertionError("native replay after-case must be SOURCE_ROOTED")
    replay = _source_replay_result(
        before,
        after,
        resolution,
        attested,
        source_validation_context,
        resolved_validation_context,
        validation_pair_hash,
    )
    sidecar = _stateless_approval_sidecar(
        candidate_subject,
        validation,
        authenticity_context,
        replay,
    )
    return derived_context, StatelessApprovalReplayResult(
        replay=replay,
        replay_approval=sidecar,
    )


def _approval_assertion_set_hash(
    validation: StatelessApprovalValidation,
) -> str:
    if type(validation) is not StatelessApprovalValidation:
        raise TypeError("assertion-set identity requires exact validation")
    return hashlib.sha256(
        _APPROVAL_ASSERTION_SET_DOMAIN
        + json.dumps(
            tuple(sorted(validation.assertion_hashes)),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _native_replay_operation_material(
    resolution: dict[str, Any],
    resolution_bytes: bytes,
    *,
    artifact_context: ArtifactContext,
    source_validation_context: _ValidationEvidenceContext,
    resolved_validation_context: _ValidationEvidenceContext,
    validation_pair_hash: str,
    subject_hash: str,
    assertion_set_hash: str,
    authenticity_context: AuthorizationAuthenticityContext,
) -> dict[str, Any]:
    if type(resolution_bytes) is not bytes:
        raise TypeError("native replay operation material requires exact bytes")
    if type(artifact_context) is not ArtifactContext or not (
        artifact_context.is_internal()
    ):
        raise TypeError("native replay operation material requires sealed artifacts")
    if type(authenticity_context) is not AuthorizationAuthenticityContext or not (
        authenticity_context.is_sealed()
    ):
        raise TypeError("native replay operation material requires sealed authorization")
    if authenticity_context.state != AUTHORIZATION_AUTHENTICITY_PASS:
        raise ApprovalGateError("native replay authorization is not PASS")
    output_reference_context = artifact_context.reference_context
    if type(output_reference_context) is not _ControlledReferenceContext:
        raise ArtifactGateError("native replay output reference context is missing")
    operations = [
        {
            "sequence": index,
            "op": "set",
            "target": "document",
            "document_id": operation["document_id"],
            "path": operation["path"],
            "value": {"present": True, "json": operation["value"]},
        }
        for index, operation in enumerate(resolution["operations"])
    ]
    return {
        "operation_kind": "NATIVE_REPLAY",
        "operation_contract_version": (
            CASE_SOURCE_NATIVE_REPLAY_OPERATION_CONTRACT_VERSION
        ),
        "native_resolution_blob": {
            "source_hash": hashlib.sha256(resolution_bytes).hexdigest(),
            "size_bytes": len(resolution_bytes),
        },
        "resolution_id": resolution["resolution_id"],
        "applied_operations": operations,
        "artifact_set_hash": artifact_context.artifact_set_hash,
        "artifact_contract_version": artifact_context.artifact_contract_version,
        "controlled_reference_set_hash": (
            output_reference_context.reference_set_hash
        ),
        "reference_contract_version": output_reference_context.contract_version,
        "source_validation_evidence_set_hash": (
            source_validation_context.evidence_set_hash
        ),
        "resolved_validation_evidence_set_hash": (
            resolved_validation_context.evidence_set_hash
        ),
        "validation_evidence_pair_hash": validation_pair_hash,
        "validation_evidence_contract_version": (
            VALIDATION_EVIDENCE_CONTRACT_VERSION
        ),
        "approval_subject_hash": subject_hash,
        "approval_subject_contract_version": (
            SOURCE_APPROVAL_SUBJECT_CONTRACT_VERSION
        ),
        "approval_assertion_set_hash": assertion_set_hash,
        "approval_assertion_set_domain_version": (
            "QualityCI/approval-assertion-set/v1"
        ),
        "authorization_authenticity_state": authenticity_context.state,
        "authorization_authenticity_context_hash": (
            authenticity_context.authorization_authenticity_context_hash
        ),
        "authorization_authenticity_context_contract_version": (
            authenticity_context.contract_version
        ),
        "authorization_record_set_hash": (
            authenticity_context.authorization_record_set_hash
        ),
        "authorization_record_set_contract_version": (
            authenticity_context.authorization_record_set_contract_version
        ),
        "authorization_trust_snapshot_hash": (
            authenticity_context.trust_snapshot_hash
        ),
        "authorization_trust_snapshot_contract_version": (
            authenticity_context.trust_snapshot_contract_version
        ),
        "authorization_trust_policy_hash": authenticity_context.trust_policy_hash,
        "authorization_trust_policy_version": (
            authenticity_context.trust_policy_version
        ),
    }


def _source_replay_result(
    before: RunResult,
    after: RunResult,
    resolution: dict[str, Any],
    attested: _AttestedResolution,
    source_validation_context: _ValidationEvidenceContext,
    resolved_validation_context: _ValidationEvidenceContext,
    validation_pair_hash: str,
) -> ReplayResult:
    context = attested.context
    if type(context.reference_context) is not _ControlledReferenceContext:
        raise ArtifactGateError("native replay output reference context is missing")
    baseline: BaselineRecord | None = None
    if after.overall_status == CheckStatus.PASS:
        seed = (
            f"{after.run_id}:{resolution['resolution_id']}:"
            f"{attested.patch_hash}:{canonical_hash(attested.roles)}"
        )
        subject = attested.subject()
        baseline = BaselineRecord(
            baseline_id=hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16],
            case_id=after.case_id,
            source_run_id=after.run_id,
            case_hash=after.case_hash,
            ruleset_version=after.ruleset_version,
            resolution_id=resolution["resolution_id"],
            approved_case_hash=subject["approved_case_hash"],
            approved_event_id=subject["event_id"],
            approved_event_revision=subject["event_revision"],
            approved_patch_hash=attested.patch_hash,
            approved_roles=attested.roles,
            artifact_set_hash=context.artifact_set_hash,
            controlled_reference_set_hash=(
                context.reference_context.reference_set_hash
            ),
            reference_contract_version=context.reference_context.contract_version,
            source_validation_evidence_set_hash=(
                source_validation_context.evidence_set_hash
            ),
            resolved_validation_evidence_set_hash=(
                resolved_validation_context.evidence_set_hash
            ),
            validation_evidence_pair_hash=validation_pair_hash,
            validation_evidence_contract_version=(
                VALIDATION_EVIDENCE_CONTRACT_VERSION
            ),
            artifact_contract_version=context.artifact_contract_version,
            case_schema_version=context.case_schema_version,
            parser_contract_version=context.parser_contract_version,
            mapping_contract_version=context.mapping_contract_version,
            security_root_policy_version=context.security_root_policy_version,
            touched_document_artifacts=tuple(
                item.to_dict() for item in context.artifact_index
            ),
        )
    return ReplayResult(
        before=before,
        after=after,
        baseline=baseline,
        resolution_id=resolution["resolution_id"],
        artifact_set_hash=context.artifact_set_hash,
        controlled_reference_set_hash=context.reference_context.reference_set_hash,
        source_validation_evidence_set_hash=(
            source_validation_context.evidence_set_hash
        ),
        resolved_validation_evidence_set_hash=(
            resolved_validation_context.evidence_set_hash
        ),
        validation_evidence_pair_hash=validation_pair_hash,
    )


def replay_with_native_approval(
    case: dict[str, Any],
    resolution: dict[str, Any],
    *,
    approval_subject: dict[str, Any] | None = None,
    approval_assertions: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
    authorization_bundle: AuthorizationRecordBundle | None = None,
    authorization_trust_bundle: AuthorizationTrustSnapshotBundle | None = None,
    artifact_bundle: RevisionArtifactBundle | None = None,
    reference_bundle: ControlledReferenceBundle | None = None,
    source_validation_bundle: ValidationEvidenceBundle | None = None,
    resolved_validation_bundle: ValidationEvidenceBundle | None = None,
) -> StatelessApprovalReplayResult:
    """Run a stateless replay only after native A05 and A06 validation.

    Legacy ``resolution.approvals`` are never upgraded or trusted here.  Once
    native validation succeeds, a private adapter feeds the already-hardened
    A02--A04 replay core; the resulting RunResults remain byte-for-byte A04
    identities.  Global single-use requires a Store and is deliberately not
    claimed by this stateless API.
    """

    if (
        approval_subject is None
        or approval_assertions is None
        or type(authorization_bundle) is not AuthorizationRecordBundle
        or type(authorization_trust_bundle) is not AuthorizationTrustSnapshotBundle
    ):
        raise ApprovalGateError(
            "LEGACY_APPROVAL_UNATTESTED: native replay requires a versioned "
            "ApprovalSubject, ApprovalAssertions, exact raw authorization bundle, "
            "and exact raw authorization trust snapshot"
        )
    try:
        native_resolution = validate_native_resolution(resolution)
        candidate_subject = validate_approval_subject(approval_subject)
        authenticity_context = prepare_authorization_authenticity_context(
            authorization_bundle,
            authorization_trust_bundle,
        )
        if authenticity_context.state != AUTHORIZATION_AUTHENTICITY_PASS:
            raise ApprovalGateError(
                "authorization authenticity is not PASS: "
                f"{authenticity_context.state}"
            )
        if type(artifact_bundle) is not RevisionArtifactBundle:
            raise ArtifactGateError(
                "resolution blocked; actual replay requires an internal replacement "
                "artifact bundle"
            )
        if type(reference_bundle) is not ControlledReferenceBundle:
            raise ArtifactGateError(
                "resolution blocked; actual replay requires controlled-reference raw bytes"
            )
        prepared_case = prepare_case(case)
        artifact_context = prepare_artifact_context(
            artifact_bundle,
            prepared_case,
            native_resolution["operations"],
            reference_bundle=reference_bundle,
        )
        expected_subject, legacy_subject = (
            _native_subject_and_legacy_projection_from_context(
                native_resolution,
                prepared_case,
                execution_nonce=candidate_subject["execution_nonce"],
                context=artifact_context,
                _native_replay_seal=_NATIVE_REPLAY_SEAL,
            )
        )
        validate_approval_subject(candidate_subject, expected=expected_subject)
        validation = validate_approval_assertions(
            candidate_subject,
            approval_assertions,
            authenticity_context.record_context,
        )
        require_authenticated_assertion_records(
            approval_assertions,
            authenticity_context,
        )
    except ApprovalGateError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ApprovalGateError(f"native approval rejected: {error}") from error

    # Do not trust, preserve, or inspect legacy approval comments.  This is a
    # one-way compatibility adapter from validated A05 role claims into the
    # established A02--A04 replay engine, not a legacy-to-native upgrade.
    adapted_resolution = json.loads(
        json.dumps(
            native_resolution,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )
    adapted_resolution["approvals"] = []
    legacy_patch_hash = canonical_hash(legacy_subject)
    adapted_resolution["approvals"] = [
        {
            "role": role,
            "decision": "APPROVED",
            "case_id": legacy_subject["case_id"],
            "event_id": legacy_subject["event_id"],
            "event_revision": legacy_subject["event_revision"],
            "approved_case_hash": legacy_subject["approved_case_hash"],
            "approved_patch_hash": legacy_patch_hash,
        }
        for role in validation.approved_roles
    ]
    replay = _replay_with_validated_native_approval(
        case,
        adapted_resolution,
        _native_replay_seal=_NATIVE_REPLAY_SEAL,
        _artifact_context=artifact_context,
        artifact_bundle=artifact_bundle,
        reference_bundle=reference_bundle,
        source_validation_bundle=source_validation_bundle,
        resolved_validation_bundle=resolved_validation_bundle,
    )
    sidecar = _stateless_approval_sidecar(
        candidate_subject,
        validation,
        authenticity_context,
        replay,
    )
    return StatelessApprovalReplayResult(replay=replay, replay_approval=sidecar)


def _stateless_approval_sidecar(
    subject: dict[str, Any],
    validation: StatelessApprovalValidation,
    authenticity_context: AuthorizationAuthenticityContext,
    replay: ReplayResult,
) -> ReplayApprovalSidecar:
    if validation.approval_subject_hash != approval_subject_hash(subject):
        raise ApprovalGateError("internal approval subject identity mismatch")
    assertion_set_hash = hashlib.sha256(
        _APPROVAL_ASSERTION_SET_DOMAIN
        + json.dumps(
            tuple(sorted(validation.assertion_hashes)),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    binding_hash = authorization_authenticity_binding_hash(
        approval_subject_hash=validation.approval_subject_hash,
        approval_assertion_set_hash=assertion_set_hash,
        authorization_authenticity_context_hash=(
            authenticity_context.authorization_authenticity_context_hash
        ),
        after_case_hash=replay.after.case_hash,
        after_run_hash=canonical_hash(replay.after.to_dict()),
    )
    return ReplayApprovalSidecar(
        approval_subject_hash=validation.approval_subject_hash,
        assertion_hashes=validation.assertion_hashes,
        approved_roles=validation.approved_roles,
        authorization_record_set_hash=validation.authorization_record_set_hash,
        authorization_record_set_contract_version=(
            validation.authorization_record_set_contract_version
        ),
        authorization_authenticity_state=authenticity_context.state,
        authorization_authenticity_context_hash=(
            authenticity_context.authorization_authenticity_context_hash
        ),
        authorization_authenticity_binding_hash=binding_hash,
        authorization_trust_snapshot_hash=authenticity_context.trust_snapshot_hash,
        authorization_trust_snapshot_contract_version=(
            authenticity_context.trust_snapshot_contract_version
        ),
        authorization_trust_policy_hash=authenticity_context.trust_policy_hash,
        authorization_trust_policy_version=authenticity_context.trust_policy_version,
        execution_nonce=subject["execution_nonce"],
        use_policy=subject["use_policy"],
        single_use_status=validation.single_use_status,
        global_single_use_verified=validation.global_single_use_verified,
    )
