"""Test-only native A05 approval constructors for A01--A04 regressions.

The production A05 boundary deliberately rejects the old
``resolution.approvals`` surface.  Older regression suites still need to
exercise their original A01--A04 target gates, so they must enter through the
real native A05 API with the checked-in raw authorization bytes.  Nothing in
this module is imported by production code and no legacy approval is upgraded
or trusted.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qualityci.approval_subject import (
    build_approval_assertion,
    validate_approval_subject,
)
from qualityci.authorization_records import (
    AuthorizationRecordBundle,
    load_authorization_record_bundle,
    prepare_authorization_record_context,
)
from qualityci.authorization_authenticity import (
    AuthorizationTrustSnapshotBundle,
    load_authorization_trust_snapshot_bundle,
)
from qualityci.controlled_references import ControlledReferenceBundle
from qualityci.loader import canonical_hash
from qualityci.revision_artifacts import (
    RevisionArtifactBundle,
    RevisionArtifactError,
    prepare_artifact_context,
)
from qualityci.validation_evidence import ValidationEvidenceBundle
from qualityci.workflow import (
    ApprovalGateError,
    ArtifactGateError,
    NATIVE_RESOLUTION_KEYS,
    StatelessApprovalReplayResult,
    _resolved_case_from_context,
    _validate_resolution_operations,
    native_resolution_approval_subject,
    replay_with_native_approval,
)
from validation_support import validation_bundle


ROOT = Path(__file__).parents[1]
SIGNED_AUTHORIZATION_MANIFEST = (
    ROOT / "tests/fixtures/authorization_authenticity/manifest.json"
)
AUTHORIZATION_TRUST_SNAPSHOT = (
    ROOT / "tests/fixtures/authorization_authenticity/trust_snapshot.json"
)


@dataclass(frozen=True)
class NativeApprovalClaims:
    resolution: dict[str, Any]
    subject: dict[str, Any]
    assertions: tuple[dict[str, Any], ...]
    authorization_bundle: AuthorizationRecordBundle
    authorization_trust_bundle: AuthorizationTrustSnapshotBundle


def native_resolution_value(resolution: dict[str, Any]) -> dict[str, Any]:
    """Return only the approval-free native resolution projection.

    Removing ``approvals`` is explicit test migration, not an assertion that
    any legacy record was valid.  Native assertions are always rebuilt from
    the independent raw authorization fixture below.
    """

    if type(resolution) is not dict:
        return resolution
    allowed = set(NATIVE_RESOLUTION_KEYS) | {"approvals"}
    if not set(resolution).issubset(allowed):
        # Let the production native validator report the precise shape error.
        return copy.deepcopy(resolution)
    return copy.deepcopy(
        {key: value for key, value in resolution.items() if key != "approvals"}
    )


def _execution_nonce(
    case: dict[str, Any],
    resolution: dict[str, Any],
    artifact_bundle: Any,
    reference_bundle: Any,
) -> str:
    artifact_manifest = getattr(artifact_bundle, "canonical_manifest_bytes", b"")
    reference_manifest = getattr(reference_bundle, "canonical_manifest_bytes", b"")
    if type(artifact_manifest) is not bytes:
        artifact_manifest = b""
    if type(reference_manifest) is not bytes:
        reference_manifest = b""
    seed = {
        "case_hash": canonical_hash(case),
        "resolution": resolution,
        "artifact_manifest_hash": hashlib.sha256(
            artifact_manifest
        ).hexdigest(),
        "reference_manifest_hash": hashlib.sha256(
            reference_manifest
        ).hexdigest(),
    }
    digest = canonical_hash(seed)
    return f"EXEC-A05-TEST-{digest[:20].upper()}"


def native_approval_claims(
    case: dict[str, Any],
    resolution: dict[str, Any],
    *,
    artifact_bundle: RevisionArtifactBundle,
    reference_bundle: ControlledReferenceBundle,
    execution_nonce: str | None = None,
    authorization_bundle: AuthorizationRecordBundle | None = None,
    authorization_trust_bundle: AuthorizationTrustSnapshotBundle | None = None,
) -> NativeApprovalClaims:
    native_resolution = native_resolution_value(resolution)
    bundle = authorization_bundle or load_authorization_record_bundle(
        SIGNED_AUTHORIZATION_MANIFEST
    )
    trust_bundle = (
        authorization_trust_bundle
        or load_authorization_trust_snapshot_bundle(AUTHORIZATION_TRUST_SNAPSHOT)
    )
    context = prepare_authorization_record_context(bundle)
    try:
        subject = native_resolution_approval_subject(
            native_resolution,
            case,
            execution_nonce=execution_nonce
            or _execution_nonce(
                case, native_resolution, artifact_bundle, reference_bundle
            ),
            artifact_bundle=artifact_bundle,
            reference_bundle=reference_bundle,
        )
    except RevisionArtifactError as error:
        raise ArtifactGateError(f"resolution artifact rejected: {error}") from error
    subject_hash = canonical_hash(subject)
    assertions = tuple(
        build_approval_assertion(
            subject,
            approval_id=f"APPROVAL-A05-TEST-{subject_hash[:12]}-{index:02d}",
            authorization_context=context,
            authorization_record_id=record.record_id,
            authorization_record_hash=record.content_hash,
            issued_at="2024-02-01T00:00:00Z",
        )
        for index, record in enumerate(context.records(), start=1)
    )
    return NativeApprovalClaims(
        resolution=native_resolution,
        subject=subject,
        assertions=assertions,
        authorization_bundle=bundle,
        authorization_trust_bundle=trust_bundle,
    )


def validate_native_claims_for_inputs(
    case: dict[str, Any],
    resolution: dict[str, Any],
    claims: NativeApprovalClaims,
    *,
    artifact_bundle: Any,
    reference_bundle: Any,
) -> None:
    """Rebind no test material; prove cached claims still match current inputs."""

    try:
        expected = native_resolution_approval_subject(
            native_resolution_value(resolution),
            case,
            execution_nonce=claims.subject["execution_nonce"],
            artifact_bundle=artifact_bundle,
            reference_bundle=reference_bundle,
        )
        validate_approval_subject(claims.subject, expected=expected)
    except ApprovalGateError:
        raise
    except RevisionArtifactError as error:
        raise ArtifactGateError(f"resolution artifact rejected: {error}") from error
    except (KeyError, TypeError, ValueError) as error:
        if "approval subject differs" in str(error):
            raise ApprovalGateError(
                "native approval rejected: approval patch/subject differs from "
                "internally derived subject"
            ) from error
        raise ApprovalGateError(f"native approval rejected: {error}") from error


def dynamic_validation_bundles(
    case: dict[str, Any],
    resolution: dict[str, Any],
    *,
    artifact_bundle: RevisionArtifactBundle,
    reference_bundle: ControlledReferenceBundle,
    result: str = "PASS",
) -> tuple[ValidationEvidenceBundle, ValidationEvidenceBundle]:
    """Build test-only A04 evidence from the exact pre/post case subjects."""

    native_resolution = native_resolution_value(resolution)
    operations = _validate_resolution_operations(native_resolution.get("operations"))
    context = prepare_artifact_context(
        artifact_bundle,
        case,
        operations,
        reference_bundle=reference_bundle,
    )
    resolved = _resolved_case_from_context(
        case, native_resolution, operations, context
    )
    return (
        validation_bundle(case, "SOURCE", result=result),
        validation_bundle(resolved, "RESOLVED", result=result),
    )


def native_approval_replay(
    case: dict[str, Any],
    resolution: dict[str, Any],
    *,
    artifact_bundle: RevisionArtifactBundle,
    reference_bundle: ControlledReferenceBundle,
    source_validation_bundle: ValidationEvidenceBundle | None = None,
    resolved_validation_bundle: ValidationEvidenceBundle | None = None,
    validation_result: str = "PASS",
    claims: NativeApprovalClaims | None = None,
    generate_validation: bool = True,
) -> StatelessApprovalReplayResult:
    runtime_resolution = native_resolution_value(resolution)
    effective_claims = claims or native_approval_claims(
        case,
        resolution,
        artifact_bundle=artifact_bundle,
        reference_bundle=reference_bundle,
    )
    if generate_validation and (
        source_validation_bundle is None or resolved_validation_bundle is None
    ):
        generated_source, generated_resolved = dynamic_validation_bundles(
            case,
            runtime_resolution,
            artifact_bundle=artifact_bundle,
            reference_bundle=reference_bundle,
            result=validation_result,
        )
        source_validation_bundle = source_validation_bundle or generated_source
        resolved_validation_bundle = (
            resolved_validation_bundle or generated_resolved
        )
    return replay_with_native_approval(
        case,
        runtime_resolution,
        approval_subject=effective_claims.subject,
        approval_assertions=list(effective_claims.assertions),
        authorization_bundle=effective_claims.authorization_bundle,
        authorization_trust_bundle=effective_claims.authorization_trust_bundle,
        artifact_bundle=artifact_bundle,
        reference_bundle=reference_bundle,
        source_validation_bundle=source_validation_bundle,
        resolved_validation_bundle=resolved_validation_bundle,
    )


def native_apply_projection(
    case: dict[str, Any],
    resolution: dict[str, Any],
    *,
    artifact_bundle: RevisionArtifactBundle,
    reference_bundle: ControlledReferenceBundle,
    source_validation_bundle: ValidationEvidenceBundle | None = None,
    resolved_validation_bundle: ValidationEvidenceBundle | None = None,
    validation_result: str = "PASS",
    claims: NativeApprovalClaims | None = None,
) -> tuple[dict[str, Any], tuple[str, ...], Any]:
    """Compatibility projection after a real native replay has authorized it."""

    envelope = native_approval_replay(
        case,
        resolution,
        artifact_bundle=artifact_bundle,
        reference_bundle=reference_bundle,
        source_validation_bundle=source_validation_bundle,
        resolved_validation_bundle=resolved_validation_bundle,
        validation_result=validation_result,
        claims=claims,
    )
    native_resolution = native_resolution_value(resolution)
    operations = _validate_resolution_operations(native_resolution.get("operations"))
    context = prepare_artifact_context(
        artifact_bundle,
        case,
        operations,
        reference_bundle=reference_bundle,
    )
    resolved = _resolved_case_from_context(
        case, native_resolution, operations, context
    )
    return resolved, envelope.replay_approval.approved_roles, context


def canonical_copy(value: Any) -> Any:
    """A strict JSON copy useful when a test mutates one native claim."""

    return json.loads(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )
