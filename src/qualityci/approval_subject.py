"""Versioned, byte-bound A05 approval subjects and assertions.

This module validates deterministic claims only.  It does not establish real
identity, authority, signature validity, trusted time, or global single-use.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .authorization_records import (
    AuthorizationRecordClaim,
    AuthorizationRecordContext,
)
from .case_source_assurance import (
    CASE_SOURCE_BOUND,
    CASE_SOURCE_DERIVED,
    validate_case_source_assurance_payload,
)
from .loader import normalized_identity, parse_rfc3339_utc


LEGACY_APPROVAL_SUBJECT_CONTRACT_VERSION = "qualityci-approval-subject-0.1"
SOURCE_APPROVAL_SUBJECT_CONTRACT_VERSION = "qualityci-approval-subject-0.2"
# Kept as the legacy write constant for existing 0.1 callers.  A08 callers
# opt in only by providing an exact pre_case_source to derive_approval_subject.
APPROVAL_SUBJECT_CONTRACT_VERSION = LEGACY_APPROVAL_SUBJECT_CONTRACT_VERSION
APPROVAL_ASSERTION_CONTRACT_VERSION = "qualityci-approval-assertion-0.1"
APPROVAL_POLICY_VERSION = "qualityci-approval-policy-0.1"
APPROVAL_PURPOSE_CODE = "APPLY_APPROVED_RESOLUTION"
APPROVAL_SCOPE_CODE = "EXACT_SUBJECT"
APPROVAL_USE_POLICY = "SINGLE_REPLAY"
GLOBAL_SINGLE_USE_UNVERIFIED = "GLOBAL_SINGLE_USE_UNVERIFIED"
APPROVAL_REQUIRED_ROLE_CLAIMS = frozenset(
    {"PROCESS_OWNER", "QUALITY_MANAGER"}
)

_SUBJECT_DOMAIN = b"QualityCI/approval-subject/v1\0"
_SOURCE_SUBJECT_DOMAIN = b"QualityCI/approval-subject/v2\0"
_ASSERTION_DOMAIN = b"QualityCI/approval-assertion/v1\0"
_TEXT_DOMAIN = b"QualityCI/approval-text/v1\0"
_OPERATIONS_DOMAIN = b"QualityCI/approval-operations/v1\0"
_ARTIFACT_DOMAIN = b"QualityCI/approval-artifact-subject/v1\0"
_REFERENCE_DOMAIN = b"QualityCI/approval-reference-policy/v1\0"
_VALIDATION_DOMAIN = b"QualityCI/approval-validation-policy/v1\0"

APPROVAL_SUBJECT_KEYS = frozenset(
    {
        "contract_version",
        "purpose_code",
        "scope_code",
        "purpose_text",
        "purpose_text_hash",
        "resolution_id",
        "resolution_description_hash",
        "operations_hash",
        "case_id",
        "event_id",
        "event_revision",
        "pre_case_subject_hash",
        "artifact_subject_hash",
        "controlled_reference_policy_hash",
        "validation_approval_policy_hash",
        "approval_policy_version",
        "required_role_claims",
        "use_policy",
        "execution_nonce",
    }
)
SOURCE_APPROVAL_SUBJECT_KEYS = APPROVAL_SUBJECT_KEYS | {"pre_case_source"}

APPROVAL_ASSERTION_KEYS = frozenset(
    {
        "assertion_contract_version",
        "approval_id",
        "approval_subject_hash",
        "decision",
        "approver_id_claim",
        "role_claim",
        "authorization_record_id",
        "authorization_record_hash",
        "issued_at",
        "effective_from",
        "expires_at",
    }
)

FORBIDDEN_SUBJECT_POST_FACT_KEYS = frozenset(
    {
        "approval_subject_hash",
        "approval_assertion",
        "approval_assertions",
        "assertion_hash",
        "assertion_hashes",
        "authorization_record_hash",
        "before",
        "after",
        "before_run",
        "after_run",
        "run_id",
        "run_hash",
        "source_validation_evidence_set_hash",
        "resolved_validation_evidence_set_hash",
        "validation_evidence_pair_hash",
        "baseline",
        "replay_admission_hash",
        "replay_ledger_hash",
        "consumption",
        "consumption_hash",
        "signature",
    }
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _domain_hash(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + _canonical_bytes(value)).hexdigest()


def _exact_nonempty(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{label} must be an exact non-empty string")
    return value


def _lower_sha(value: Any, label: str) -> str:
    value = _exact_nonempty(value, label)
    if len(value) != 64 or value != value.lower():
        raise ValueError(f"{label} must be a lowercase SHA-256")
    try:
        int(value, 16)
    except ValueError as error:
        raise ValueError(f"{label} must be a lowercase SHA-256") from error
    return value


def approval_subject_hash(subject: Mapping[str, Any]) -> str:
    value = validate_approval_subject(subject)
    domain = (
        _SUBJECT_DOMAIN
        if value["contract_version"] == LEGACY_APPROVAL_SUBJECT_CONTRACT_VERSION
        else _SOURCE_SUBJECT_DOMAIN
    )
    return hashlib.sha256(domain + _canonical_bytes(value)).hexdigest()


def approval_assertion_hash(assertion: Mapping[str, Any]) -> str:
    value = validate_approval_assertion_shape(assertion)
    return hashlib.sha256(_ASSERTION_DOMAIN + _canonical_bytes(value)).hexdigest()


def derive_approval_subject(
    *,
    resolution_id: str,
    description: str,
    operations: Sequence[Mapping[str, Any]],
    case_id: str,
    event_id: str,
    event_revision: str,
    pre_case_subject_hash: str,
    artifact_subject: Mapping[str, Any],
    controlled_reference_policy: Mapping[str, Any],
    validation_approval_policy: Mapping[str, Any],
    required_role_claims: Sequence[str],
    execution_nonce: str,
    pre_case_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive every A05 subject field from captured pre-approval facts."""

    resolution_id = _exact_nonempty(resolution_id, "resolution_id")
    description = _exact_nonempty(description, "resolution description")
    case_id = _exact_nonempty(case_id, "case_id")
    event_id = _exact_nonempty(event_id, "event_id")
    event_revision = _exact_nonempty(event_revision, "event_revision")
    execution_nonce = _exact_nonempty(execution_nonce, "execution_nonce")
    _lower_sha(pre_case_subject_hash, "pre_case_subject_hash")
    if type(operations) not in {list, tuple} or not operations:
        raise ValueError("operations must be a non-empty exact sequence")
    if any(type(item) is not dict for item in operations):
        raise ValueError("operations members must be exact objects")
    if type(artifact_subject) is not dict or not artifact_subject:
        raise ValueError("artifact_subject must be an exact non-empty object")
    if type(controlled_reference_policy) is not dict or not controlled_reference_policy:
        raise ValueError(
            "controlled_reference_policy must be an exact non-empty object"
        )
    if type(validation_approval_policy) is not dict or not validation_approval_policy:
        raise ValueError("validation_approval_policy must be an exact non-empty object")
    if type(required_role_claims) not in {list, tuple}:
        raise ValueError("required_role_claims must be an exact sequence")
    roles = list(required_role_claims)
    if any(type(role) is not str or not role.strip() for role in roles):
        raise ValueError("required_role_claims must contain exact non-empty strings")
    roles.sort(key=lambda value: (normalized_identity(value), value))
    if len({normalized_identity(role) for role in roles}) != len(roles):
        raise ValueError("required_role_claims contains normalized duplicates")

    text_hash = hashlib.sha256(_TEXT_DOMAIN + description.encode("utf-8")).hexdigest()
    source: dict[str, Any] | None = None
    if pre_case_source is not None:
        if type(pre_case_source) is not dict:
            raise ValueError("pre_case_source must be an exact object")
        source = validate_case_source_assurance_payload(dict(pre_case_source))
        if source["case_source_assurance_state"] not in {
            CASE_SOURCE_BOUND,
            CASE_SOURCE_DERIVED,
        }:
            raise ValueError("pre_case_source must be BOUND or SOURCE_ROOTED")

    subject = {
        "contract_version": (
            LEGACY_APPROVAL_SUBJECT_CONTRACT_VERSION
            if source is None
            else SOURCE_APPROVAL_SUBJECT_CONTRACT_VERSION
        ),
        "purpose_code": APPROVAL_PURPOSE_CODE,
        "scope_code": APPROVAL_SCOPE_CODE,
        "purpose_text": description,
        "purpose_text_hash": text_hash,
        "resolution_id": resolution_id,
        "resolution_description_hash": text_hash,
        "operations_hash": _domain_hash(_OPERATIONS_DOMAIN, list(operations)),
        "case_id": case_id,
        "event_id": event_id,
        "event_revision": event_revision,
        "pre_case_subject_hash": pre_case_subject_hash,
        "artifact_subject_hash": _domain_hash(_ARTIFACT_DOMAIN, artifact_subject),
        "controlled_reference_policy_hash": _domain_hash(
            _REFERENCE_DOMAIN, controlled_reference_policy
        ),
        "validation_approval_policy_hash": _domain_hash(
            _VALIDATION_DOMAIN, validation_approval_policy
        ),
        "approval_policy_version": APPROVAL_POLICY_VERSION,
        "required_role_claims": roles,
        "use_policy": APPROVAL_USE_POLICY,
        "execution_nonce": execution_nonce,
    }
    if source is not None:
        subject["pre_case_source"] = source
    return validate_approval_subject(subject)


def validate_approval_subject(
    subject: Mapping[str, Any],
    *,
    expected: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if type(subject) is not dict:
        raise ValueError("approval subject must be an exact object")
    version = subject.get("contract_version")
    if version == LEGACY_APPROVAL_SUBJECT_CONTRACT_VERSION:
        expected_keys = APPROVAL_SUBJECT_KEYS
    elif version == SOURCE_APPROVAL_SUBJECT_CONTRACT_VERSION:
        expected_keys = SOURCE_APPROVAL_SUBJECT_KEYS
    else:
        raise ValueError("unsupported approval subject contract_version")
    extra = set(subject) - SOURCE_APPROVAL_SUBJECT_KEYS
    forbidden = extra & FORBIDDEN_SUBJECT_POST_FACT_KEYS
    if forbidden:
        raise ValueError(
            f"approval subject contains forbidden post-fact keys: {sorted(forbidden)}"
        )
    if set(subject) != expected_keys:
        raise ValueError("approval subject must contain the exact versioned key set")
    for key in APPROVAL_SUBJECT_KEYS - {"required_role_claims"}:
        _exact_nonempty(subject[key], f"approval subject {key}")
    for key in (
        "purpose_text_hash",
        "resolution_description_hash",
        "operations_hash",
        "pre_case_subject_hash",
        "artifact_subject_hash",
        "controlled_reference_policy_hash",
        "validation_approval_policy_hash",
    ):
        _lower_sha(subject[key], f"approval subject {key}")
    if version == SOURCE_APPROVAL_SUBJECT_CONTRACT_VERSION:
        source = subject["pre_case_source"]
        if type(source) is not dict:
            raise ValueError("approval subject pre_case_source must be an exact object")
        source = validate_case_source_assurance_payload(source)
        if source["case_source_assurance_state"] not in {
            CASE_SOURCE_BOUND,
            CASE_SOURCE_DERIVED,
        }:
            raise ValueError(
                "approval subject pre_case_source must be BOUND or SOURCE_ROOTED"
            )
    if subject["purpose_code"] != APPROVAL_PURPOSE_CODE:
        raise ValueError("unsupported approval purpose_code")
    if subject["scope_code"] != APPROVAL_SCOPE_CODE:
        raise ValueError("unsupported approval scope_code")
    if subject["approval_policy_version"] != APPROVAL_POLICY_VERSION:
        raise ValueError("unsupported approval_policy_version")
    if subject["use_policy"] != APPROVAL_USE_POLICY:
        raise ValueError("unsupported approval use_policy")
    roles = subject["required_role_claims"]
    if type(roles) is not list or any(
        type(role) is not str or not role.strip() for role in roles
    ):
        raise ValueError("required_role_claims must be an exact string array")
    canonical_roles = sorted(
        roles, key=lambda value: (normalized_identity(value), value)
    )
    if roles != canonical_roles or len(
        {normalized_identity(role) for role in roles}
    ) != len(roles):
        raise ValueError("required_role_claims must be canonical and unique")
    if roles != sorted(APPROVAL_REQUIRED_ROLE_CLAIMS):
        raise ValueError(
            "required_role_claims must exactly match the approval policy roles"
        )
    text_hash = hashlib.sha256(
        _TEXT_DOMAIN + subject["purpose_text"].encode("utf-8")
    ).hexdigest()
    if (
        subject["purpose_text_hash"] != text_hash
        or subject["resolution_description_hash"] != text_hash
    ):
        raise ValueError("approval subject captured purpose text hash mismatch")
    value = json.loads(_canonical_bytes(subject))
    if expected is not None:
        expected_value = validate_approval_subject(expected)
        if value != expected_value:
            raise ValueError("approval subject differs from internally derived subject")
    return value


def _authorization_record_binding(
    context: AuthorizationRecordContext,
    record_id: str,
    content_hash: str,
) -> AuthorizationRecordClaim:
    """Resolve one claim only through the exact sealed raw-capture context."""

    if type(context) is not AuthorizationRecordContext or not context.is_sealed():
        raise ValueError("authorization record context is not exact and sealed")
    record = context.record(record_id, content_hash)
    if (
        record.purpose_code != APPROVAL_PURPOSE_CODE
        or record.scope_code != APPROVAL_SCOPE_CODE
    ):
        raise ValueError("authorization purpose/scope claim is unsupported")
    effective = parse_rfc3339_utc(
        record.effective_from, "authorization effective_from"
    )
    expires = parse_rfc3339_utc(record.expires_at, "authorization expires_at")
    if expires < effective:
        raise ValueError("authorization expires_at precedes effective_from")
    return record


def build_approval_assertion(
    subject: Mapping[str, Any],
    *,
    approval_id: str,
    authorization_context: AuthorizationRecordContext,
    authorization_record_id: str,
    authorization_record_hash: str,
    issued_at: str,
    decision: str = "APPROVED",
) -> dict[str, Any]:
    subject_hash = approval_subject_hash(subject)
    authorization = _authorization_record_binding(
        authorization_context,
        authorization_record_id,
        authorization_record_hash,
    )
    assertion = {
        "assertion_contract_version": APPROVAL_ASSERTION_CONTRACT_VERSION,
        "approval_id": _exact_nonempty(approval_id, "approval_id"),
        "approval_subject_hash": subject_hash,
        "decision": decision,
        "approver_id_claim": authorization.approver_id_claim,
        "role_claim": authorization.role_claim,
        "authorization_record_id": authorization.record_id,
        "authorization_record_hash": authorization.content_hash,
        "issued_at": issued_at,
        "effective_from": authorization.effective_from,
        "expires_at": authorization.expires_at,
    }
    return validate_approval_assertion_shape(assertion)


def validate_approval_assertion_shape(
    assertion: Mapping[str, Any],
) -> dict[str, Any]:
    if type(assertion) is not dict or set(assertion) != APPROVAL_ASSERTION_KEYS:
        raise ValueError("approval assertion must contain the exact versioned key set")
    for key in APPROVAL_ASSERTION_KEYS:
        _exact_nonempty(assertion[key], f"approval assertion {key}")
    if assertion["assertion_contract_version"] != APPROVAL_ASSERTION_CONTRACT_VERSION:
        raise ValueError("unsupported approval assertion contract_version")
    if assertion["decision"] != "APPROVED":
        raise ValueError("approval assertion decision must be APPROVED")
    if assertion["role_claim"] not in APPROVAL_REQUIRED_ROLE_CLAIMS:
        raise ValueError("approval assertion role_claim is unsupported")
    _lower_sha(assertion["approval_subject_hash"], "approval assertion subject hash")
    _lower_sha(
        assertion["authorization_record_hash"],
        "approval assertion authorization record hash",
    )
    effective = parse_rfc3339_utc(
        assertion["effective_from"], "approval assertion effective_from"
    )
    issued = parse_rfc3339_utc(
        assertion["issued_at"], "approval assertion issued_at"
    )
    expires = parse_rfc3339_utc(
        assertion["expires_at"], "approval assertion expires_at"
    )
    if not effective <= issued <= expires:
        raise ValueError("approval assertion static time window mismatch")
    return json.loads(_canonical_bytes(assertion))


@dataclass(frozen=True)
class StatelessApprovalValidation:
    approval_subject_hash: str
    assertion_hashes: tuple[str, ...]
    approved_roles: tuple[str, ...]
    authorization_record_set_hash: str
    authorization_record_set_contract_version: str
    single_use_status: str = GLOBAL_SINGLE_USE_UNVERIFIED
    global_single_use_verified: bool = False


def validate_approval_assertions(
    subject: Mapping[str, Any],
    assertions: Sequence[Mapping[str, Any]],
    authorization_context: AuthorizationRecordContext,
) -> StatelessApprovalValidation:
    subject_value = validate_approval_subject(subject)
    subject_hash = approval_subject_hash(subject_value)
    if type(assertions) not in {list, tuple} or not assertions:
        raise ValueError("native approval requires explicit assertions")
    if (
        type(authorization_context) is not AuthorizationRecordContext
        or not authorization_context.is_sealed()
    ):
        raise ValueError("native approval requires an exact sealed authorization context")
    records: dict[str, AuthorizationRecordClaim] = {}
    for record in authorization_context.records():
        key = normalized_identity(record.record_id)
        if key in records:
            raise ValueError("authorization records contain normalized duplicate IDs")
        records[key] = record

    seen_approval_ids: set[str] = set()
    seen_roles: set[str] = set()
    assertion_hashes: list[str] = []
    for raw in assertions:
        assertion = validate_approval_assertion_shape(raw)
        approval_key = normalized_identity(assertion["approval_id"])
        if approval_key in seen_approval_ids:
            raise ValueError("approval assertions contain normalized duplicate approval_id")
        seen_approval_ids.add(approval_key)
        if assertion["approval_subject_hash"] != subject_hash:
            raise ValueError("approval assertion is bound to a different subject")
        role = assertion["role_claim"]
        if role not in subject_value["required_role_claims"]:
            raise ValueError("approval assertion role is not required by the subject")
        if role in seen_roles:
            raise ValueError("approval assertions contain duplicate role claims")
        seen_roles.add(role)
        record = records.get(normalized_identity(assertion["authorization_record_id"]))
        if record is None:
            raise ValueError("approval assertion authorization record is missing")
        if (
            assertion["authorization_record_id"] != record.record_id
            or assertion["authorization_record_hash"] != record.content_hash
            or assertion["approver_id_claim"] != record.approver_id_claim
            or role != record.role_claim
            or record.purpose_code != subject_value["purpose_code"]
            or record.scope_code != subject_value["scope_code"]
            or assertion["effective_from"] != record.effective_from
            or assertion["expires_at"] != record.expires_at
        ):
            raise ValueError("approval assertion authorization record join mismatch")
        assertion_hashes.append(approval_assertion_hash(assertion))

    required_roles = set(subject_value["required_role_claims"])
    if seen_roles != required_roles:
        raise ValueError(
            f"native approval is missing required role assertions: "
            f"{sorted(required_roles - seen_roles)}"
        )
    if len(assertion_hashes) != len(set(assertion_hashes)):
        raise ValueError("approval assertions contain duplicate hashes")
    return StatelessApprovalValidation(
        approval_subject_hash=subject_hash,
        assertion_hashes=tuple(sorted(assertion_hashes)),
        approved_roles=tuple(sorted(seen_roles)),
        authorization_record_set_hash=authorization_context.record_set_hash,
        authorization_record_set_contract_version=authorization_context.contract_version,
    )
