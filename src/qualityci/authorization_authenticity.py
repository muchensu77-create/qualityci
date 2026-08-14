"""Fail-closed A06 authorization authenticity boundary.

The public API in this module is intentionally separate from A05's byte-bound
claim parser.  A05 legacy records remain inspectable, but can never acquire an
authenticated state by inference.  Verification of the signed 0.2 contract is
added behind the same sealed context API.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .authorization_records import (
    AUTHORIZATION_RECORD_SET_VERSION,
    SIGNED_AUTHORIZATION_RECORD_SET_VERSION,
    AuthorizationRecordBundle,
    AuthorizationRecordClaim,
    AuthorizationRecordContext,
    _capture_regular_file_once,
    prepare_authorization_record_context,
)
from .loader import normalized_identity, parse_rfc3339_utc, strict_json_loads


AUTHORIZATION_AUTHENTICITY_PASS = "PASS"
AUTHORIZATION_AUTHENTICITY_CONTRADICTED = "CONTRADICTED"
AUTHORIZATION_AUTHENTICITY_UNVERIFIABLE = "UNVERIFIABLE"
LEGACY_UNSIGNED_AUTHORIZATION = "LEGACY_UNSIGNED_AUTHORIZATION"

AUTHORIZATION_TRUST_SNAPSHOT_CONTRACT_VERSION = (
    "qualityci-authorization-trust-snapshot-0.1"
)
AUTHORIZATION_TRUST_POLICY_VERSION = "qualityci-authorization-trust-policy-0.1"
AUTHORIZATION_AUTHENTICITY_CONTEXT_VERSION = (
    "qualityci-authorization-authenticity-context-0.1"
)
AUTHORIZATION_AUTHENTICITY_BINDING_VERSION = (
    "qualityci-authorization-authenticity-binding-0.1"
)

MAX_AUTHORIZATION_TRUST_SNAPSHOT_BYTES = 256 * 1024
MAX_AUTHORIZATION_TRUST_JSON_DEPTH = 16
_CONTEXT_SEAL = object()
_SNAPSHOT_DOMAIN = b"QualityCI/authorization-trust-snapshot/v1\0"
_SNAPSHOT_HASH_DOMAIN = b"QualityCI/authorization-trust-snapshot-hash/v1\0"
_RECORD_SIGNATURE_DOMAIN = b"QualityCI/signed-authorization-record/v1\0"
_POLICY_DOMAIN = b"QualityCI/authorization-trust-policy/v1\0"
_CONTEXT_DOMAIN = b"QualityCI/authorization-authenticity-context/v1\0"
_BINDING_DOMAIN = b"QualityCI/authorization-authenticity-binding/v1\0"

_FIXED_POLICY = {
    "anchor_id": "QUALITYCI_SYNTHETIC_ROOT_2026",
    "anchor_public_key": "DiGh7dlGivcJqWZ4xpdviGh3cAenSoAPMFUSGqiGamo=",
    "contract_version": AUTHORIZATION_TRUST_POLICY_VERSION,
    "minimum_snapshot_sequence": 1,
    "required_role_claims": ["PROCESS_OWNER", "QUALITY_MANAGER"],
    "signature_algorithm": "ED25519",
    "snapshot_id": "QCI-SYNTHETIC-TRUST-2026-001",
    "trust_domain": "QUALITYCI_SYNTHETIC_LOCAL_V1",
}

_SNAPSHOT_KEYS = {
    "anchor_id",
    "contract_version",
    "issued_at",
    "issuer_keys",
    "signature",
    "signature_algorithm",
    "snapshot_id",
    "snapshot_sequence",
    "trust_domain",
}
_ISSUER_KEY_KEYS = {
    "allowed_purpose_codes",
    "allowed_role_claims",
    "allowed_scope_codes",
    "effective_from",
    "expires_at",
    "issuer_id",
    "public_key",
    "revocation_status",
    "revoked_at",
    "verification_key_id",
}
_SIGNED_RECORD_KEYS = {
    "approver_id_claim",
    "contract_version",
    "effective_from",
    "expires_at",
    "issued_at",
    "issuer_id",
    "purpose_code",
    "record_id",
    "role_claim",
    "scope_code",
    "signature",
    "signature_algorithm",
    "trust_domain",
    "verification_key_id",
}


class AuthorizationAuthenticityError(ValueError):
    """Raised when untrusted material cannot satisfy the A06 gate."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _lower_sha(value: Any, label: str) -> str:
    if type(value) is not str or len(value) != 64 or value != value.lower():
        raise AuthorizationAuthenticityError(f"{label} must be a lowercase SHA-256")
    try:
        int(value, 16)
    except ValueError as error:
        raise AuthorizationAuthenticityError(
            f"{label} must be a lowercase SHA-256"
        ) from error
    return value


def _exact_string(value: Any, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise AuthorizationAuthenticityError(
            f"{label} must be an exact non-empty trimmed string"
        )
    if any(ord(character) < 32 for character in value):
        raise AuthorizationAuthenticityError(f"{label} contains control characters")
    return value


def _strict_base64(value: Any, label: str, expected_size: int) -> bytes:
    value = _exact_string(value, label)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise AuthorizationAuthenticityError(f"{label} is not canonical base64") from error
    if len(raw) != expected_size or base64.b64encode(raw).decode("ascii") != value:
        raise AuthorizationAuthenticityError(f"{label} has invalid encoded size")
    return raw


def _exact_sorted_strings(
    value: Any,
    label: str,
    *,
    allowed: frozenset[str],
) -> tuple[str, ...]:
    if type(value) is not list or not value or any(type(item) is not str for item in value):
        raise AuthorizationAuthenticityError(f"{label} must be a non-empty exact array")
    result = tuple(_exact_string(item, label) for item in value)
    canonical = tuple(sorted(result, key=lambda item: (normalized_identity(item), item)))
    if result != canonical or len({normalized_identity(item) for item in result}) != len(result):
        raise AuthorizationAuthenticityError(f"{label} must be unique and canonical")
    if not set(result).issubset(allowed):
        raise AuthorizationAuthenticityError(f"{label} contains unsupported capability")
    return result


def _snapshot_value(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_AUTHORIZATION_TRUST_SNAPSHOT_BYTES:
        raise AuthorizationAuthenticityError(
            "authorization trust snapshot requires bounded exact immutable bytes"
        )
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise AuthorizationAuthenticityError(
            "authorization trust snapshot is not strict UTF-8 JSON"
        ) from error
    if type(value) is not dict or set(value) != _SNAPSHOT_KEYS:
        raise AuthorizationAuthenticityError(
            "authorization trust snapshot has unsupported root shape"
        )
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_AUTHORIZATION_TRUST_JSON_DEPTH:
            raise AuthorizationAuthenticityError(
                "authorization trust snapshot exceeds JSON depth limit"
            )
        if type(current) is dict:
            stack.extend((item, depth + 1) for item in current.values())
        elif type(current) is list:
            stack.extend((item, depth + 1) for item in current)
    if raw != _canonical_bytes(value):
        raise AuthorizationAuthenticityError(
            "authorization trust snapshot must be canonical JSON"
        )
    if value.get("contract_version") != AUTHORIZATION_TRUST_SNAPSHOT_CONTRACT_VERSION:
        raise AuthorizationAuthenticityError(
            "unsupported authorization trust snapshot contract_version"
        )
    for field in (
        "snapshot_id",
        "issued_at",
        "trust_domain",
        "anchor_id",
        "signature_algorithm",
        "signature",
    ):
        _exact_string(value[field], f"authorization trust snapshot {field}")
    if type(value["snapshot_sequence"]) is not int or value["snapshot_sequence"] <= 0:
        raise AuthorizationAuthenticityError(
            "authorization trust snapshot_sequence must be an exact positive integer"
        )
    snapshot_issued_at = parse_rfc3339_utc(
        value["issued_at"], "authorization trust snapshot issued_at"
    )
    if value["signature_algorithm"] != "ED25519":
        raise AuthorizationAuthenticityError(
            "authorization trust snapshot signature_algorithm is unsupported"
        )
    _strict_base64(value["signature"], "authorization trust snapshot signature", 64)
    issuer_keys = value["issuer_keys"]
    if (
        type(issuer_keys) is not list
        or len(issuer_keys) != 2
        or any(type(item) is not dict or set(item) != _ISSUER_KEY_KEYS for item in issuer_keys)
    ):
        raise AuthorizationAuthenticityError(
            "authorization trust snapshot issuer_keys has unsupported shape"
        )
    for item in issuer_keys:
        for field in (
            "issuer_id",
            "verification_key_id",
            "public_key",
            "effective_from",
            "expires_at",
            "revocation_status",
        ):
            _exact_string(item[field], f"authorization issuer key {field}")
        _strict_base64(item["public_key"], "authorization issuer public_key", 32)
        _exact_sorted_strings(
            item["allowed_role_claims"],
            "authorization issuer allowed_role_claims",
            allowed=frozenset({"PROCESS_OWNER", "QUALITY_MANAGER"}),
        )
        _exact_sorted_strings(
            item["allowed_purpose_codes"],
            "authorization issuer allowed_purpose_codes",
            allowed=frozenset({"APPLY_APPROVED_RESOLUTION"}),
        )
        _exact_sorted_strings(
            item["allowed_scope_codes"],
            "authorization issuer allowed_scope_codes",
            allowed=frozenset({"EXACT_SUBJECT"}),
        )
        effective = parse_rfc3339_utc(
            item["effective_from"], "authorization issuer key effective_from"
        )
        expires = parse_rfc3339_utc(
            item["expires_at"], "authorization issuer key expires_at"
        )
        if effective > expires:
            raise AuthorizationAuthenticityError(
                "authorization issuer key static UTC window is reversed"
            )
        if item["revocation_status"] not in {"ACTIVE", "REVOKED", "UNKNOWN"}:
            raise AuthorizationAuthenticityError(
                "authorization issuer key revocation_status is unsupported"
            )
        if item["revocation_status"] == "REVOKED":
            revoked_at = parse_rfc3339_utc(
                item["revoked_at"], "authorization issuer key revoked_at"
            )
            if revoked_at > snapshot_issued_at:
                raise AuthorizationAuthenticityError(
                    "authorization issuer revocation occurs after snapshot"
                )
        elif item["revoked_at"] is not None:
            raise AuthorizationAuthenticityError(
                "non-revoked authorization issuer key must have null revoked_at"
            )
    return value


def _signed_record_value(raw: bytes) -> dict[str, Any]:
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise AuthorizationAuthenticityError(
            "signed authorization record is not strict UTF-8 JSON"
        ) from error
    if type(value) is not dict or set(value) != _SIGNED_RECORD_KEYS:
        raise AuthorizationAuthenticityError(
            "signed authorization record has unsupported root shape"
        )
    if raw != _canonical_bytes(value):
        raise AuthorizationAuthenticityError(
            "signed authorization record must be canonical JSON"
        )
    for field in _SIGNED_RECORD_KEYS:
        _exact_string(value[field], f"signed authorization record {field}")
    if value["contract_version"] != "qualityci-authorization-record-0.2":
        raise AuthorizationAuthenticityError(
            "unsupported signed authorization record contract_version"
        )
    if value["signature_algorithm"] != "ED25519":
        raise AuthorizationAuthenticityError(
            "signed authorization record signature_algorithm is unsupported"
        )
    _strict_base64(value["signature"], "signed authorization record signature", 64)
    return value


def _verify_ed25519(public_key: str, signature: str, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(
            _strict_base64(public_key, "authorization public_key", 32)
        ).verify(
            _strict_base64(signature, "authorization signature", 64),
            message,
        )
    except InvalidSignature:
        return False
    return True


def _without_signature(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in value if key != "signature"}


@dataclass(frozen=True)
class AuthorizationTrustSnapshotBundle:
    """One read-once canonical trust snapshot; there is no caller policy input."""

    canonical_snapshot_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.canonical_snapshot_bytes) is not bytes:
            raise TypeError("authorization trust snapshot requires exact bytes")
        copied = bytes(self.canonical_snapshot_bytes)
        _snapshot_value(copied)
        object.__setattr__(self, "canonical_snapshot_bytes", copied)


@dataclass(frozen=True, init=False)
class AuthorizationAuthenticityContext:
    contract_version: str
    state: str
    reason_code: str
    record_context: AuthorizationRecordContext
    authorization_record_set_hash: str
    authorization_record_set_contract_version: str
    trust_snapshot_hash: str
    trust_snapshot_contract_version: str
    trust_policy_hash: str
    trust_policy_version: str
    authorization_authenticity_context_hash: str
    _authenticated_records: tuple[AuthorizationRecordClaim, ...]
    _signed_issued_at: tuple[tuple[str, str], ...]
    _seal: object

    def __init__(
        self,
        *,
        state: str,
        reason_code: str,
        record_context: AuthorizationRecordContext,
        trust_snapshot_hash: str,
        authenticated_records: tuple[AuthorizationRecordClaim, ...],
        signed_issued_at: tuple[tuple[str, str], ...] = (),
        _seal: object,
    ) -> None:
        if _seal is not _CONTEXT_SEAL:
            raise TypeError("authorization authenticity context is internal")
        if type(record_context) is not AuthorizationRecordContext or not record_context.is_sealed():
            raise TypeError("authorization authenticity requires a sealed record context")
        if state not in {
            AUTHORIZATION_AUTHENTICITY_PASS,
            AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
            AUTHORIZATION_AUTHENTICITY_UNVERIFIABLE,
        }:
            raise ValueError("unsupported authorization authenticity state")
        _lower_sha(trust_snapshot_hash, "trust_snapshot_hash")
        policy_hash = hashlib.sha256(
            _POLICY_DOMAIN + _canonical_bytes(_FIXED_POLICY)
        ).hexdigest()
        subject = {
            "authorization_record_set_contract_version": record_context.contract_version,
            "authorization_record_set_hash": record_context.record_set_hash,
            "contract_version": AUTHORIZATION_AUTHENTICITY_CONTEXT_VERSION,
            "reason_code": reason_code,
            "state": state,
            "trust_policy_hash": policy_hash,
            "trust_policy_version": AUTHORIZATION_TRUST_POLICY_VERSION,
            "trust_snapshot_contract_version": AUTHORIZATION_TRUST_SNAPSHOT_CONTRACT_VERSION,
            "trust_snapshot_hash": trust_snapshot_hash,
        }
        context_hash = hashlib.sha256(
            _CONTEXT_DOMAIN + _canonical_bytes(subject)
        ).hexdigest()
        object.__setattr__(self, "contract_version", AUTHORIZATION_AUTHENTICITY_CONTEXT_VERSION)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "reason_code", reason_code)
        object.__setattr__(self, "record_context", record_context)
        object.__setattr__(self, "authorization_record_set_hash", record_context.record_set_hash)
        object.__setattr__(self, "authorization_record_set_contract_version", record_context.contract_version)
        object.__setattr__(self, "trust_snapshot_hash", trust_snapshot_hash)
        object.__setattr__(self, "trust_snapshot_contract_version", AUTHORIZATION_TRUST_SNAPSHOT_CONTRACT_VERSION)
        object.__setattr__(self, "trust_policy_hash", policy_hash)
        object.__setattr__(self, "trust_policy_version", AUTHORIZATION_TRUST_POLICY_VERSION)
        object.__setattr__(self, "authorization_authenticity_context_hash", context_hash)
        object.__setattr__(self, "_authenticated_records", tuple(authenticated_records))
        object.__setattr__(self, "_signed_issued_at", tuple(signed_issued_at))
        object.__setattr__(self, "_seal", _seal)

    @property
    def context_hash(self) -> str:
        return self.authorization_authenticity_context_hash

    def authenticated_records(self) -> tuple[AuthorizationRecordClaim, ...]:
        return tuple(self._authenticated_records)

    def is_sealed(self) -> bool:
        return self._seal is _CONTEXT_SEAL


def load_authorization_trust_snapshot_bundle(
    path: str | Path,
    *,
    root_dir: str | Path | None = None,
) -> AuthorizationTrustSnapshotBundle:
    resolved = Path(os.path.abspath(os.fspath(path)))
    raw = _capture_regular_file_once(
        resolved,
        label="authorization trust snapshot",
        maximum=MAX_AUTHORIZATION_TRUST_SNAPSHOT_BYTES,
        root_dir=root_dir,
    )
    return AuthorizationTrustSnapshotBundle(raw)


def prepare_authorization_authenticity_context(
    authorization_bundle: AuthorizationRecordBundle,
    trust_snapshot_bundle: AuthorizationTrustSnapshotBundle,
) -> AuthorizationAuthenticityContext:
    if type(authorization_bundle) is not AuthorizationRecordBundle:
        raise TypeError("authorization authenticity requires an exact record bundle")
    if type(trust_snapshot_bundle) is not AuthorizationTrustSnapshotBundle:
        raise TypeError("authorization authenticity requires an exact trust snapshot bundle")
    record_context = prepare_authorization_record_context(authorization_bundle)
    snapshot = _snapshot_value(trust_snapshot_bundle.canonical_snapshot_bytes)
    snapshot_hash = hashlib.sha256(
        _SNAPSHOT_HASH_DOMAIN + trust_snapshot_bundle.canonical_snapshot_bytes
    ).hexdigest()
    if record_context.contract_version == AUTHORIZATION_RECORD_SET_VERSION:
        return AuthorizationAuthenticityContext(
            state=AUTHORIZATION_AUTHENTICITY_UNVERIFIABLE,
            reason_code=LEGACY_UNSIGNED_AUTHORIZATION,
            record_context=record_context,
            trust_snapshot_hash=snapshot_hash,
            authenticated_records=(),
            _seal=_CONTEXT_SEAL,
        )
    if record_context.contract_version != SIGNED_AUTHORIZATION_RECORD_SET_VERSION:
        raise AuthorizationAuthenticityError(
            "unsupported authorization record set at authenticity boundary"
        )
    def sealed(
        state: str,
        reason_code: str,
        *,
        authenticated: tuple[AuthorizationRecordClaim, ...] = (),
        issued: tuple[tuple[str, str], ...] = (),
    ) -> AuthorizationAuthenticityContext:
        return AuthorizationAuthenticityContext(
            state=state,
            reason_code=reason_code,
            record_context=record_context,
            trust_snapshot_hash=snapshot_hash,
            authenticated_records=authenticated,
            signed_issued_at=issued,
            _seal=_CONTEXT_SEAL,
        )

    for field in (
        "anchor_id",
        "signature_algorithm",
        "snapshot_id",
        "trust_domain",
    ):
        if snapshot[field] != _FIXED_POLICY[field]:
            return sealed(
                AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
                "TRUST_SNAPSHOT_POLICY_MISMATCH",
            )
    if snapshot["snapshot_sequence"] < _FIXED_POLICY["minimum_snapshot_sequence"]:
        return sealed(
            AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
            "TRUST_SNAPSHOT_SEQUENCE_MISMATCH",
        )
    identities = [
        (item["issuer_id"], item["verification_key_id"])
        for item in snapshot["issuer_keys"]
    ]
    normalized_identities = [
        (normalized_identity(issuer_id), normalized_identity(key_id))
        for issuer_id, key_id in identities
    ]
    if (
        len(set(identities)) != len(identities)
        or len(set(normalized_identities)) != len(normalized_identities)
    ):
        return sealed(
            AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
            "TRUST_SNAPSHOT_ISSUER_IDENTITY_CONFLICT",
        )
    snapshot_message = _SNAPSHOT_DOMAIN + _canonical_bytes(
        _without_signature(snapshot)
    )
    if not _verify_ed25519(
        _FIXED_POLICY["anchor_public_key"], snapshot["signature"], snapshot_message
    ):
        return sealed(
            AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
            "TRUST_SNAPSHOT_SIGNATURE_INVALID",
        )

    keys = {
        (item["issuer_id"], item["verification_key_id"]): item
        for item in snapshot["issuer_keys"]
    }
    values = {
        member.record_id: _signed_record_value(member.raw_bytes)
        for member in authorization_bundle.members
    }
    roles = [value["role_claim"] for value in values.values()]
    expected_roles = _FIXED_POLICY["required_role_claims"]
    if sorted(roles, key=lambda item: (normalized_identity(item), item)) != expected_roles:
        return sealed(
            AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
            "AUTHORIZATION_ROLE_SET_MISMATCH",
        )

    pending_unverifiable: str | None = None
    issued: list[tuple[str, str]] = []
    for record_id, value in values.items():
        if value["record_id"] != record_id or value["trust_domain"] != snapshot["trust_domain"]:
            return sealed(
                AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
                "AUTHORIZATION_RECORD_TRUST_JOIN_MISMATCH",
            )
        key = keys.get((value["issuer_id"], value["verification_key_id"]))
        if key is None:
            pending_unverifiable = "AUTHORIZATION_ISSUER_KEY_NOT_FOUND"
            continue
        if key["revocation_status"] == "REVOKED":
            return sealed(
                AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
                "AUTHORIZATION_ISSUER_KEY_REVOKED",
            )
        if key["revocation_status"] == "UNKNOWN":
            pending_unverifiable = "AUTHORIZATION_ISSUER_KEY_STATUS_UNKNOWN"
            continue
        if (
            value["role_claim"] not in key["allowed_role_claims"]
            or value["purpose_code"] not in key["allowed_purpose_codes"]
            or value["scope_code"] not in key["allowed_scope_codes"]
        ):
            return sealed(
                AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
                "AUTHORIZATION_ISSUER_CAPABILITY_MISMATCH",
            )
        key_from = parse_rfc3339_utc(key["effective_from"], "issuer effective_from")
        key_until = parse_rfc3339_utc(key["expires_at"], "issuer expires_at")
        record_from = parse_rfc3339_utc(value["effective_from"], "record effective_from")
        record_issued = parse_rfc3339_utc(value["issued_at"], "record issued_at")
        record_until = parse_rfc3339_utc(value["expires_at"], "record expires_at")
        if not key_from <= record_from <= record_issued <= record_until <= key_until:
            return sealed(
                AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
                "AUTHORIZATION_STATIC_WINDOW_MISMATCH",
            )
        record_message = _RECORD_SIGNATURE_DOMAIN + _canonical_bytes(
            _without_signature(value)
        )
        if not _verify_ed25519(key["public_key"], value["signature"], record_message):
            return sealed(
                AUTHORIZATION_AUTHENTICITY_CONTRADICTED,
                "AUTHORIZATION_RECORD_SIGNATURE_INVALID",
            )
        issued.append((record_id, value["issued_at"]))
    if pending_unverifiable is not None:
        return sealed(AUTHORIZATION_AUTHENTICITY_UNVERIFIABLE, pending_unverifiable)
    return sealed(
        AUTHORIZATION_AUTHENTICITY_PASS,
        AUTHORIZATION_AUTHENTICITY_PASS,
        authenticated=record_context.records(),
        issued=tuple(sorted(issued)),
    )


def require_authenticated_assertion_records(
    assertions: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    context: AuthorizationAuthenticityContext,
) -> tuple[AuthorizationRecordClaim, ...]:
    if type(context) is not AuthorizationAuthenticityContext or not context.is_sealed():
        raise TypeError("assertion authenticity requires an exact sealed context")
    if context.state != AUTHORIZATION_AUTHENTICITY_PASS:
        raise AuthorizationAuthenticityError(
            f"authorization authenticity is not PASS: {context.state}"
        )
    if type(assertions) not in {list, tuple} or any(type(item) is not dict for item in assertions):
        raise TypeError("approval assertions require exact list/tuple objects")
    from .approval_subject import validate_approval_assertion_shape

    validated = tuple(validate_approval_assertion_shape(item) for item in assertions)
    records = context.authenticated_records()
    if len(validated) != len(records):
        raise AuthorizationAuthenticityError(
            "approval assertions differ from authenticated authorization records"
        )
    assertions_by_record = {item["authorization_record_id"]: item for item in validated}
    if len(assertions_by_record) != len(validated):
        raise AuthorizationAuthenticityError(
            "approval assertions contain duplicate authorization record references"
        )
    signed_issued_at = dict(context._signed_issued_at)
    for record in records:
        assertion = assertions_by_record.get(record.record_id)
        if assertion is None or (
            assertion["authorization_record_hash"] != record.content_hash
            or assertion["approver_id_claim"] != record.approver_id_claim
            or assertion["role_claim"] != record.role_claim
            or assertion["effective_from"] != record.effective_from
            or assertion["expires_at"] != record.expires_at
        ):
            raise AuthorizationAuthenticityError(
                "approval assertion differs from authenticated authorization record"
            )
        if parse_rfc3339_utc(assertion["issued_at"], "approval assertion issued_at") < parse_rfc3339_utc(
            signed_issued_at[record.record_id], "signed authorization record issued_at"
        ):
            raise AuthorizationAuthenticityError(
                "approval assertion predates signed authorization record"
            )
    return records


def authorization_authenticity_binding_hash(
    *,
    approval_subject_hash: str,
    approval_assertion_set_hash: str,
    authorization_authenticity_context_hash: str,
    after_case_hash: str,
    after_run_hash: str,
) -> str:
    subject = {
        "after_case_hash": _lower_sha(after_case_hash, "after_case_hash"),
        "after_run_hash": _lower_sha(after_run_hash, "after_run_hash"),
        "approval_assertion_set_hash": _lower_sha(
            approval_assertion_set_hash, "approval_assertion_set_hash"
        ),
        "approval_subject_hash": _lower_sha(approval_subject_hash, "approval_subject_hash"),
        "authorization_authenticity_context_hash": _lower_sha(
            authorization_authenticity_context_hash,
            "authorization_authenticity_context_hash",
        ),
        "contract_version": AUTHORIZATION_AUTHENTICITY_BINDING_VERSION,
    }
    return hashlib.sha256(_BINDING_DOMAIN + _canonical_bytes(subject)).hexdigest()
