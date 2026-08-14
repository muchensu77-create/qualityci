"""Raw validation-report capture and sealed A04 evaluation context.

The public bundle contains immutable bytes, not trust.  A sealed context is
created only after the manifest and every report have been parsed from the
same captured buffers and bound to a prepared case subject.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .ingestion import IngestionLimits, read_source_bytes
from .loader import (
    MAX_JSON_FILE_BYTES,
    canonical_case_projection,
    parse_rfc3339_utc,
    strict_json_loads,
)


VALIDATION_PLAN_CONTRACT_VERSION = "qualityci-validation-plan-0.1"
VALIDATION_EVIDENCE_CONTRACT_VERSION = "qualityci-validation-evidence-0.1"
VALIDATION_EVIDENCE_PACK_VERSION = "qualityci-validation-evidence-pack-0.1"
VALIDATION_PARSER_CONTRACT_VERSION = "qualityci-validation-json-parser-0.1"
VALIDATION_APPROVAL_POLICY_VERSION = "qualityci-validation-approval-policy-0.1"
VALIDATION_ASSURANCE_UNATTESTED = "UNATTESTED_VALIDATION_JSON"
VALIDATION_ASSURANCE_ATTESTED = "ATTESTED_VALIDATION_SET"
VALIDATION_PHASES = {"SOURCE", "RESOLVED"}
MAX_VALIDATION_MEMBERS = 1_024
MAX_VALIDATION_MEMBER_BYTES = 2 * 1024 * 1024
MAX_VALIDATION_TOTAL_BYTES = 16 * 1024 * 1024
MAX_VALIDATION_JSON_DEPTH = 32

_MANIFEST_KEYS = {"contract_version", "phase", "members"}
_MEMBER_KEYS = {"source_id", "source_path", "evidence_id", "format", "phase"}
_REPORT_KEYS = {
    "case_schema_version",
    "case_subject_hash",
    "claim",
    "event_id",
    "event_revision",
    "evidence_id",
    "evidence_type",
    "issued_at",
    "issuer_id",
    "issuer_role",
    "locator",
    "performed_at",
    "result",
    "ruleset_version",
    "scope_digest",
    "summary",
}
_CONTEXT_SEAL = object()


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


def _exact_string(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{label} must be an exact non-empty string")
    return value


def _lower_sha(value: Any, label: str) -> str:
    value = _exact_string(value, label)
    if len(value) != 64 or value != value.lower():
        raise ValueError(f"{label} must be a lowercase SHA-256")
    try:
        int(value, 16)
    except ValueError as error:
        raise ValueError(f"{label} must be a lowercase SHA-256") from error
    return value


def _canonical_filename(value: Any) -> str:
    value = _exact_string(value, "validation source_path")
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError("validation source_path must be a canonical filename")
    path = Path(value)
    if (
        path.is_absolute()
        or len(path.parts) != 1
        or value in {".", ".."}
        or "\\" in value
        or "#" in value
    ):
        raise ValueError(
            "validation source_path must be one relative filename without #"
        )
    return value


def _utc(value: Any, label: str) -> datetime:
    return parse_rfc3339_utc(value, label)


def validation_scope_digest(case: dict[str, Any]) -> str:
    event = case["event"]
    plan = copy.deepcopy(event.get("validation_plan"))
    if isinstance(plan, dict) and isinstance(plan.get("required_evidence"), list):
        plan["required_evidence"].sort(
            key=lambda item: (
                str(item.get("evidence_id", "")).casefold()
                if isinstance(item, dict)
                else "",
                str(item.get("evidence_id", "")) if isinstance(item, dict) else "",
            )
        )
    projection = {
        "case_id": case["case_id"],
        "event_id": event["event_id"],
        "event_revision": event["revision"],
        "event_type": event["event_type"],
        "risk_level": event["risk_level"],
        "affected_process_steps": sorted(event.get("affected_process_steps", [])),
        "affected_characteristics": sorted(
            event.get("affected_characteristics", [])
        ),
        "affected_links": sorted(
            copy.deepcopy(event.get("affected_links", [])),
            key=lambda item: (
                item.get("process_step_id", ""),
                item.get("characteristic_id", ""),
            ),
        ),
        "validation_plan": copy.deepcopy(plan),
        "case_schema_version": case.get("schema_version"),
        "ruleset_version": "qci-rules-0.6.0",
    }
    return _domain_hash(b"QualityCI/validation-scope/v1\0", projection)


def validation_case_subject_hash(case: dict[str, Any]) -> str:
    # Start from the exact same non-semantic ordering projection as the formal
    # case identity, then remove only fields that are downstream of this
    # subject and would otherwise create an identity cycle.
    projection = canonical_case_projection(case)
    event = projection.get("event")
    if isinstance(event, dict):
        for key in (
            "validation_evidence",
            "validation_context",
            "validation_evidence_set_hash",
            "approvals",
        ):
            event.pop(key, None)
        validation_plan = event.get("validation_plan")
        if isinstance(validation_plan, dict) and isinstance(
            validation_plan.get("required_evidence"), list
        ):
            validation_plan["required_evidence"].sort(
                key=lambda item: (
                    str(item.get("evidence_id", "")).casefold()
                    if isinstance(item, dict)
                    else "",
                    str(item.get("evidence_id", ""))
                    if isinstance(item, dict)
                    else "",
                )
            )
    for key in (
        "active_mutation",
        "run_result",
        "findings",
        "audit",
        "validation_context",
        "validation_evidence_set_hash",
    ):
        projection.pop(key, None)
    return _domain_hash(b"QualityCI/validation-case-subject/v1\0", projection)


_CASE_IDENTITY_SEAL = object()


@dataclass(frozen=True, init=False)
class _ValidationCaseIdentity:
    case_subject_hash: str
    scope_digest: str
    _seal: object

    def __init__(
        self, *, case_subject_hash: str, scope_digest: str, _seal: object
    ) -> None:
        if _seal is not _CASE_IDENTITY_SEAL:
            raise TypeError("validation case identity is internal")
        object.__setattr__(self, "case_subject_hash", case_subject_hash)
        object.__setattr__(self, "scope_digest", scope_digest)
        object.__setattr__(self, "_seal", _seal)

    def is_sealed(self) -> bool:
        return self._seal is _CASE_IDENTITY_SEAL


def _prepare_validation_case_identity(case: dict[str, Any]) -> _ValidationCaseIdentity:
    return _ValidationCaseIdentity(
        case_subject_hash=validation_case_subject_hash(case),
        scope_digest=validation_scope_digest(case),
        _seal=_CASE_IDENTITY_SEAL,
    )


def validation_approval_policy(
    source_case: dict[str, Any],
    resolved_case: dict[str, Any],
    *,
    _source_identity: _ValidationCaseIdentity | None = None,
    _resolved_identity: _ValidationCaseIdentity | None = None,
) -> dict[str, Any]:
    """Project only the pre-approved validation requirements into approval identity.

    The policy deliberately excludes evidence-set hashes, observed results, issuer
    claims, and timestamps.  Those are post-approval raw-evidence facts.  Approval
    binds only the two case subjects/scopes that future SOURCE and RESOLVED evidence
    must satisfy.
    """

    source_identity = (
        _source_identity
        if type(_source_identity) is _ValidationCaseIdentity
        and _source_identity.is_sealed()
        else _prepare_validation_case_identity(source_case)
    )
    resolved_identity = (
        _resolved_identity
        if type(_resolved_identity) is _ValidationCaseIdentity
        and _resolved_identity.is_sealed()
        else _prepare_validation_case_identity(resolved_case)
    )
    return {
        "contract_version": VALIDATION_APPROVAL_POLICY_VERSION,
        "validation_evidence_contract_version": (
            VALIDATION_EVIDENCE_CONTRACT_VERSION
        ),
        "required_phases": ["SOURCE", "RESOLVED"],
        "source_case_subject_hash": source_identity.case_subject_hash,
        "source_scope_digest": source_identity.scope_digest,
        "resolved_case_subject_hash": resolved_identity.case_subject_hash,
        "resolved_scope_digest": resolved_identity.scope_digest,
    }


def validation_evidence_pair_hash(
    source_context: "_ValidationEvidenceContext",
    resolved_context: "_ValidationEvidenceContext",
) -> str:
    return hashlib.sha256(
        (
            "QualityCI/validation-evidence-pair/v1\0"
            + _domain_hash(
                b"",
                {
                    "source_case_subject_hash": source_context.case_subject_hash,
                    "source_evidence_set_hash": source_context.evidence_set_hash,
                    "resolved_case_subject_hash": resolved_context.case_subject_hash,
                    "resolved_evidence_set_hash": resolved_context.evidence_set_hash,
                    "contract_version": VALIDATION_EVIDENCE_CONTRACT_VERSION,
                },
            )
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class ValidationEvidenceMember:
    source_id: str
    evidence_id: str
    filename: str
    raw_bytes: bytes

    def __post_init__(self) -> None:
        if (
            type(self.source_id) is not str
            or type(self.evidence_id) is not str
            or type(self.filename) is not str
            or type(self.raw_bytes) is not bytes
        ):
            raise TypeError(
                "validation member source_id/evidence_id/filename/raw_bytes "
                "require exact built-in str/bytes types"
            )
        _exact_string(self.source_id, "validation member source_id")
        _exact_string(self.evidence_id, "validation member evidence_id")
        _canonical_filename(self.filename)
        if not self.raw_bytes or len(self.raw_bytes) > MAX_VALIDATION_MEMBER_BYTES:
            raise ValueError("validation member byte size is invalid")
        object.__setattr__(self, "raw_bytes", bytes(self.raw_bytes))


@dataclass(frozen=True)
class ValidationEvidenceBundle:
    canonical_manifest_bytes: bytes
    members: tuple[ValidationEvidenceMember, ...]

    def __post_init__(self) -> None:
        if type(self.canonical_manifest_bytes) is not bytes:
            raise TypeError("validation manifest requires exact immutable bytes")
        if type(self.members) is not tuple or any(
            type(member) is not ValidationEvidenceMember for member in self.members
        ):
            raise TypeError("validation bundle requires exact immutable members")
        if not self.members or len(self.members) > MAX_VALIDATION_MEMBERS:
            raise ValueError("validation bundle member count is invalid")
        if sum(len(member.raw_bytes) for member in self.members) > MAX_VALIDATION_TOTAL_BYTES:
            raise ValueError("validation bundle exceeds total byte limit")
        object.__setattr__(
            self, "canonical_manifest_bytes", bytes(self.canonical_manifest_bytes)
        )
        object.__setattr__(
            self,
            "members",
            tuple(
                ValidationEvidenceMember(
                    member.source_id,
                    member.evidence_id,
                    member.filename,
                    bytes(member.raw_bytes),
                )
                for member in self.members
            ),
        )
        _validate_bundle(self)


@dataclass(frozen=True)
class _ValidationWitness:
    source_id: str
    evidence_id: str
    filename: str
    source_hash: str
    raw_bytes: bytes

    def __post_init__(self) -> None:
        if hashlib.sha256(self.raw_bytes).hexdigest() != self.source_hash:
            raise ValueError("validation witness hash differs from raw bytes")


@dataclass(frozen=True, init=False)
class _ValidationEvidenceContext:
    phase: str
    contract_version: str
    evidence_set_hash: str
    case_subject_hash: str
    scope_digest: str
    reports_json: bytes
    witnesses: tuple[_ValidationWitness, ...]
    _seal: object

    def __init__(
        self,
        *,
        phase: str,
        evidence_set_hash: str,
        case_subject_hash: str,
        scope_digest: str,
        reports_json: bytes,
        witnesses: tuple[_ValidationWitness, ...],
        _seal: object,
    ) -> None:
        if _seal is not _CONTEXT_SEAL:
            raise TypeError("validation context is internal")
        object.__setattr__(self, "phase", phase)
        object.__setattr__(
            self, "contract_version", VALIDATION_EVIDENCE_CONTRACT_VERSION
        )
        object.__setattr__(self, "evidence_set_hash", evidence_set_hash)
        object.__setattr__(self, "case_subject_hash", case_subject_hash)
        object.__setattr__(self, "scope_digest", scope_digest)
        object.__setattr__(self, "reports_json", bytes(reports_json))
        object.__setattr__(self, "witnesses", tuple(witnesses))
        object.__setattr__(self, "_seal", _seal)

    def reports(self) -> tuple[dict[str, Any], ...]:
        value = json.loads(self.reports_json.decode("utf-8"))
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ValueError("internal validation reports are invalid")
        return tuple(copy.deepcopy(value))

    def is_sealed(self) -> bool:
        return self._seal is _CONTEXT_SEAL


def _strict_json_bytes(raw: bytes, label: str) -> Any:
    from .loader import strict_json_loads

    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise ValueError(f"{label} is not UTF-8 JSON") from error
    value = strict_json_loads(text)
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_VALIDATION_JSON_DEPTH:
            raise ValueError(
                f"{label} JSON nesting exceeds {MAX_VALIDATION_JSON_DEPTH} levels"
            )
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    if raw != _canonical_bytes(value):
        raise ValueError(f"{label} is not canonical JSON")
    return value


def _validate_bundle(bundle: ValidationEvidenceBundle) -> dict[str, Any]:
    from .loader import normalized_identity

    manifest = _strict_json_bytes(
        bundle.canonical_manifest_bytes, "validation manifest"
    )
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEYS:
        raise ValueError("validation manifest has unsupported root shape")
    if manifest["contract_version"] != VALIDATION_EVIDENCE_PACK_VERSION:
        raise ValueError("unsupported validation evidence pack version")
    phase = manifest["phase"]
    if type(phase) is not str or phase not in VALIDATION_PHASES:
        raise ValueError("validation manifest phase is unsupported")
    specs = manifest["members"]
    if (
        not isinstance(specs, list)
        or not specs
        or len(specs) > MAX_VALIDATION_MEMBERS
        or any(not isinstance(spec, dict) or set(spec) != _MEMBER_KEYS for spec in specs)
    ):
        raise ValueError("validation manifest members have unsupported shape")
    for spec in specs:
        for key in ("source_id", "evidence_id"):
            _exact_string(spec[key], f"validation manifest {key}")
        _canonical_filename(spec["source_path"])
        if spec["format"] != "JSON" or spec["phase"] != phase:
            raise ValueError("validation member format/phase differs from manifest")
    for values, label in (
        ([spec["source_id"] for spec in specs], "source_id"),
        ([spec["evidence_id"] for spec in specs], "evidence_id"),
        ([spec["source_path"] for spec in specs], "source_path"),
    ):
        identities = [normalized_identity(value) for value in values]
        if len(identities) != len(set(identities)):
            raise ValueError(f"duplicate normalized validation {label}")
    canonical = {
        "contract_version": VALIDATION_EVIDENCE_PACK_VERSION,
        "members": sorted(
            copy.deepcopy(specs),
            key=lambda item: (
                normalized_identity(item["evidence_id"]),
                item["evidence_id"],
            ),
        ),
        "phase": phase,
    }
    if bundle.canonical_manifest_bytes != _canonical_bytes(canonical):
        raise ValueError("validation manifest is not canonical")
    members = {member.evidence_id: member for member in bundle.members}
    specs_by_id = {spec["evidence_id"]: spec for spec in specs}
    if len(members) != len(bundle.members) or set(members) != set(specs_by_id):
        raise ValueError("validation members differ from manifest")
    for evidence_id, spec in specs_by_id.items():
        member = members[evidence_id]
        if (
            member.source_id != spec["source_id"]
            or member.filename != spec["source_path"]
        ):
            raise ValueError("validation member identity differs from manifest")
    return canonical


def load_validation_evidence_bundle(
    manifest_path: str | Path,
    *,
    root_dir: str | Path | None = None,
) -> ValidationEvidenceBundle:
    from .loader import load_json, normalized_identity

    requested = Path(manifest_path)
    if root_dir is None:
        path = requested.resolve(strict=True)
        manifest = load_json(path)
    else:
        path = requested
        _name, _relative, manifest_raw = read_source_bytes(
            path,
            root_dir=root_dir,
            limits=IngestionLimits(max_file_bytes=MAX_JSON_FILE_BYTES),
        )
        try:
            manifest = strict_json_loads(manifest_raw.decode("utf-8"))
        except (UnicodeError, TypeError, ValueError) as error:
            raise ValueError("validation manifest must be strict UTF-8 JSON") from error
    # Canonical construction still delegates the full contract to the Bundle.
    if not isinstance(manifest, dict) or not isinstance(manifest.get("members"), list):
        raise ValueError("validation manifest has unsupported shape")
    specs = manifest["members"]
    members: list[ValidationEvidenceMember] = []
    for spec in specs:
        if not isinstance(spec, dict):
            raise ValueError("validation manifest member must be an object")
        filename = _canonical_filename(spec.get("source_path"))
        source = path.parent / filename
        if root_dir is None:
            metadata = os.lstat(source)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size <= 0
                or metadata.st_size > MAX_VALIDATION_MEMBER_BYTES
            ):
                raise ValueError(
                    "validation report must be one regular non-link file"
                )
            raw = source.read_bytes()
            after = os.lstat(source)
            if len(raw) != metadata.st_size or (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise ValueError("validation report changed during capture")
        else:
            _name, _relative, raw = read_source_bytes(
                source,
                root_dir=root_dir,
                limits=IngestionLimits(
                    max_file_bytes=MAX_VALIDATION_MEMBER_BYTES
                ),
            )
        members.append(
            ValidationEvidenceMember(
                source_id=spec.get("source_id"),
                evidence_id=spec.get("evidence_id"),
                filename=filename,
                raw_bytes=raw,
            )
        )
    canonical = {
        "contract_version": manifest.get("contract_version"),
        "members": sorted(
            copy.deepcopy(specs),
            key=lambda item: (
                normalized_identity(item.get("evidence_id", "")),
                item.get("evidence_id", ""),
            ),
        ),
        "phase": manifest.get("phase"),
    }
    members.sort(
        key=lambda item: (normalized_identity(item.evidence_id), item.evidence_id)
    )
    return ValidationEvidenceBundle(_canonical_bytes(canonical), tuple(members))


def _prepare_validation_evidence_context(
    bundle: ValidationEvidenceBundle,
    case: dict[str, Any],
    *,
    expected_phase: str,
    _case_identity: _ValidationCaseIdentity | None = None,
) -> _ValidationEvidenceContext:
    if type(bundle) is not ValidationEvidenceBundle:
        raise TypeError("validation run requires exact raw evidence bundle")
    if expected_phase not in VALIDATION_PHASES:
        raise ValueError("validation expected phase is unsupported")
    manifest = _validate_bundle(bundle)
    if manifest["phase"] != expected_phase:
        raise ValueError("validation evidence phase mismatch")
    specs = {spec["evidence_id"]: spec for spec in manifest["members"]}
    members = {member.evidence_id: member for member in bundle.members}
    reports: list[dict[str, Any]] = []
    witnesses: list[_ValidationWitness] = []
    for evidence_id in sorted(specs):
        spec = specs[evidence_id]
        member = members[evidence_id]
        report = _strict_json_bytes(
            member.raw_bytes, f"validation report {evidence_id}"
        )
        if not isinstance(report, dict) or set(report) != _REPORT_KEYS:
            raise ValueError("validation report has unsupported claim shape")
        for key in _REPORT_KEYS - {"summary"}:
            _exact_string(report[key], f"validation report {evidence_id}.{key}")
        if type(report["summary"]) is not str:
            raise ValueError("validation report summary must be an exact string")
        if report["evidence_id"] != evidence_id:
            raise ValueError("validation report evidence_id differs from manifest")
        if report["result"] not in {"PASS", "FAIL", "PENDING"}:
            raise ValueError("validation report result is unsupported")
        _lower_sha(report["case_subject_hash"], "validation case_subject_hash")
        _lower_sha(report["scope_digest"], "validation scope_digest")
        performed = _utc(report["performed_at"], "validation performed_at")
        issued = _utc(report["issued_at"], "validation issued_at")
        if issued < performed:
            raise ValueError("validation issued_at precedes performed_at")
        expected_locator = f"{member.filename}#/result"
        if report["locator"] != expected_locator:
            raise ValueError("validation report locator does not identify its result cell")
        source_hash = hashlib.sha256(member.raw_bytes).hexdigest()
        reports.append(
            {
                **copy.deepcopy(report),
                "source_id": member.source_id,
                "source_path": member.filename,
                "source_hash": source_hash,
                "phase": expected_phase,
            }
        )
        witnesses.append(
            _ValidationWitness(
                member.source_id,
                evidence_id,
                member.filename,
                source_hash,
                member.raw_bytes,
            )
        )
    reports.sort(key=lambda item: item["evidence_id"])
    case_identity = (
        _case_identity
        if type(_case_identity) is _ValidationCaseIdentity
        and _case_identity.is_sealed()
        else _prepare_validation_case_identity(case)
    )
    subject_hash = case_identity.case_subject_hash
    scope_digest = case_identity.scope_digest
    set_payload = {
        "case_subject_hash": subject_hash,
        "contract_version": VALIDATION_EVIDENCE_CONTRACT_VERSION,
        "manifest": manifest,
        "parser_contract_version": VALIDATION_PARSER_CONTRACT_VERSION,
        "phase": expected_phase,
        "reports": reports,
        "scope_digest": scope_digest,
    }
    return _ValidationEvidenceContext(
        phase=expected_phase,
        evidence_set_hash=_domain_hash(
            b"QualityCI/validation-evidence-set/v1\0", set_payload
        ),
        case_subject_hash=subject_hash,
        scope_digest=scope_digest,
        reports_json=_canonical_bytes(reports),
        witnesses=tuple(witnesses),
        _seal=_CONTEXT_SEAL,
    )


def _is_sealed_validation_context(value: Any) -> bool:
    return type(value) is _ValidationEvidenceContext and value.is_sealed()
