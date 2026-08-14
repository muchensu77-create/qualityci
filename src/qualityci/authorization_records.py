"""Strict raw capture for byte-bound authorization-record declarations.

This module proves only that exact canonical bytes made exact textual claims.
It does not authenticate a person, role, issuer, clock, or external authority.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .ingestion import IngestionLimits, read_source_bytes
from .loader import normalized_identity, parse_rfc3339_utc, strict_json_loads


AUTHORIZATION_RECORD_CONTRACT_VERSION = "qualityci-authorization-record-0.1"
AUTHORIZATION_RECORD_PACK_VERSION = "qualityci-authorization-record-pack-0.1"
AUTHORIZATION_RECORD_SET_VERSION = "qualityci-authorization-record-set-0.1"
SIGNED_AUTHORIZATION_RECORD_CONTRACT_VERSION = "qualityci-authorization-record-0.2"
SIGNED_AUTHORIZATION_RECORD_PACK_VERSION = "qualityci-authorization-record-pack-0.2"
SIGNED_AUTHORIZATION_RECORD_SET_VERSION = "qualityci-authorization-record-set-0.2"
AUTHORIZATION_PURPOSE_CODE = "APPLY_APPROVED_RESOLUTION"
AUTHORIZATION_SCOPE_CODE = "EXACT_SUBJECT"
AUTHORIZATION_ROLE_CLAIMS = frozenset({"QUALITY_MANAGER", "PROCESS_OWNER"})

MAX_AUTHORIZATION_MEMBERS = 128
MAX_AUTHORIZATION_MANIFEST_BYTES = 256 * 1024
MAX_AUTHORIZATION_MEMBER_BYTES = 256 * 1024
MAX_AUTHORIZATION_TOTAL_BYTES = 4 * 1024 * 1024
MAX_AUTHORIZATION_JSON_DEPTH = 16

_MANIFEST_KEYS = {"contract_version", "bundle_id", "members"}
_MEMBER_KEYS = {
    "record_id",
    "source_path",
    "content_hash",
    "size_bytes",
    "format",
}
_RECORD_KEYS = {
    "contract_version",
    "record_id",
    "approver_id_claim",
    "role_claim",
    "purpose_code",
    "scope_code",
    "effective_from",
    "expires_at",
}
_SIGNED_RECORD_KEYS = _RECORD_KEYS | {
    "trust_domain",
    "issuer_id",
    "verification_key_id",
    "issued_at",
    "signature_algorithm",
    "signature",
}
_CONTEXT_SEAL = object()
_SET_DOMAIN = b"QualityCI/authorization-record-set/v1\0"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _exact_string(value: Any, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{label} must be an exact non-empty trimmed string")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{label} contains control characters")
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


def _exact_positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be an exact positive integer")
    return value


def _strict_base64(value: Any, label: str, expected_size: int) -> bytes:
    """Validate the exact wire encoding at the raw-record parser boundary."""

    value = _exact_string(value, label)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError(f"{label} must be canonical base64") from error
    if len(raw) != expected_size or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError(f"{label} must encode exactly {expected_size} bytes")
    return raw


def _canonical_pack_path(value: Any) -> str:
    value = _exact_string(value, "authorization source_path")
    if "\\" in value:
        raise ValueError("authorization source_path must use canonical '/' separators")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value in {".", ".."}
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ValueError("authorization source_path must be a canonical pack-relative path")
    return value


def _strict_json_bytes(raw: bytes, label: str) -> Any:
    if type(raw) is not bytes:
        raise TypeError(f"{label} requires exact immutable bytes")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except UnicodeError as error:
        raise ValueError(f"{label} is not UTF-8 JSON") from error
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_AUTHORIZATION_JSON_DEPTH:
            raise ValueError(
                f"{label} JSON nesting exceeds {MAX_AUTHORIZATION_JSON_DEPTH} levels"
            )
        if type(current) is dict:
            stack.extend((item, depth + 1) for item in current.values())
        elif type(current) is list:
            stack.extend((item, depth + 1) for item in current)
    if raw != _canonical_bytes(value):
        raise ValueError(f"{label} is not canonical JSON")
    return value


def _normalized_unique(values: list[str], label: str) -> None:
    identities = [normalized_identity(value) for value in values]
    if len(identities) != len(set(identities)):
        raise ValueError(f"duplicate normalized authorization {label}")


@dataclass(frozen=True)
class AuthorizationRecordMember:
    record_id: str
    filename: str
    content_hash: str
    size_bytes: int
    raw_bytes: bytes

    def __post_init__(self) -> None:
        if (
            type(self.record_id) is not str
            or type(self.filename) is not str
            or type(self.content_hash) is not str
            or type(self.size_bytes) is not int
            or type(self.raw_bytes) is not bytes
        ):
            raise TypeError(
                "authorization member fields require exact built-in str/int/bytes types"
            )
        _exact_string(self.record_id, "authorization member record_id")
        _canonical_pack_path(self.filename)
        _lower_sha(self.content_hash, "authorization member content_hash")
        _exact_positive_int(self.size_bytes, "authorization member size_bytes")
        if self.size_bytes > MAX_AUTHORIZATION_MEMBER_BYTES:
            raise ValueError("authorization member exceeds byte limit")
        if len(self.raw_bytes) != self.size_bytes:
            raise ValueError("authorization member size differs from captured bytes")
        if hashlib.sha256(self.raw_bytes).hexdigest() != self.content_hash:
            raise ValueError("authorization member hash differs from captured bytes")
        object.__setattr__(self, "raw_bytes", bytes(self.raw_bytes))


@dataclass(frozen=True)
class AuthorizationRecordBundle:
    canonical_manifest_bytes: bytes
    members: tuple[AuthorizationRecordMember, ...]

    def __post_init__(self) -> None:
        if type(self.canonical_manifest_bytes) is not bytes:
            raise TypeError("authorization manifest requires exact immutable bytes")
        if type(self.members) is not tuple or any(
            type(member) is not AuthorizationRecordMember for member in self.members
        ):
            raise TypeError("authorization bundle requires exact immutable members")
        if not self.members or len(self.members) > MAX_AUTHORIZATION_MEMBERS:
            raise ValueError("authorization bundle member count is invalid")
        if (
            sum(member.size_bytes for member in self.members)
            > MAX_AUTHORIZATION_TOTAL_BYTES
        ):
            raise ValueError("authorization bundle exceeds total byte limit")
        object.__setattr__(
            self, "canonical_manifest_bytes", bytes(self.canonical_manifest_bytes)
        )
        object.__setattr__(
            self,
            "members",
            tuple(
                AuthorizationRecordMember(
                    member.record_id,
                    member.filename,
                    member.content_hash,
                    member.size_bytes,
                    bytes(member.raw_bytes),
                )
                for member in self.members
            ),
        )
        _validate_bundle(self)


@dataclass(frozen=True)
class AuthorizationRecordClaim:
    record_id: str
    content_hash: str
    approver_id_claim: str
    role_claim: str
    purpose_code: str
    scope_code: str
    effective_from: str
    expires_at: str


@dataclass(frozen=True, init=False)
class AuthorizationRecordContext:
    contract_version: str
    bundle_id: str
    record_set_hash: str
    _records: tuple[AuthorizationRecordClaim, ...]
    _seal: object

    def __init__(
        self,
        *,
        bundle_id: str,
        record_set_hash: str,
        records: tuple[AuthorizationRecordClaim, ...],
        contract_version: str = AUTHORIZATION_RECORD_SET_VERSION,
        _seal: object,
    ) -> None:
        if _seal is not _CONTEXT_SEAL:
            raise TypeError("authorization record context is internal")
        if contract_version not in {
            AUTHORIZATION_RECORD_SET_VERSION,
            SIGNED_AUTHORIZATION_RECORD_SET_VERSION,
        }:
            raise ValueError("unsupported authorization record set version")
        object.__setattr__(self, "contract_version", contract_version)
        object.__setattr__(self, "bundle_id", bundle_id)
        object.__setattr__(self, "record_set_hash", record_set_hash)
        object.__setattr__(self, "_records", tuple(records))
        object.__setattr__(self, "_seal", _seal)

    def records(self) -> tuple[AuthorizationRecordClaim, ...]:
        return tuple(self._records)

    def record(self, record_id: str, content_hash: str) -> AuthorizationRecordClaim:
        _exact_string(record_id, "authorization lookup record_id")
        _lower_sha(content_hash, "authorization lookup content_hash")
        matches = tuple(
            item
            for item in self._records
            if item.record_id == record_id and item.content_hash == content_hash
        )
        if len(matches) != 1:
            raise ValueError("authorization record binding is missing or ambiguous")
        return matches[0]

    def is_sealed(self) -> bool:
        return self._seal is _CONTEXT_SEAL


def _validate_bundle(bundle: AuthorizationRecordBundle) -> dict[str, Any]:
    manifest = _strict_json_bytes(
        bundle.canonical_manifest_bytes, "authorization manifest"
    )
    if type(manifest) is not dict or set(manifest) != _MANIFEST_KEYS:
        raise ValueError("authorization manifest has unsupported root shape")
    pack_version = manifest["contract_version"]
    if pack_version not in {
        AUTHORIZATION_RECORD_PACK_VERSION,
        SIGNED_AUTHORIZATION_RECORD_PACK_VERSION,
    }:
        raise ValueError("unsupported authorization record pack version")
    record_version = (
        SIGNED_AUTHORIZATION_RECORD_CONTRACT_VERSION
        if pack_version == SIGNED_AUTHORIZATION_RECORD_PACK_VERSION
        else AUTHORIZATION_RECORD_CONTRACT_VERSION
    )
    _exact_string(manifest["bundle_id"], "authorization manifest bundle_id")
    specs = manifest["members"]
    if (
        type(specs) is not list
        or not specs
        or len(specs) > MAX_AUTHORIZATION_MEMBERS
        or any(type(spec) is not dict or set(spec) != _MEMBER_KEYS for spec in specs)
    ):
        raise ValueError("authorization manifest members have unsupported shape")
    for spec in specs:
        _exact_string(spec["record_id"], "authorization manifest record_id")
        _canonical_pack_path(spec["source_path"])
        _lower_sha(spec["content_hash"], "authorization manifest content_hash")
        size = _exact_positive_int(
            spec["size_bytes"], "authorization manifest size_bytes"
        )
        if size > MAX_AUTHORIZATION_MEMBER_BYTES:
            raise ValueError("authorization manifest member exceeds byte limit")
        if spec["format"] != "JSON":
            raise ValueError("authorization manifest member format is unsupported")
    if sum(spec["size_bytes"] for spec in specs) > MAX_AUTHORIZATION_TOTAL_BYTES:
        raise ValueError("authorization manifest exceeds total byte limit")
    _normalized_unique(
        [spec["record_id"] for spec in specs], "manifest record_id"
    )
    _normalized_unique(
        [spec["source_path"] for spec in specs], "manifest source_path"
    )
    canonical = {
        "bundle_id": manifest["bundle_id"],
        "contract_version": pack_version,
        "members": sorted(
            copy.deepcopy(specs),
            key=lambda item: (
                normalized_identity(item["record_id"]),
                item["record_id"],
            ),
        ),
    }
    if bundle.canonical_manifest_bytes != _canonical_bytes(canonical):
        raise ValueError("authorization manifest is not canonical")
    members = {member.record_id: member for member in bundle.members}
    specs_by_id = {spec["record_id"]: spec for spec in specs}
    if len(members) != len(bundle.members) or set(members) != set(specs_by_id):
        raise ValueError("authorization members differ from manifest")
    _normalized_unique(
        [member.record_id for member in bundle.members], "member record_id"
    )
    _normalized_unique(
        [member.filename for member in bundle.members], "member source_path"
    )
    for record_id, spec in specs_by_id.items():
        member = members[record_id]
        if (
            member.filename != spec["source_path"]
            or member.content_hash != spec["content_hash"]
            or member.size_bytes != spec["size_bytes"]
        ):
            raise ValueError("authorization member identity differs from manifest")
        _validate_record(
            member.raw_bytes,
            expected_record_id=record_id,
            expected_contract_version=record_version,
        )
    return canonical


def _validate_record(
    raw: bytes,
    *,
    expected_record_id: str,
    expected_contract_version: str = AUTHORIZATION_RECORD_CONTRACT_VERSION,
) -> dict[str, Any]:
    record = _strict_json_bytes(raw, f"authorization record {expected_record_id}")
    expected_keys = (
        _SIGNED_RECORD_KEYS
        if expected_contract_version == SIGNED_AUTHORIZATION_RECORD_CONTRACT_VERSION
        else _RECORD_KEYS
    )
    if type(record) is not dict or set(record) != expected_keys:
        raise ValueError("authorization record has unsupported claim shape")
    if record["contract_version"] != expected_contract_version:
        raise ValueError("unsupported authorization record version")
    for field in (
        "record_id",
        "approver_id_claim",
        "role_claim",
        "purpose_code",
        "scope_code",
        "effective_from",
        "expires_at",
    ):
        _exact_string(record[field], f"authorization record {field}")
    if expected_contract_version == SIGNED_AUTHORIZATION_RECORD_CONTRACT_VERSION:
        for field in (
            "trust_domain",
            "issuer_id",
            "verification_key_id",
            "issued_at",
            "signature_algorithm",
            "signature",
        ):
            _exact_string(record[field], f"authorization record {field}")
        if record["signature_algorithm"] != "ED25519":
            raise ValueError("authorization record signature_algorithm is unsupported")
        _strict_base64(
            record["signature"],
            "authorization record signature",
            64,
        )
    if record["record_id"] != expected_record_id:
        raise ValueError("authorization record_id differs from manifest foreign key")
    if record["role_claim"] not in AUTHORIZATION_ROLE_CLAIMS:
        raise ValueError("authorization record role_claim is unsupported")
    if record["purpose_code"] != AUTHORIZATION_PURPOSE_CODE:
        raise ValueError("authorization record purpose_code is unsupported")
    if record["scope_code"] != AUTHORIZATION_SCOPE_CODE:
        raise ValueError("authorization record scope_code is unsupported")
    effective_from = parse_rfc3339_utc(
        record["effective_from"], "authorization record effective_from"
    )
    expires_at = parse_rfc3339_utc(
        record["expires_at"], "authorization record expires_at"
    )
    if effective_from > expires_at:
        raise ValueError("authorization record static UTC window is reversed")
    if expected_contract_version == SIGNED_AUTHORIZATION_RECORD_CONTRACT_VERSION:
        issued_at = parse_rfc3339_utc(
            record["issued_at"], "authorization record issued_at"
        )
        if not effective_from <= issued_at <= expires_at:
            raise ValueError(
                "authorization record issued_at is outside its static UTC window"
            )
    return record


def _capture_regular_file_once(
    path: Path,
    *,
    label: str,
    maximum: int,
    root_dir: str | Path | None = None,
) -> bytes:
    if root_dir is not None:
        try:
            _name, _relative, raw = read_source_bytes(
                path,
                root_dir=root_dir,
                limits=IngestionLimits(max_file_bytes=maximum),
            )
        except ValueError as error:
            raise ValueError(f"{label} could not be captured: {error}") from error
        if not raw:
            raise ValueError(
                f"{label} must be one bounded regular non-link file"
            )
        return raw
    try:
        before = os.lstat(path)
    except OSError as error:
        raise ValueError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise ValueError(f"{label} must be one bounded regular non-link file")
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            raw = handle.read(maximum + 1)
            closed = os.fstat(handle.fileno())
    except OSError as error:
        raise ValueError(f"{label} changed during capture") from error
    try:
        after = os.lstat(path)
    except OSError as error:
        raise ValueError(f"{label} changed during capture") from error
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
    )
    if (
        len(raw) > maximum
        or len(raw) != before.st_size
        or identity(before) != identity(opened)
        or identity(opened) != identity(closed)
        or identity(before) != identity(after)
    ):
        raise ValueError(f"{label} changed during capture")
    return raw


def _member_path(pack_root: Path, source_path: str) -> Path:
    relative = PurePosixPath(_canonical_pack_path(source_path))
    current = pack_root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise ValueError("authorization member parent is unavailable") from error
        is_windows_reparse_point = bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
        ) or bool(getattr(metadata, "st_reparse_tag", 0))
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or is_windows_reparse_point
        ):
            raise ValueError("authorization member parent must be a real directory")
    return pack_root.joinpath(*relative.parts)


def load_authorization_record_bundle(
    manifest_path: str | Path,
    *,
    root_dir: str | Path | None = None,
) -> AuthorizationRecordBundle:
    """Capture the manifest and every declared member once from one pack root."""

    path = Path(os.path.abspath(os.fspath(manifest_path)))
    if root_dir is not None:
        capture_root = Path(root_dir)
    else:
        # Keep the pack directory itself inside the root-bounded open chain.
        # If it is a symlink or Windows junction, the secure opener must see
        # and reject that component instead of canonicalizing it as the root.
        capture_root = path.parent.parent
        if capture_root == path.parent:  # filesystem-root manifest
            capture_root = path.parent
    raw_manifest = _capture_regular_file_once(
        path,
        label="authorization manifest",
        maximum=MAX_AUTHORIZATION_MANIFEST_BYTES,
        root_dir=capture_root,
    )
    manifest = _strict_json_bytes(raw_manifest, "authorization manifest")
    if type(manifest) is not dict or set(manifest) != _MANIFEST_KEYS:
        raise ValueError("authorization manifest has unsupported root shape")
    specs = manifest.get("members")
    if type(specs) is not list:
        raise ValueError("authorization manifest members have unsupported shape")
    # Validate all cheap manifest identities and declared budgets before reads.
    # The full Bundle validator also compares members, so perform shape and
    # budget checks locally before capture.
    if manifest.get("contract_version") not in {
        AUTHORIZATION_RECORD_PACK_VERSION,
        SIGNED_AUTHORIZATION_RECORD_PACK_VERSION,
    }:
        raise ValueError("unsupported authorization record pack version")
    pack_version = manifest["contract_version"]
    _exact_string(manifest.get("bundle_id"), "authorization manifest bundle_id")
    if (
        not specs
        or len(specs) > MAX_AUTHORIZATION_MEMBERS
        or any(type(spec) is not dict or set(spec) != _MEMBER_KEYS for spec in specs)
    ):
        raise ValueError("authorization manifest members have unsupported shape")
    record_ids: list[str] = []
    source_paths: list[str] = []
    declared_total = 0
    for spec in specs:
        record_ids.append(
            _exact_string(spec["record_id"], "authorization manifest record_id")
        )
        source_paths.append(_canonical_pack_path(spec["source_path"]))
        _lower_sha(spec["content_hash"], "authorization manifest content_hash")
        declared_size = _exact_positive_int(
            spec["size_bytes"], "authorization manifest size_bytes"
        )
        if declared_size > MAX_AUTHORIZATION_MEMBER_BYTES:
            raise ValueError("authorization manifest member exceeds byte limit")
        declared_total += declared_size
        if spec["format"] != "JSON":
            raise ValueError("authorization manifest member format is unsupported")
    if declared_total > MAX_AUTHORIZATION_TOTAL_BYTES:
        raise ValueError("authorization manifest exceeds total byte limit")
    _normalized_unique(record_ids, "manifest record_id")
    _normalized_unique(source_paths, "manifest source_path")
    canonical = {
        "bundle_id": manifest["bundle_id"],
        "contract_version": pack_version,
        "members": sorted(
            copy.deepcopy(specs),
            key=lambda item: (
                normalized_identity(item["record_id"]),
                item["record_id"],
            ),
        ),
    }
    if raw_manifest != _canonical_bytes(canonical):
        raise ValueError("authorization manifest is not canonical")

    members: list[AuthorizationRecordMember] = []
    for spec in specs:
        source = _member_path(path.parent, spec["source_path"])
        if source == path:
            raise ValueError("authorization member must not reference its manifest")
        raw = _capture_regular_file_once(
            source,
            label="authorization record",
            maximum=MAX_AUTHORIZATION_MEMBER_BYTES,
            root_dir=capture_root,
        )
        members.append(
            AuthorizationRecordMember(
                record_id=spec["record_id"],
                filename=spec["source_path"],
                content_hash=spec["content_hash"],
                size_bytes=spec["size_bytes"],
                raw_bytes=raw,
            )
        )
    members.sort(
        key=lambda item: (normalized_identity(item.record_id), item.record_id)
    )
    bundle = AuthorizationRecordBundle(raw_manifest, tuple(members))
    # Loading a raw pack includes strict record parsing from the captured buffer.
    prepare_authorization_record_context(bundle)
    return bundle


def prepare_authorization_record_context(
    bundle: AuthorizationRecordBundle,
) -> AuthorizationRecordContext:
    """Seal exact byte-bound declarations without asserting external truth."""

    if type(bundle) is not AuthorizationRecordBundle:
        raise TypeError("authorization context requires an exact raw bundle")
    manifest = _validate_bundle(bundle)
    pack_version = manifest["contract_version"]
    record_version = (
        SIGNED_AUTHORIZATION_RECORD_CONTRACT_VERSION
        if pack_version == SIGNED_AUTHORIZATION_RECORD_PACK_VERSION
        else AUTHORIZATION_RECORD_CONTRACT_VERSION
    )
    set_version = (
        SIGNED_AUTHORIZATION_RECORD_SET_VERSION
        if pack_version == SIGNED_AUTHORIZATION_RECORD_PACK_VERSION
        else AUTHORIZATION_RECORD_SET_VERSION
    )
    specs = {spec["record_id"]: spec for spec in manifest["members"]}
    claims: list[AuthorizationRecordClaim] = []
    for member in bundle.members:
        record = _validate_record(
            member.raw_bytes,
            expected_record_id=member.record_id,
            expected_contract_version=record_version,
        )
        spec = specs[member.record_id]
        if (
            member.content_hash != spec["content_hash"]
            or member.size_bytes != spec["size_bytes"]
        ):
            raise ValueError("authorization captured bytes differ from manifest")
        claims.append(
            AuthorizationRecordClaim(
                record_id=record["record_id"],
                content_hash=member.content_hash,
                approver_id_claim=record["approver_id_claim"],
                role_claim=record["role_claim"],
                purpose_code=record["purpose_code"],
                scope_code=record["scope_code"],
                effective_from=record["effective_from"],
                expires_at=record["expires_at"],
            )
        )
    claims.sort(
        key=lambda item: (normalized_identity(item.record_id), item.record_id)
    )
    set_subject = {
        "bundle_id": manifest["bundle_id"],
        "contract_version": set_version,
        "members": [
            {
                "content_hash": claim.content_hash,
                "record_id": claim.record_id,
            }
            for claim in claims
        ],
        "pack_contract_version": pack_version,
        "record_contract_version": record_version,
    }
    record_set_hash = hashlib.sha256(
        _SET_DOMAIN + _canonical_bytes(set_subject)
    ).hexdigest()
    return AuthorizationRecordContext(
        bundle_id=manifest["bundle_id"],
        record_set_hash=record_set_hash,
        records=tuple(claims),
        contract_version=set_version,
        _seal=_CONTEXT_SEAL,
    )
