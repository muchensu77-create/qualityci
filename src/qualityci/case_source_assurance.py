"""A08 whole-Case raw source capture and root binding.

This module owns immutable raw material.  Public JSON objects, hashes, state
labels, and caller-created contexts are never accepted as source assurance.
The actual evaluator reparses the owned bytes and derives every identity in the
same call.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .case_builder import (
    DERIVED_LOCATOR_CONTRACT_VERSION,
    DOCUMENT_TYPES,
    IDENTICAL_VALUE_AGGREGATION_CONTRACT_VERSION,
    MANIFEST_VERSION,
    MAPPING_CONTRACT_VERSION,
    MAPPING_VALUE_CONVERSION_CONTRACT_VERSION,
    PARSER_CONSUMPTION_PLAN_VERSION,
    ManifestError,
    _build_case_and_reference_context_from_source_bundle,
    _validate_manifest,
)
from .controlled_references import (
    DERIVED_REFERENCE_IDENTITY_CONTRACT_VERSION,
    _ControlledReferenceContext,
    _is_sealed_reference_context,
)
from .ingestion import (
    DEFAULT_LIMITS,
    INGESTION_POLICY_VERSION,
    _read_source,
    _resolve_source,
)
from .loader import (
    CASE_SCHEMA_VERSION,
    CONTROLLED_REFERENCE_CONTRACT_VERSION,
    MAX_MUTATION_OPERATIONS,
    apply_mutation,
    canonical_hash,
    prepare_case,
    strict_json_loads,
)
from .revision_artifacts import (
    ARTIFACT_CONTRACT_VERSION,
    ArtifactContext,
    RevisionArtifactError,
    resolve_case_from_artifact_context,
)


CASE_SOURCE_PACK_CONTRACT_VERSION = "qualityci-case-source-pack-0.1"
CASE_SOURCE_SET_CONTRACT_VERSION = "qualityci-case-source-set-0.1"
CASE_SOURCE_LINEAGE_CONTRACT_VERSION = "qualityci-case-source-lineage-0.1"
CASE_SOURCE_MUTATION_OPERATION_CONTRACT_VERSION = (
    "qualityci-case-source-mutation-operation-0.1"
)
CASE_SOURCE_NATIVE_REPLAY_OPERATION_CONTRACT_VERSION = (
    "qualityci-case-source-native-replay-operation-0.1"
)
RUN_RESULT_CONTRACT_VERSION = "qualityci-run-result-0.2"
RUN_IDENTITY_VERSION = "qualityci-run-identity-v4"

CASE_SOURCE_UNBOUND = "UNBOUND_SERIALIZED_CASE"
CASE_SOURCE_BOUND = "BOUND_RAW_SOURCE_CASE"
CASE_SOURCE_DERIVED = "SOURCE_ROOTED_DERIVATION"

_SOURCE_SET_DOMAIN = b"QualityCI/case-source-set/v1\0"
_SOURCE_BINDING_DOMAIN = b"QualityCI/case-source-binding/v1\0"
_SOURCE_LINEAGE_DOMAIN = b"QualityCI/case-source-lineage/v1\0"
_MUTATION_OPERATION_DOMAIN = b"QualityCI/case-source-operation/mutation/v1\0"
_NATIVE_REPLAY_OPERATION_DOMAIN = (
    b"QualityCI/case-source-operation/native-replay/v1\0"
)
_SOURCE_KINDS = frozenset({"JSON", "CSV", "XLSX", "DOCX"})
_SNAPSHOT_KINDS = frozenset({"FILESYSTEM_SINGLE_SNAPSHOT", "IN_MEMORY_BUNDLE"})
_CONTEXT_SEAL = object()
_FILESYSTEM_SNAPSHOT_SEAL = object()


class CaseSourceError(ValueError):
    """Raw Case source material is incomplete, ambiguous, or inconsistent."""


def _canonical_json_text(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise CaseSourceError("case source value is not canonical JSON") from error


def _canonical_json_bytes(value: Any) -> bytes:
    return _canonical_json_text(value).encode("utf-8")


def _domain_hash(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + _canonical_json_bytes(value)).hexdigest()


def _exact_nonempty(value: Any, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise CaseSourceError(f"{label} must be an exact non-empty trimmed string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise CaseSourceError(f"{label} contains a control character")
    return value


def _normalized_identity(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def _normalized_path(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _validate_relative_source_path(value: Any, label: str) -> str:
    path = _exact_nonempty(value, label)
    if "\\" in path:
        raise CaseSourceError(f"{label} must use canonical POSIX separators")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise CaseSourceError(f"{label} must be one canonical pack-relative path")
    if parsed.as_posix() != path:
        raise CaseSourceError(f"{label} must be one canonical pack-relative path")
    return path


@dataclass(frozen=True, slots=True)
class CaseSourceCapture:
    relative_path: str
    size_bytes: int
    source_kind: str
    filesystem_safe: bool

    def __post_init__(self) -> None:
        _validate_relative_source_path(self.relative_path, "capture.relative_path")
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise CaseSourceError("capture.size_bytes must be a non-negative integer")
        if type(self.source_kind) is not str or self.source_kind not in _SOURCE_KINDS:
            raise CaseSourceError("capture.source_kind is unsupported")
        if type(self.filesystem_safe) is not bool:
            raise CaseSourceError("capture.filesystem_safe must be an exact bool")


@dataclass(frozen=True, slots=True)
class CaseSourceSnapshot:
    source_kind: str
    captures: tuple[CaseSourceCapture, ...]
    _seal: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.source_kind) is not str or self.source_kind not in _SNAPSHOT_KINDS:
            raise CaseSourceError("snapshot.source_kind is unsupported")
        if type(self.captures) is not tuple or len(self.captures) != 6:
            raise CaseSourceError("case source snapshot must contain exactly six captures")
        if any(type(item) is not CaseSourceCapture for item in self.captures):
            raise CaseSourceError("snapshot captures must use the exact capture type")
        paths = [_normalized_path(item.relative_path) for item in self.captures]
        if len(paths) != len(set(paths)):
            raise CaseSourceError("snapshot capture paths have a normalized collision")
        json_count = sum(item.source_kind == "JSON" for item in self.captures)
        if json_count != 1:
            raise CaseSourceError("snapshot must contain exactly one JSON manifest capture")
        if self.source_kind == "FILESYSTEM_SINGLE_SNAPSHOT":
            if self._seal is not _FILESYSTEM_SNAPSHOT_SEAL or not all(
                item.filesystem_safe for item in self.captures
            ):
                raise CaseSourceError(
                    "filesystem safety facts require the filesystem loader"
                )
        elif self._seal is not None or any(
            item.filesystem_safe for item in self.captures
        ):
            raise CaseSourceError(
                "in-memory snapshot captures cannot assert filesystem safety"
            )


@dataclass(frozen=True, slots=True)
class CaseSourceMember:
    document_type: str
    source_id: str
    source_path: str
    source_kind: str
    raw_bytes: bytes
    declared_table_selector_json: str | None

    def __post_init__(self) -> None:
        if type(self.document_type) is not str or self.document_type not in DOCUMENT_TYPES:
            raise CaseSourceError("case source member document_type is unsupported")
        _exact_nonempty(self.source_id, "member.source_id")
        _validate_relative_source_path(self.source_path, "member.source_path")
        if type(self.source_kind) is not str or self.source_kind not in {
            "CSV",
            "XLSX",
            "DOCX",
        }:
            raise CaseSourceError("case source member source_kind is unsupported")
        expected_kind = Path(self.source_path).suffix.removeprefix(".").upper()
        if self.source_kind != expected_kind:
            raise CaseSourceError("case source member kind differs from its path")
        if type(self.raw_bytes) is not bytes:
            raise CaseSourceError("case source member raw_bytes must be exact immutable bytes")
        if self.declared_table_selector_json is not None:
            if type(self.declared_table_selector_json) is not str:
                raise CaseSourceError("declared table selector must be canonical JSON text")
            try:
                selector = strict_json_loads(self.declared_table_selector_json)
            except (TypeError, ValueError) as error:
                raise CaseSourceError("declared table selector is invalid JSON") from error
            if type(selector) is not dict:
                raise CaseSourceError("declared table selector must be an object")
            if _canonical_json_text(selector) != self.declared_table_selector_json:
                raise CaseSourceError("declared table selector JSON is not canonical")


@dataclass(frozen=True, slots=True)
class CaseSourceBundle:
    manifest_bytes: bytes
    members: tuple[CaseSourceMember, ...]
    snapshot: CaseSourceSnapshot
    contract_version: str = CASE_SOURCE_PACK_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.manifest_bytes) is not bytes:
            raise CaseSourceError("case source manifest_bytes must be exact immutable bytes")
        if type(self.members) is not tuple or len(self.members) != len(DOCUMENT_TYPES):
            raise CaseSourceError("case source bundle must contain exactly five members")
        if any(type(item) is not CaseSourceMember for item in self.members):
            raise CaseSourceError("case source members must use the exact member type")
        if type(self.snapshot) is not CaseSourceSnapshot:
            raise CaseSourceError("case source bundle requires the exact snapshot type")
        if self.contract_version != CASE_SOURCE_PACK_CONTRACT_VERSION:
            raise CaseSourceError("unsupported case source pack contract version")

        by_role = {item.document_type: item for item in self.members}
        if len(by_role) != len(DOCUMENT_TYPES) or set(by_role) != set(DOCUMENT_TYPES):
            raise CaseSourceError("case source bundle repeats or omits a document role")
        if tuple(item.document_type for item in self.members) != tuple(DOCUMENT_TYPES):
            raise CaseSourceError(
                "case source members must use the canonical role order"
            )
        ordered = self.members

        source_ids = [_normalized_identity(item.source_id) for item in ordered]
        source_paths = [_normalized_path(item.source_path) for item in ordered]
        source_hashes = [hashlib.sha256(item.raw_bytes).hexdigest() for item in ordered]
        for values, label in (
            (source_ids, "source_id"),
            (source_paths, "source_path"),
            (source_hashes, "raw member bytes"),
        ):
            if len(values) != len(set(values)):
                raise CaseSourceError(f"case source bundle has a normalized {label} collision")

        captures_by_path = {
            _normalized_path(item.relative_path): item for item in self.snapshot.captures
        }
        manifest_captures = [
            item for item in self.snapshot.captures if item.source_kind == "JSON"
        ]
        expected_paths = {_normalized_path(item.source_path) for item in ordered}
        if set(captures_by_path) - {
            _normalized_path(manifest_captures[0].relative_path)
        } != expected_paths:
            raise CaseSourceError("snapshot capture set differs from manifest plus five members")
        if manifest_captures[0].size_bytes != len(self.manifest_bytes):
            raise CaseSourceError("manifest capture size differs from owned bytes")
        for member in ordered:
            capture = captures_by_path[_normalized_path(member.source_path)]
            if capture.size_bytes != len(member.raw_bytes):
                raise CaseSourceError("member capture size differs from owned bytes")
            if capture.source_kind != member.source_kind:
                raise CaseSourceError("member capture kind differs from owned member")


@dataclass(frozen=True, slots=True)
class CaseMutationBundle:
    raw_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.raw_bytes) is not bytes:
            raise CaseSourceError("mutation raw_bytes must be exact immutable bytes")


@dataclass(frozen=True, slots=True)
class CaseSourceSetMember:
    document_type: str
    source_id: str
    source_path: str
    source_kind: str
    size_bytes: int
    source_hash: str
    declared_table_selector_json: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_type": self.document_type,
            "source_id": self.source_id,
            "source_path": self.source_path,
            "source_kind": self.source_kind,
            "size_bytes": self.size_bytes,
            "source_hash": self.source_hash,
            "declared_table_selector": (
                None
                if self.declared_table_selector_json is None
                else strict_json_loads(self.declared_table_selector_json)
            ),
        }


@dataclass(frozen=True, slots=True)
class CaseSourceSet:
    source_set_hash: str
    source_set_contract_version: str
    source_pack_contract_version: str
    manifest_source_hash: str
    manifest_size_bytes: int
    members: tuple[CaseSourceSetMember, ...]

    def identity_projection(self) -> dict[str, Any]:
        return {
            "source_set_contract_version": self.source_set_contract_version,
            "source_pack_contract_version": self.source_pack_contract_version,
            "builder_manifest": {
                "source_hash": self.manifest_source_hash,
                "size_bytes": self.manifest_size_bytes,
            },
            "members": [member.to_dict() for member in self.members],
        }

    def to_dict(self) -> dict[str, Any]:
        return {"source_set_hash": self.source_set_hash, **self.identity_projection()}


@dataclass(frozen=True, slots=True)
class CaseSourceLineage:
    contract_version: str
    lineage_hash: str
    root_binding_hash: str
    parent_lineage_hash: str | None
    input_case_hash: str
    operation_kind: str
    operation_contract_version: str
    operation_material_hash: str
    output_case_hash: str
    _operation_material_json: str
    _operation_blob_bytes: bytes

    def __post_init__(self) -> None:
        if self.contract_version != CASE_SOURCE_LINEAGE_CONTRACT_VERSION:
            raise CaseSourceError("unsupported case source lineage contract")
        for value, label in (
            (self.lineage_hash, "lineage hash"),
            (self.root_binding_hash, "root binding hash"),
            (self.input_case_hash, "lineage input Case hash"),
            (self.operation_material_hash, "operation material hash"),
            (self.output_case_hash, "lineage output Case hash"),
        ):
            _lower_hash(value, label)
        if self.parent_lineage_hash is not None:
            _lower_hash(self.parent_lineage_hash, "parent lineage hash")
            if self.parent_lineage_hash == self.lineage_hash:
                raise CaseSourceError("lineage cannot name itself as parent")
        if self.operation_kind not in {"MUTATION", "NATIVE_REPLAY"}:
            raise CaseSourceError("case source lineage operation kind is unsupported")
        expected_version = {
            "MUTATION": CASE_SOURCE_MUTATION_OPERATION_CONTRACT_VERSION,
            "NATIVE_REPLAY": CASE_SOURCE_NATIVE_REPLAY_OPERATION_CONTRACT_VERSION,
        }[self.operation_kind]
        if self.operation_contract_version != expected_version:
            raise CaseSourceError("lineage operation contract is inconsistent")
        if type(self._operation_material_json) is not str:
            raise CaseSourceError("lineage operation material must be canonical JSON")
        material = strict_json_loads(self._operation_material_json)
        if type(material) is not dict or _canonical_json_text(material) != (
            self._operation_material_json
        ):
            raise CaseSourceError("lineage operation material JSON is not canonical")
        if type(self._operation_blob_bytes) is not bytes:
            raise CaseSourceError("lineage operation blob must be exact immutable bytes")

    @property
    def operation_blob_source_hash(self) -> str:
        return hashlib.sha256(self._operation_blob_bytes).hexdigest()

    @property
    def operation_material_source_hash(self) -> str:
        return hashlib.sha256(self._operation_material_json.encode("utf-8")).hexdigest()

    def operation_material(self) -> dict[str, Any]:
        value = strict_json_loads(self._operation_material_json)
        if type(value) is not dict:
            raise AssertionError("sealed lineage operation material is not an object")
        return value

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "lineage_hash": self.lineage_hash,
            "root_binding_hash": self.root_binding_hash,
            "parent_lineage_hash": self.parent_lineage_hash,
            "input_case_hash": self.input_case_hash,
            "operation_kind": self.operation_kind,
            "operation_contract_version": self.operation_contract_version,
            "operation_material_hash": self.operation_material_hash,
            "operation_material": self.operation_material(),
            "output_case_hash": self.output_case_hash,
        }


def _lower_hash(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CaseSourceError(f"{label} must be one lowercase SHA-256 value")
    return value


def validate_case_source_assurance_payload(value: Any) -> dict[str, Any]:
    """Validate an output tuple; this function never constructs authority."""

    keys = {
        "case_source_assurance_state",
        "case_source_pack_contract_version",
        "case_source_set_contract_version",
        "case_source_set_hash",
        "case_source_binding_hash",
        "case_source_lineage_contract_version",
        "case_source_lineage_hash",
    }
    if type(value) is not dict or set(value) != keys:
        raise CaseSourceError("case source assurance must contain the exact field set")
    state = value["case_source_assurance_state"]
    if type(state) is not str or state not in {
        CASE_SOURCE_UNBOUND,
        CASE_SOURCE_BOUND,
        CASE_SOURCE_DERIVED,
    }:
        raise CaseSourceError("case source assurance state is unsupported")
    if state == CASE_SOURCE_UNBOUND:
        if any(value[key] is not None for key in keys - {"case_source_assurance_state"}):
            raise CaseSourceError("unbound Case source assurance requires null identities")
    else:
        if value["case_source_pack_contract_version"] != (
            CASE_SOURCE_PACK_CONTRACT_VERSION
        ):
            raise CaseSourceError("case source pack version is inconsistent")
        if value["case_source_set_contract_version"] != (
            CASE_SOURCE_SET_CONTRACT_VERSION
        ):
            raise CaseSourceError("case source set version is inconsistent")
        _lower_hash(value["case_source_set_hash"], "case source set hash")
        _lower_hash(value["case_source_binding_hash"], "case source binding hash")
        if state == CASE_SOURCE_BOUND:
            if (
                value["case_source_lineage_contract_version"] is not None
                or value["case_source_lineage_hash"] is not None
            ):
                raise CaseSourceError("bound root Case cannot claim a lineage")
        else:
            if value["case_source_lineage_contract_version"] != (
                CASE_SOURCE_LINEAGE_CONTRACT_VERSION
            ):
                raise CaseSourceError("derived Case requires the lineage contract")
            _lower_hash(value["case_source_lineage_hash"], "case source lineage hash")
    return dict(value)


@dataclass(frozen=True, slots=True)
class CaseSourceAssurance:
    case_source_assurance_state: str
    case_source_pack_contract_version: str | None
    case_source_set_contract_version: str | None
    case_source_set_hash: str | None
    case_source_binding_hash: str | None
    case_source_lineage_contract_version: str | None
    case_source_lineage_hash: str | None

    def __post_init__(self) -> None:
        validate_case_source_assurance_payload(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_source_assurance_state": self.case_source_assurance_state,
            "case_source_pack_contract_version": (
                self.case_source_pack_contract_version
            ),
            "case_source_set_contract_version": self.case_source_set_contract_version,
            "case_source_set_hash": self.case_source_set_hash,
            "case_source_binding_hash": self.case_source_binding_hash,
            "case_source_lineage_contract_version": (
                self.case_source_lineage_contract_version
            ),
            "case_source_lineage_hash": self.case_source_lineage_hash,
        }


def unbound_case_source_assurance() -> CaseSourceAssurance:
    return CaseSourceAssurance(
        case_source_assurance_state=CASE_SOURCE_UNBOUND,
        case_source_pack_contract_version=None,
        case_source_set_contract_version=None,
        case_source_set_hash=None,
        case_source_binding_hash=None,
        case_source_lineage_contract_version=None,
        case_source_lineage_hash=None,
    )


@dataclass(frozen=True, slots=True)
class _CaseSourceContext:
    _seal: object
    bundle: CaseSourceBundle
    case_source_set: CaseSourceSet
    case_source_binding_hash: str
    root_case_hash: str
    _case_json: str
    _reference_context: Any
    lineages: tuple[CaseSourceLineage, ...]

    def case(self) -> dict[str, Any]:
        value = strict_json_loads(self._case_json)
        if type(value) is not dict:
            raise AssertionError("sealed root Case JSON is not an object")
        return value

    def assurance(self) -> CaseSourceAssurance:
        terminal = self.lineages[-1] if self.lineages else None
        return CaseSourceAssurance(
            case_source_assurance_state=(
                CASE_SOURCE_BOUND if terminal is None else CASE_SOURCE_DERIVED
            ),
            case_source_pack_contract_version=CASE_SOURCE_PACK_CONTRACT_VERSION,
            case_source_set_contract_version=CASE_SOURCE_SET_CONTRACT_VERSION,
            case_source_set_hash=self.case_source_set.source_set_hash,
            case_source_binding_hash=self.case_source_binding_hash,
            case_source_lineage_contract_version=(
                None if terminal is None else terminal.contract_version
            ),
            case_source_lineage_hash=(
                None if terminal is None else terminal.lineage_hash
            ),
        )


def _is_sealed_case_source_context(value: object) -> bool:
    return type(value) is _CaseSourceContext and value._seal is _CONTEXT_SEAL


def _decode_manifest(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CaseSourceError("case source manifest must be UTF-8 JSON") from error
    try:
        value = strict_json_loads(text)
    except (TypeError, ValueError) as error:
        raise CaseSourceError(f"invalid case source manifest JSON: {error}") from error
    if type(value) is not dict:
        raise CaseSourceError("case source manifest root must be an object")
    return value


def _validate_manifest_identities(document_specs: list[dict[str, Any]]) -> None:
    fields = {
        "source_id": [_normalized_identity(item["source_id"]) for item in document_specs],
        "source_path": [_normalized_path(item["source_path"]) for item in document_specs],
        "document_id": [
            _normalized_identity(item["document_id"]) for item in document_specs
        ],
    }
    for label, values in fields.items():
        if len(values) != len(set(values)):
            raise CaseSourceError(f"manifest has a normalized {label} collision")


def _capture_filesystem_bytes(
    path: Path,
    *,
    root: Path,
    expected_root_identity: tuple[Any, ...] | None = None,
) -> tuple[str, str, bytes, tuple[Any, ...]]:
    """Read once while pinning every member to the manifest's root identity."""

    source = _resolve_source(path, root)
    root_identity = (
        source.root_device,
        source.root_inode,
        source.root_windows_file_id,
    )
    if expected_root_identity is not None and root_identity != expected_root_identity:
        raise CaseSourceError("case source root changed during snapshot capture")
    raw, size = _read_source(source, DEFAULT_LIMITS)
    if size != len(raw):
        raise AssertionError("bounded source read returned an inconsistent size")
    return source.path.name, source.display_path, raw, root_identity


def load_case_source_bundle(manifest_path: str | Path) -> CaseSourceBundle:
    """Capture one Builder manifest and its exact five members exactly once."""

    requested = Path(manifest_path)
    root = requested.parent
    (
        manifest_name,
        manifest_relative,
        manifest_bytes,
        root_identity,
    ) = _capture_filesystem_bytes(
        requested,
        root=root,
    )
    if Path(manifest_name).suffix.casefold() != ".json":
        raise CaseSourceError("case source manifest must be a JSON file")
    manifest = _decode_manifest(manifest_bytes)
    try:
        _normalized, document_specs = _validate_manifest(manifest)
    except (TypeError, ValueError) as error:
        raise CaseSourceError(f"invalid case source manifest: {error}") from error
    _validate_manifest_identities(document_specs)
    specs_by_type = {item["document_type"]: item for item in document_specs}

    members: list[CaseSourceMember] = []
    captures: list[CaseSourceCapture] = [
        CaseSourceCapture(
            relative_path=manifest_relative,
            size_bytes=len(manifest_bytes),
            source_kind="JSON",
            filesystem_safe=True,
        )
    ]
    for role in DOCUMENT_TYPES:
        spec = specs_by_type[role]
        source_path = _validate_relative_source_path(
            spec["source_path"], f"{role}.source_path"
        )
        expected_kind = Path(source_path).suffix.removeprefix(".").upper()
        if expected_kind not in {"CSV", "XLSX", "DOCX"}:
            raise CaseSourceError("case source members must be CSV/XLSX/DOCX")
        _filename, display_path, raw_bytes, _member_root_identity = (
            _capture_filesystem_bytes(
                root / PurePosixPath(source_path),
                root=root,
                expected_root_identity=root_identity,
            )
        )
        if display_path != source_path:
            raise CaseSourceError("captured member path differs from manifest path")
        selector_json = (
            None
            if spec.get("table_selector") is None
            else _canonical_json_text(spec["table_selector"])
        )
        members.append(
            CaseSourceMember(
                document_type=role,
                source_id=spec["source_id"],
                source_path=source_path,
                source_kind=expected_kind,
                raw_bytes=bytes(raw_bytes),
                declared_table_selector_json=selector_json,
            )
        )
        captures.append(
            CaseSourceCapture(
                relative_path=source_path,
                size_bytes=len(raw_bytes),
                source_kind=expected_kind,
                filesystem_safe=True,
            )
        )
    return _filesystem_case_source_bundle(
        manifest_bytes=bytes(manifest_bytes),
        members=tuple(members),
        captures=tuple(captures),
    )


def _filesystem_case_source_bundle(
    *,
    manifest_bytes: bytes,
    members: tuple[CaseSourceMember, ...],
    captures: tuple[CaseSourceCapture, ...],
) -> CaseSourceBundle:
    """Construct the diagnostic filesystem snapshot only after owned reads."""

    if (
        type(captures) is not tuple
        or len(captures) != 6
        or any(type(item) is not CaseSourceCapture for item in captures)
        or not all(item.filesystem_safe for item in captures)
    ):
        raise CaseSourceError("filesystem snapshot factory received invalid captures")
    paths = [_normalized_path(item.relative_path) for item in captures]
    if len(paths) != len(set(paths)) or sum(
        item.source_kind == "JSON" for item in captures
    ) != 1:
        raise CaseSourceError("filesystem snapshot factory received ambiguous captures")
    snapshot = object.__new__(CaseSourceSnapshot)
    object.__setattr__(snapshot, "source_kind", "FILESYSTEM_SINGLE_SNAPSHOT")
    object.__setattr__(snapshot, "captures", captures)
    object.__setattr__(snapshot, "_seal", _FILESYSTEM_SNAPSHOT_SEAL)
    return CaseSourceBundle(
        manifest_bytes=manifest_bytes,
        members=members,
        snapshot=snapshot,
    )


def load_case_mutation_bundle(
    path: str | Path,
    *,
    root_dir: str | Path | None = None,
) -> CaseMutationBundle:
    """Capture one mutation beneath an optional caller-owned security root."""

    requested = Path(path)
    root = Path(root_dir) if root_dir is not None else requested.parent
    _name, _relative, raw, _root_identity = _capture_filesystem_bytes(
        requested,
        root=root,
    )
    if requested.suffix.casefold() != ".json":
        raise CaseSourceError("case mutation bundle must be captured from JSON")
    _decode_mutation(raw)
    return CaseMutationBundle(bytes(raw))


def _prepare_case_source_context(bundle: CaseSourceBundle) -> _CaseSourceContext:
    """Rebuild the root Case, source-set identity, and versioned binding."""

    if type(bundle) is not CaseSourceBundle:
        raise TypeError("source assurance requires an exact CaseSourceBundle")
    manifest = _decode_manifest(bundle.manifest_bytes)
    try:
        _normalized, document_specs = _validate_manifest(manifest)
    except (TypeError, ValueError) as error:
        raise CaseSourceError(f"invalid case source manifest: {error}") from error
    _validate_manifest_identities(document_specs)
    specs_by_type = {item["document_type"]: item for item in document_specs}
    members_by_type = {item.document_type: item for item in bundle.members}
    for role in DOCUMENT_TYPES:
        spec = specs_by_type[role]
        member = members_by_type[role]
        selector_json = (
            None
            if spec.get("table_selector") is None
            else _canonical_json_text(spec["table_selector"])
        )
        if (
            member.source_id != spec["source_id"]
            or member.source_path != spec["source_path"]
            or member.declared_table_selector_json != selector_json
        ):
            raise CaseSourceError(f"case source member differs from manifest: {role}")

    case, reference_context = _build_case_and_reference_context_from_source_bundle(
        bundle
    )
    root_case_hash = canonical_hash(case)
    set_members = tuple(
        CaseSourceSetMember(
            document_type=member.document_type,
            source_id=member.source_id,
            source_path=member.source_path,
            source_kind=member.source_kind,
            size_bytes=len(member.raw_bytes),
            source_hash=hashlib.sha256(member.raw_bytes).hexdigest(),
            declared_table_selector_json=member.declared_table_selector_json,
        )
        for member in bundle.members
    )
    source_set_without_hash = {
        "source_set_contract_version": CASE_SOURCE_SET_CONTRACT_VERSION,
        "source_pack_contract_version": CASE_SOURCE_PACK_CONTRACT_VERSION,
        "builder_manifest": {
            "source_hash": hashlib.sha256(bundle.manifest_bytes).hexdigest(),
            "size_bytes": len(bundle.manifest_bytes),
        },
        "members": [member.to_dict() for member in set_members],
    }
    source_set = CaseSourceSet(
        source_set_hash=_domain_hash(_SOURCE_SET_DOMAIN, source_set_without_hash),
        source_set_contract_version=CASE_SOURCE_SET_CONTRACT_VERSION,
        source_pack_contract_version=CASE_SOURCE_PACK_CONTRACT_VERSION,
        manifest_source_hash=source_set_without_hash["builder_manifest"]["source_hash"],
        manifest_size_bytes=len(bundle.manifest_bytes),
        members=set_members,
    )
    binding_projection = {
        "source_set_hash": source_set.source_set_hash,
        "case_hash": root_case_hash,
        "case_schema_version": CASE_SCHEMA_VERSION,
        "builder_manifest_version": MANIFEST_VERSION,
        "ingestion_policy_version": INGESTION_POLICY_VERSION,
        "parser_consumption_plan_version": PARSER_CONSUMPTION_PLAN_VERSION,
        "mapping_contract_version": MAPPING_CONTRACT_VERSION,
        "derived_locator_contract_version": DERIVED_LOCATOR_CONTRACT_VERSION,
        "identical_value_aggregation_contract_version": (
            IDENTICAL_VALUE_AGGREGATION_CONTRACT_VERSION
        ),
        "mapping_value_conversion_contract_version": (
            MAPPING_VALUE_CONVERSION_CONTRACT_VERSION
        ),
        "derived_reference_identity_contract_version": (
            DERIVED_REFERENCE_IDENTITY_CONTRACT_VERSION
        ),
        "controlled_reference_contract_version": (
            CONTROLLED_REFERENCE_CONTRACT_VERSION
        ),
    }
    return _CaseSourceContext(
        _seal=_CONTEXT_SEAL,
        bundle=bundle,
        case_source_set=source_set,
        case_source_binding_hash=_domain_hash(
            _SOURCE_BINDING_DOMAIN, binding_projection
        ),
        root_case_hash=root_case_hash,
        _case_json=_canonical_json_text(case),
        _reference_context=reference_context,
        lineages=(),
    )


def _decode_mutation(raw: bytes) -> dict[str, Any]:
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError) as error:
        raise CaseSourceError(f"invalid mutation raw JSON: {error}") from error
    if type(value) is not dict:
        raise CaseSourceError("mutation raw JSON root must be an object")
    mutation_id = _exact_nonempty(value.get("mutation_id"), "mutation_id")
    operations = value.get("operations")
    if (
        type(operations) is not list
        or not operations
        or len(operations) > MAX_MUTATION_OPERATIONS
    ):
        raise CaseSourceError("mutation operations must be one bounded non-empty list")
    normalized_operations: list[dict[str, Any]] = []
    for index, operation in enumerate(operations):
        if type(operation) is not dict:
            raise CaseSourceError(f"mutation operations[{index}] must be an object")
        target = operation.get("target", "document")
        if type(target) is not str or target not in {"document", "event", "case"}:
            raise CaseSourceError(f"mutation operations[{index}] target is unsupported")
        op = operation.get("op")
        if type(op) is not str or op not in {"set", "delete"}:
            raise CaseSourceError(f"mutation operations[{index}] op is unsupported")
        path = _exact_nonempty(operation.get("path"), f"mutation operations[{index}].path")
        allowed = {"op", "path"}
        if "target" in operation:
            allowed.add("target")
        document_id: str | None
        if target == "document":
            document_id = _exact_nonempty(
                operation.get("document_id"),
                f"mutation operations[{index}].document_id",
            )
            allowed.add("document_id")
        else:
            document_id = None
            if "document_id" in operation:
                raise CaseSourceError(
                    f"mutation operations[{index}] non-document target forbids document_id"
                )
        if op == "set":
            if "value" not in operation:
                raise CaseSourceError(
                    f"mutation operations[{index}] set requires value"
                )
            allowed.add("value")
            value_projection = {"present": True, "json": operation["value"]}
            _canonical_json_text(operation["value"])
        else:
            if "value" in operation:
                raise CaseSourceError(
                    f"mutation operations[{index}] delete forbids value"
                )
            value_projection = {"present": False}
        if set(operation) != allowed:
            raise CaseSourceError(
                f"mutation operations[{index}] contains unknown or inconsistent fields"
            )
        normalized_operations.append(
            {
                "sequence": index,
                "op": op,
                "target": target,
                "document_id": document_id,
                "path": path,
                "value": value_projection,
            }
        )
    return {"mutation_id": mutation_id, "operations": normalized_operations}


def _mutation_for_application(material: dict[str, Any]) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []
    for projected in material["applied_operations"]:
        operation: dict[str, Any] = {
            "op": projected["op"],
            "target": projected["target"],
            "path": projected["path"],
        }
        if projected["document_id"] is not None:
            operation["document_id"] = projected["document_id"]
        if projected["value"]["present"] is True:
            operation["value"] = projected["value"]["json"]
        operations.append(operation)
    return {"mutation_id": material["mutation_id"], "operations": operations}


_NATIVE_REPLAY_MATERIAL_KEYS = frozenset(
    {
        "operation_kind",
        "operation_contract_version",
        "native_resolution_blob",
        "resolution_id",
        "applied_operations",
        "artifact_set_hash",
        "artifact_contract_version",
        "controlled_reference_set_hash",
        "reference_contract_version",
        "source_validation_evidence_set_hash",
        "resolved_validation_evidence_set_hash",
        "validation_evidence_pair_hash",
        "validation_evidence_contract_version",
        "approval_subject_hash",
        "approval_subject_contract_version",
        "approval_assertion_set_hash",
        "approval_assertion_set_domain_version",
        "authorization_authenticity_state",
        "authorization_authenticity_context_hash",
        "authorization_authenticity_context_contract_version",
        "authorization_record_set_hash",
        "authorization_record_set_contract_version",
        "authorization_trust_snapshot_hash",
        "authorization_trust_snapshot_contract_version",
        "authorization_trust_policy_hash",
        "authorization_trust_policy_version",
    }
)
_NATIVE_REPLAY_HASH_FIELDS = frozenset(
    {
        "artifact_set_hash",
        "controlled_reference_set_hash",
        "source_validation_evidence_set_hash",
        "resolved_validation_evidence_set_hash",
        "validation_evidence_pair_hash",
        "approval_subject_hash",
        "approval_assertion_set_hash",
        "authorization_authenticity_context_hash",
        "authorization_record_set_hash",
        "authorization_trust_snapshot_hash",
        "authorization_trust_policy_hash",
    }
)
_NATIVE_REPLAY_CONSTANT_FIELDS = {
    "operation_kind": "NATIVE_REPLAY",
    "operation_contract_version": (
        CASE_SOURCE_NATIVE_REPLAY_OPERATION_CONTRACT_VERSION
    ),
    "artifact_contract_version": "qualityci-revision-artifact-0.3",
    "reference_contract_version": "qualityci-controlled-reference-0.1",
    "validation_evidence_contract_version": (
        "qualityci-validation-evidence-0.1"
    ),
    "approval_subject_contract_version": "qualityci-approval-subject-0.2",
    "approval_assertion_set_domain_version": (
        "QualityCI/approval-assertion-set/v1"
    ),
    "authorization_authenticity_state": "PASS",
    "authorization_authenticity_context_contract_version": (
        "qualityci-authorization-authenticity-context-0.1"
    ),
    "authorization_record_set_contract_version": (
        "qualityci-authorization-record-set-0.2"
    ),
    "authorization_trust_snapshot_contract_version": (
        "qualityci-authorization-trust-snapshot-0.1"
    ),
    "authorization_trust_policy_version": (
        "qualityci-authorization-trust-policy-0.1"
    ),
}


def _native_resolution_projection(raw_bytes: bytes) -> dict[str, Any]:
    try:
        value = strict_json_loads(raw_bytes.decode("utf-8"))
    except (UnicodeError, TypeError, ValueError) as error:
        raise CaseSourceError("native resolution bytes are invalid JSON") from error
    required = {"resolution_id", "description", "replacement_set_id", "operations"}
    if type(value) is not dict or set(value) != required:
        raise CaseSourceError("native resolution must contain the exact raw key set")
    for key in ("resolution_id", "description", "replacement_set_id"):
        _exact_nonempty(value[key], f"native resolution {key}")
    operations = value["operations"]
    if type(operations) is not list or not operations:
        raise CaseSourceError("native resolution operations must be non-empty")
    projected: list[dict[str, Any]] = []
    for index, operation in enumerate(operations):
        if type(operation) is not dict or set(operation) != {
            "op",
            "document_id",
            "path",
            "value",
        }:
            raise CaseSourceError(
                f"native resolution operations[{index}] has an invalid shape"
            )
        if operation["op"] != "set":
            raise CaseSourceError("native resolution permits only set operations")
        document_id = _exact_nonempty(
            operation["document_id"],
            f"native resolution operations[{index}].document_id",
        )
        path = _exact_nonempty(
            operation["path"],
            f"native resolution operations[{index}].path",
        )
        _canonical_json_text(operation["value"])
        projected.append(
            {
                "sequence": index,
                "op": "set",
                "target": "document",
                "document_id": document_id,
                "path": path,
                "value": {"present": True, "json": operation["value"]},
            }
        )
    return {
        "resolution_id": value["resolution_id"],
        "replacement_set_id": value["replacement_set_id"],
        "applied_operations": projected,
    }


def _validate_native_replay_material(
    material: dict[str, Any],
    operation_blob: bytes,
) -> dict[str, Any]:
    if type(material) is not dict or set(material) != _NATIVE_REPLAY_MATERIAL_KEYS:
        raise CaseSourceError("native replay material must contain the exact key set")
    if type(operation_blob) is not bytes:
        raise CaseSourceError("native replay operation blob must be exact bytes")
    for key, expected in _NATIVE_REPLAY_CONSTANT_FIELDS.items():
        if material[key] != expected:
            raise CaseSourceError(f"native replay material {key} is inconsistent")
    for key in _NATIVE_REPLAY_HASH_FIELDS:
        _lower_hash(material[key], f"native replay material {key}")
    blob = material["native_resolution_blob"]
    if type(blob) is not dict or set(blob) != {"source_hash", "size_bytes"}:
        raise CaseSourceError("native replay resolution blob identity is invalid")
    if (
        blob["source_hash"] != hashlib.sha256(operation_blob).hexdigest()
        or type(blob["size_bytes"]) is not int
        or blob["size_bytes"] != len(operation_blob)
    ):
        raise CaseSourceError("native replay resolution blob differs from raw bytes")
    projected = _native_resolution_projection(operation_blob)
    if material["resolution_id"] != projected["resolution_id"]:
        raise CaseSourceError("native replay resolution_id differs from raw bytes")
    if material["applied_operations"] != projected["applied_operations"]:
        raise CaseSourceError("native replay operations differ from raw bytes")
    canonical = strict_json_loads(_canonical_json_text(material))
    if type(canonical) is not dict:
        raise AssertionError("canonical native replay material is not an object")
    return canonical


def _native_operations_for_application(material: dict[str, Any]) -> dict[str, Any]:
    return {
        "mutation_id": f"native-replay:{material['resolution_id']}",
        "operations": [
            {
                "op": operation["op"],
                "target": operation["target"],
                "document_id": operation["document_id"],
                "path": operation["path"],
                "value": operation["value"]["json"],
            }
            for operation in material["applied_operations"]
        ],
    }


def _derive_case_source_mutation(
    context: _CaseSourceContext,
    mutation_bundle: CaseMutationBundle,
) -> _CaseSourceContext:
    if not _is_sealed_case_source_context(context):
        raise TypeError("source mutation requires a sealed source context")
    if type(mutation_bundle) is not CaseMutationBundle:
        raise TypeError("source mutation requires exact CaseMutationBundle")
    decoded = _decode_mutation(mutation_bundle.raw_bytes)
    operation_material = {
        "operation_kind": "MUTATION",
        "operation_contract_version": (
            CASE_SOURCE_MUTATION_OPERATION_CONTRACT_VERSION
        ),
        "mutation_blob": {
            "source_hash": hashlib.sha256(mutation_bundle.raw_bytes).hexdigest(),
            "size_bytes": len(mutation_bundle.raw_bytes),
        },
        "mutation_id": decoded["mutation_id"],
        "applied_operations": decoded["operations"],
    }
    operation_material_json = _canonical_json_text(operation_material)
    operation_material_hash = _domain_hash(
        _MUTATION_OPERATION_DOMAIN,
        operation_material,
    )
    input_case = context.case()
    input_case_hash = canonical_hash(input_case)
    output_case = prepare_case(
        apply_mutation(input_case, _mutation_for_application(operation_material))
    )
    output_case_hash = canonical_hash(output_case)
    parent_lineage_hash = (
        None if not context.lineages else context.lineages[-1].lineage_hash
    )
    lineage_core = {
        "contract_version": CASE_SOURCE_LINEAGE_CONTRACT_VERSION,
        "root_binding_hash": context.case_source_binding_hash,
        "parent_lineage_hash": parent_lineage_hash,
        "input_case_hash": input_case_hash,
        "operation_kind": "MUTATION",
        "operation_contract_version": (
            CASE_SOURCE_MUTATION_OPERATION_CONTRACT_VERSION
        ),
        "operation_material_hash": operation_material_hash,
        "output_case_hash": output_case_hash,
    }
    lineage = CaseSourceLineage(
        contract_version=CASE_SOURCE_LINEAGE_CONTRACT_VERSION,
        lineage_hash=_domain_hash(_SOURCE_LINEAGE_DOMAIN, lineage_core),
        root_binding_hash=context.case_source_binding_hash,
        parent_lineage_hash=parent_lineage_hash,
        input_case_hash=input_case_hash,
        operation_kind="MUTATION",
        operation_contract_version=(
            CASE_SOURCE_MUTATION_OPERATION_CONTRACT_VERSION
        ),
        operation_material_hash=operation_material_hash,
        output_case_hash=output_case_hash,
        _operation_material_json=operation_material_json,
        _operation_blob_bytes=mutation_bundle.raw_bytes,
    )
    if context.lineages:
        previous = context.lineages[-1]
        if previous.output_case_hash != lineage.input_case_hash:
            raise CaseSourceError("mutation lineage input differs from its parent output")
    elif context.root_case_hash != lineage.input_case_hash:
        raise CaseSourceError("first mutation lineage input differs from the root Case")
    return _CaseSourceContext(
        _seal=_CONTEXT_SEAL,
        bundle=context.bundle,
        case_source_set=context.case_source_set,
        case_source_binding_hash=context.case_source_binding_hash,
        root_case_hash=context.root_case_hash,
        _case_json=_canonical_json_text(output_case),
        _reference_context=context._reference_context,
        lineages=(*context.lineages, lineage),
    )


def _derive_case_source_native_replay(
    context: _CaseSourceContext,
    *,
    operation_blob: bytes,
    operation_material: dict[str, Any],
    artifact_context: ArtifactContext,
) -> _CaseSourceContext:
    """Append one native replay lineage from sealed pre-operation facts.

    This private primitive accepts neither a source state nor any lineage/hash
    claim.  It recomputes the raw resolution projection, material identity,
    terminal Case, parent/root closure, and lineage hash before returning a new
    sealed context.
    """

    if not _is_sealed_case_source_context(context):
        raise TypeError("native replay lineage requires a sealed source context")
    material = _validate_native_replay_material(
        operation_material,
        operation_blob,
    )
    if type(artifact_context) is not ArtifactContext or not artifact_context.is_internal():
        raise TypeError(
            "native replay lineage requires an exact sealed artifact context"
        )
    raw_resolution = _native_resolution_projection(operation_blob)
    if (
        artifact_context.artifact_set_hash != material["artifact_set_hash"]
        or artifact_context.artifact_contract_version
        != material["artifact_contract_version"]
        or artifact_context.artifact_contract_version != ARTIFACT_CONTRACT_VERSION
        or artifact_context.replacement_set_id
        != raw_resolution["replacement_set_id"]
        or artifact_context.source_reference_set_hash
        != context._reference_context.reference_set_hash
    ):
        raise CaseSourceError(
            "native replay artifact context differs from operation material"
        )
    output_reference_context = artifact_context.reference_context
    if not _is_sealed_reference_context(output_reference_context):
        raise TypeError(
            "native replay lineage requires an exact sealed output reference context"
        )
    if (
        output_reference_context.reference_set_hash
        != material["controlled_reference_set_hash"]
        or output_reference_context.contract_version
        != material["reference_contract_version"]
    ):
        raise CaseSourceError(
            "native replay output reference context differs from material"
        )
    input_case = context.case()
    try:
        output_case = resolve_case_from_artifact_context(
            input_case,
            material["resolution_id"],
            _native_operations_for_application(material)["operations"],
            artifact_context,
        )
    except RevisionArtifactError as error:
        raise CaseSourceError(
            f"native replay artifact rebuild rejected: {error}"
        ) from error
    input_case_hash = canonical_hash(input_case)
    output_case_hash = canonical_hash(output_case)
    parent_lineage_hash = (
        None if not context.lineages else context.lineages[-1].lineage_hash
    )
    operation_material_json = _canonical_json_text(material)
    operation_material_hash = _domain_hash(
        _NATIVE_REPLAY_OPERATION_DOMAIN,
        material,
    )
    lineage_core = {
        "contract_version": CASE_SOURCE_LINEAGE_CONTRACT_VERSION,
        "root_binding_hash": context.case_source_binding_hash,
        "parent_lineage_hash": parent_lineage_hash,
        "input_case_hash": input_case_hash,
        "operation_kind": "NATIVE_REPLAY",
        "operation_contract_version": (
            CASE_SOURCE_NATIVE_REPLAY_OPERATION_CONTRACT_VERSION
        ),
        "operation_material_hash": operation_material_hash,
        "output_case_hash": output_case_hash,
    }
    lineage = CaseSourceLineage(
        contract_version=CASE_SOURCE_LINEAGE_CONTRACT_VERSION,
        lineage_hash=_domain_hash(_SOURCE_LINEAGE_DOMAIN, lineage_core),
        root_binding_hash=context.case_source_binding_hash,
        parent_lineage_hash=parent_lineage_hash,
        input_case_hash=input_case_hash,
        operation_kind="NATIVE_REPLAY",
        operation_contract_version=(
            CASE_SOURCE_NATIVE_REPLAY_OPERATION_CONTRACT_VERSION
        ),
        operation_material_hash=operation_material_hash,
        output_case_hash=output_case_hash,
        _operation_material_json=operation_material_json,
        _operation_blob_bytes=operation_blob,
    )
    if context.lineages:
        if context.lineages[-1].output_case_hash != lineage.input_case_hash:
            raise CaseSourceError(
                "native replay lineage input differs from parent output"
            )
    elif context.root_case_hash != lineage.input_case_hash:
        raise CaseSourceError("native replay lineage input differs from root Case")
    return _CaseSourceContext(
        _seal=_CONTEXT_SEAL,
        bundle=context.bundle,
        case_source_set=context.case_source_set,
        case_source_binding_hash=context.case_source_binding_hash,
        root_case_hash=context.root_case_hash,
        _case_json=_canonical_json_text(output_case),
        _reference_context=output_reference_context,
        lineages=(*context.lineages, lineage),
    )


__all__ = [
    "CASE_SOURCE_BOUND",
    "CASE_SOURCE_DERIVED",
    "CASE_SOURCE_LINEAGE_CONTRACT_VERSION",
    "CASE_SOURCE_MUTATION_OPERATION_CONTRACT_VERSION",
    "CASE_SOURCE_NATIVE_REPLAY_OPERATION_CONTRACT_VERSION",
    "CASE_SOURCE_PACK_CONTRACT_VERSION",
    "CASE_SOURCE_SET_CONTRACT_VERSION",
    "CASE_SOURCE_UNBOUND",
    "RUN_IDENTITY_VERSION",
    "RUN_RESULT_CONTRACT_VERSION",
    "CaseSourceAssurance",
    "CaseSourceBundle",
    "CaseSourceCapture",
    "CaseSourceError",
    "CaseSourceLineage",
    "CaseSourceMember",
    "CaseMutationBundle",
    "CaseSourceSet",
    "CaseSourceSetMember",
    "CaseSourceSnapshot",
    "load_case_source_bundle",
    "load_case_mutation_bundle",
    "unbound_case_source_assurance",
    "validate_case_source_assurance_payload",
]
