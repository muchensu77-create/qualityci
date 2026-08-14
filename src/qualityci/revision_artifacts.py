"""Content-addressed revision artifacts for approved document replacements."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Mapping

from .case_builder import (
    ArtifactBuildEvidence,
    CaseBuilderError,
    DERIVED_LOCATOR_CONTRACT_VERSION,
    DERIVED_REFERENCE_IDENTITY_CONTRACT_VERSION,
    MAPPING_CONTRACT_VERSION,
    PARSER_CONSUMPTION_PLAN_VERSION,
    build_document_from_artifact_bytes,
    _finalize_inspection_reference_with_registry,
)
from .controlled_references import (
    ControlledReferenceBundle,
    _ControlledReferenceContext,
    _ReferenceWitness,
    _is_sealed_reference_context,
    _prepare_controlled_reference_context,
    _seal_controlled_reference_context_from_registry,
)
from .ingestion import (
    DEFAULT_LIMITS,
    INGESTION_POLICY_VERSION,
    IngestionError,
    IngestionLimits,
    read_source_bytes,
)
from .loader import (
    CASE_SCHEMA_VERSION,
    MAX_JSON_FILE_BYTES,
    apply_mutation,
    canonical_hash,
    normalized_identity,
    strict_json_loads,
    validate_case,
)


ARTIFACT_CONTRACT_VERSION = "qualityci-revision-artifact-0.3"
ARTIFACT_MANIFEST_VERSION = "qualityci-revision-artifact-pack-0.1"
ARTIFACT_SECURITY_ROOT_POLICY_VERSION = "qualityci-artifact-root-policy-0.1"
MAX_REPLACEMENT_DOCUMENTS = 128
MAX_ARTIFACT_MAPPINGS = 30_000
_DOMAIN = b"QualityCI/revision-artifact-set/v1\0"
_CONTEXT_SEAL = object()
_ROOT_KEYS = {
    "manifest_version",
    "replacement_set_id",
    "case_schema_version",
    "parser_contract_version",
    "mapping_contract_version",
    "security_root_policy_version",
    "documents",
}
_DOCUMENT_KEYS = {
    "source_id",
    "source_path",
    "document_id",
    "document_type",
    "revision",
    "status",
    "owner",
    "revision_date",
    "columns",
    "header_row",
    "table_selector",
    "supersedes",
}
_SUPERSEDES_KEYS = {"document_id", "revision", "source_hash"}
_DOCUMENT_TYPES = {
    "PROCESS_FLOW",
    "PFMEA",
    "CONTROL_PLAN",
    "SOP",
    "INSPECTION_RECORD",
}
_DOCUMENT_STATUSES = {"DRAFT", "APPROVED", "SUPERSEDED"}
_PATH_SEGMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ASCII_SOURCE_EXTENSION = re.compile(
    r"\.(?:csv|xlsx|docx)\Z", flags=re.ASCII | re.IGNORECASE
)
_PROTECTED_ROOTS = {
    "document_id",
    "source_hash",
    "source",
    "mapping_provenance",
    "revision_artifact",
}
_ALLOWED_FACT_ROOTS = {"document_type", "revision", "status", "owner", "revision_date", "fields"}
_FIXED_MAPPING_SOURCE_KEYS = {
    "source_id",
    "document_id",
    "source_hash",
    "locator",
    "kind",
    "coordinates",
    "column",
    "raw_value",
}
_FIXED_MAPPING_SOURCE_STRING_KEYS = (
    "source_id",
    "document_id",
    "source_hash",
    "locator",
    "kind",
    "column",
    "raw_value",
)
_FIXED_MAPPING_COORDINATE_KEYS = {"row", "column"}


class RevisionArtifactError(ValueError):
    """Raised when replacement bytes cannot prove the proposed document facts."""


def normalized_relative_path_identity(value: str) -> str:
    """Validate one canonical NFC pack filename and return its collision key."""

    suffix = Path(value).suffix if isinstance(value, str) else ""
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or value != unicodedata.normalize("NFC", value)
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or any(unicodedata.category(character).startswith("C") for character in value)
        or _ASCII_SOURCE_EXTENSION.fullmatch(suffix) is None
    ):
        raise RevisionArtifactError(
            "source_path/filename must be one canonical NFC relative filename"
        )
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


@dataclass(frozen=True)
class ArtifactMemberBytes:
    source_id: str
    document_id: str
    filename: str
    raw_bytes: bytes

    def __post_init__(self) -> None:
        for name in ("source_id", "document_id", "filename"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise RevisionArtifactError(f"artifact member {name} must be non-empty")
        normalized_relative_path_identity(self.filename)
        raw = self.raw_bytes
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise RevisionArtifactError("artifact member content must be bytes-like")
        object.__setattr__(self, "raw_bytes", bytes(raw))


@dataclass(frozen=True)
class RevisionArtifactBundle:
    """Deeply immutable manifest and captured raw-byte members."""

    canonical_manifest_bytes: bytes
    members: tuple[ArtifactMemberBytes, ...]

    def __post_init__(self) -> None:
        manifest = self.canonical_manifest_bytes
        if not isinstance(manifest, (bytes, bytearray, memoryview)):
            raise RevisionArtifactError("artifact manifest must be bytes-like")
        copied_members = tuple(
            item
            if type(item) is ArtifactMemberBytes
            else ArtifactMemberBytes(
                item.source_id, item.document_id, item.filename, item.raw_bytes
            )
            for item in tuple(self.members)
        )
        object.__setattr__(self, "canonical_manifest_bytes", bytes(manifest))
        object.__setattr__(self, "members", copied_members)


@dataclass(frozen=True)
class ArtifactIndexEntry:
    document_id: str
    source_id: str
    source_path: str
    source_hash: str
    size_bytes: int
    declared_format: str
    detected_format: str
    supersedes_document_id: str
    supersedes_revision: str
    supersedes_source_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "source_id": self.source_id,
            "source_path": self.source_path,
            "source_hash": self.source_hash,
            "size_bytes": self.size_bytes,
            "declared_format": self.declared_format,
            "detected_format": self.detected_format,
            "supersedes": {
                "document_id": self.supersedes_document_id,
                "revision": self.supersedes_revision,
                "source_hash": self.supersedes_source_hash,
            },
        }


@dataclass(frozen=True)
class ArtifactContext:
    """Internally rebuilt context; documents are exposed only by defensive parse."""

    replacement_set_id: str
    artifact_set_hash: str
    documents_json: bytes
    canonical_manifest_bytes: bytes
    members: tuple[ArtifactMemberBytes, ...]
    artifact_index: tuple[ArtifactIndexEntry, ...]
    reference_context: _ControlledReferenceContext | None
    source_reference_set_hash: str | None
    _seal: object = field(repr=False, compare=False)
    artifact_contract_version: str = ARTIFACT_CONTRACT_VERSION
    case_schema_version: str = CASE_SCHEMA_VERSION
    parser_contract_version: str = INGESTION_POLICY_VERSION
    mapping_contract_version: str = MAPPING_CONTRACT_VERSION
    security_root_policy_version: str = ARTIFACT_SECURITY_ROOT_POLICY_VERSION

    def is_internal(self) -> bool:
        return self._seal is _CONTEXT_SEAL

    def documents(self) -> tuple[dict[str, Any], ...]:
        value = strict_json_loads(self.documents_json.decode("utf-8"))
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise RevisionArtifactError("internal artifact documents are invalid")
        return tuple(value)

    def subject_fields(self) -> dict[str, Any]:
        subject = {
            "replacement_set_id": self.replacement_set_id,
            "artifact_set_hash": self.artifact_set_hash,
            "artifact_contract_version": self.artifact_contract_version,
            "case_schema_version": self.case_schema_version,
            "parser_contract_version": self.parser_contract_version,
            "mapping_contract_version": self.mapping_contract_version,
            "security_root_policy_version": self.security_root_policy_version,
            "touched_document_artifacts": [item.to_dict() for item in self.artifact_index],
        }
        if self.reference_context is not None:
            subject.update(
                {
                    "reference_contract_version": self.reference_context.contract_version,
                    "controlled_reference_set_hash": self.reference_context.reference_set_hash,
                    "controlled_reference_source_set_hash": self.source_reference_set_hash,
                }
            )
        return subject


def resolve_case_from_artifact_context(
    pre_case: dict[str, Any],
    resolution_id: str,
    operations: list[dict[str, Any]],
    context: ArtifactContext,
) -> dict[str, Any]:
    """Rebuild the one authoritative post-resolution Case.

    Native replay and source-lineage construction must share this operation:
    applying the approved patch alone is insufficient because the captured
    artifact bytes also rebuild protected document facts and provenance.
    """

    if type(pre_case) is not dict:
        raise RevisionArtifactError("pre-resolution Case must be an exact object")
    if type(resolution_id) is not str or not resolution_id.strip():
        raise RevisionArtifactError("resolution_id must be a non-empty string")
    if type(operations) is not list:
        raise RevisionArtifactError("resolution operations must be an exact list")
    if type(context) is not ArtifactContext or not context.is_internal():
        raise RevisionArtifactError(
            "post-resolution Case requires an internally rebuilt artifact context"
        )
    touched = validate_resolution_operation_paths(operations)
    indexed = [item.document_id for item in context.artifact_index]
    if {
        normalized_identity(item) for item in touched
    } != {
        normalized_identity(item) for item in indexed
    } or len(touched) != len(indexed):
        raise RevisionArtifactError(
            "sealed artifact context does not exactly cover resolution operations"
        )

    proposed = apply_mutation(
        pre_case,
        {
            "mutation_id": f"resolution:{resolution_id}",
            "operations": operations,
        },
    )
    proposed_documents = {
        item["document_id"]: item for item in proposed["documents"]
    }
    rebuilt_sequence = context.documents()
    rebuilt_ids = [item.get("document_id") for item in rebuilt_sequence]
    if (
        any(type(item) is not str or not item for item in rebuilt_ids)
        or len(rebuilt_ids) != len(set(rebuilt_ids))
        or len({normalized_identity(item) for item in rebuilt_ids}) != len(rebuilt_ids)
        or len(rebuilt_ids) != len(indexed)
        or set(rebuilt_ids) != set(indexed)
    ):
        raise RevisionArtifactError(
            "sealed artifact documents do not exactly match its artifact index"
        )
    rebuilt_documents = {
        item["document_id"]: item for item in rebuilt_sequence
    }
    fact_keys = (
        "document_id",
        "document_type",
        "revision",
        "status",
        "owner",
        "revision_date",
        "fields",
    )
    for document_id, rebuilt in rebuilt_documents.items():
        expected = proposed_documents.get(document_id)
        if expected is None or any(
            expected.get(key) != rebuilt.get(key) for key in fact_keys
        ):
            raise RevisionArtifactError(
                "rebuilt artifact facts differ from approved patch for "
                f"{document_id}"
            )
        proposed_documents[document_id] = rebuilt
    proposed["documents"] = list(proposed_documents.values())
    validate_case(proposed)
    if proposed["event"]["risk_level"] != pre_case["event"]["risk_level"]:
        raise RevisionArtifactError(
            "resolution blocked; v0.1 resolutions cannot reclassify event risk; "
            "create a new event revision and approval subject"
        )
    proposed.pop("active_mutation", None)
    proposed["applied_resolution"] = resolution_id
    return proposed


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise RevisionArtifactError("artifact data is not stable canonical JSON") from error


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RevisionArtifactError(f"{label} must be a non-empty string")
    return value


def _validate_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ROOT_KEYS:
        raise RevisionArtifactError(
            f"artifact manifest must contain exactly {sorted(_ROOT_KEYS)}"
        )
    expected_versions = {
        "manifest_version": ARTIFACT_MANIFEST_VERSION,
        "case_schema_version": CASE_SCHEMA_VERSION,
        "parser_contract_version": INGESTION_POLICY_VERSION,
        "mapping_contract_version": MAPPING_CONTRACT_VERSION,
        "security_root_policy_version": ARTIFACT_SECURITY_ROOT_POLICY_VERSION,
    }
    for key, expected in expected_versions.items():
        if value.get(key) != expected:
            raise RevisionArtifactError(f"unsupported {key}: {value.get(key)!r}")
    _require_string(value.get("replacement_set_id"), "replacement_set_id")
    documents = value.get("documents")
    if (
        not isinstance(documents, list)
        or not documents
        or len(documents) > MAX_REPLACEMENT_DOCUMENTS
        or any(not isinstance(item, dict) for item in documents)
    ):
        raise RevisionArtifactError("artifact documents must be a bounded non-empty list")
    seen_documents: set[str] = set()
    seen_sources: set[str] = set()
    seen_paths: set[str] = set()
    for index, spec in enumerate(documents):
        if set(spec) != _DOCUMENT_KEYS:
            raise RevisionArtifactError(
                f"documents[{index}] must contain exactly {sorted(_DOCUMENT_KEYS)}"
            )
        for key in (
            "source_id",
            "source_path",
            "document_id",
            "document_type",
            "revision",
            "status",
            "owner",
            "revision_date",
        ):
            _require_string(spec.get(key), f"documents[{index}].{key}")
        if spec["document_type"] not in _DOCUMENT_TYPES:
            raise RevisionArtifactError(
                f"unsupported documents[{index}].document_type"
            )
        if spec["status"] not in _DOCUMENT_STATUSES:
            raise RevisionArtifactError(f"unsupported documents[{index}].status")
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", spec["revision_date"]) is None:
            raise RevisionArtifactError(
                f"documents[{index}].revision_date must use YYYY-MM-DD format"
            )
        try:
            date.fromisoformat(spec["revision_date"])
        except ValueError as error:
            raise RevisionArtifactError(
                f"documents[{index}].revision_date must be an ISO calendar date"
            ) from error
        source_path_identity = normalized_relative_path_identity(spec["source_path"])
        source_path = Path(spec["source_path"])
        if (
            source_path.is_absolute()
            or ".." in source_path.parts
            or len(source_path.parts) != 1
            or _ASCII_SOURCE_EXTENSION.fullmatch(source_path.suffix) is None
        ):
            raise RevisionArtifactError("source_path must be one relative controlled file")
        supersedes = spec.get("supersedes")
        if not isinstance(supersedes, dict) or set(supersedes) != _SUPERSEDES_KEYS:
            raise RevisionArtifactError("supersedes must contain document_id/revision/source_hash")
        for key in _SUPERSEDES_KEYS:
            _require_string(supersedes.get(key), f"documents[{index}].supersedes.{key}")
        document_key = normalized_identity(spec["document_id"])
        source_key = normalized_identity(spec["source_id"])
        path_key = source_path_identity
        if document_key in seen_documents:
            raise RevisionArtifactError("normalized duplicate replacement document_id")
        if source_key in seen_sources:
            raise RevisionArtifactError("normalized duplicate artifact source_id")
        if path_key in seen_paths:
            raise RevisionArtifactError("normalized duplicate artifact source_path")
        seen_documents.add(document_key)
        seen_sources.add(source_key)
        seen_paths.add(path_key)
        columns = spec.get("columns")
        if (
            type(columns) is not dict
            or not columns
            or any(
                type(key) is not str
                or not key.strip()
                or type(value) is not str
                or not value.strip()
                for key, value in columns.items()
            )
        ):
            raise RevisionArtifactError(
                f"documents[{index}].columns must be a non-empty object "
                "of exact non-empty string keys and values"
            )
        header_row = spec.get("header_row")
        if isinstance(header_row, bool) or not isinstance(header_row, int) or header_row <= 0:
            raise RevisionArtifactError("artifact header_row must be a positive integer")
        if spec.get("table_selector") is not None and not isinstance(
            spec["table_selector"], dict
        ):
            raise RevisionArtifactError("artifact table_selector must be an object or null")
    return value


def artifact_document_sort_key(document_id: str) -> tuple[str, str]:
    return normalized_identity(document_id), document_id


def canonicalize_artifact_manifest(value: Any) -> tuple[dict[str, Any], bytes]:
    manifest = _validate_manifest(value)
    manifest["documents"].sort(
        key=lambda item: artifact_document_sort_key(item["document_id"])
    )
    return manifest, _canonical_bytes(manifest)


def artifact_context_matches_bundle(
    context: ArtifactContext, bundle: RevisionArtifactBundle
) -> bool:
    if (
        type(context) is not ArtifactContext
        or not context.is_internal()
        or type(bundle) is not RevisionArtifactBundle
    ):
        return False
    try:
        _manifest, canonical_bytes = canonicalize_artifact_manifest(
            strict_json_loads(bundle.canonical_manifest_bytes.decode("utf-8"))
        )
    except (UnicodeError, ValueError):
        return False
    members = tuple(
        sorted(
            bundle.members,
            key=lambda item: artifact_document_sort_key(item.document_id),
        )
    )
    return (
        context.canonical_manifest_bytes == canonical_bytes
        and context.members == members
    )


def load_revision_artifact_bundle(
    manifest_path: str | Path,
    *,
    root_dir: str | Path | None = None,
    limits: IngestionLimits = DEFAULT_LIMITS,
) -> RevisionArtifactBundle:
    """Capture a strict manifest and every member exactly once beneath a root."""

    path = Path(manifest_path)
    security_root = Path(root_dir) if root_dir is not None else path.parent
    _name, _display, manifest_raw = read_source_bytes(
        path,
        root_dir=security_root,
        limits=limits,
    )
    if len(manifest_raw) > MAX_JSON_FILE_BYTES:
        raise RevisionArtifactError("artifact manifest exceeds JSON byte limit")
    try:
        manifest = strict_json_loads(manifest_raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise RevisionArtifactError(f"invalid strict artifact manifest: {error}") from error
    manifest, canonical_manifest_bytes = canonicalize_artifact_manifest(manifest)
    members: list[ArtifactMemberBytes] = []
    for spec in manifest["documents"]:
        filename, _relative, raw = read_source_bytes(
            path.parent / spec["source_path"],
            root_dir=security_root,
            limits=limits,
        )
        members.append(
            ArtifactMemberBytes(
                source_id=spec["source_id"],
                document_id=spec["document_id"],
                filename=filename,
                raw_bytes=raw,
            )
        )
    return RevisionArtifactBundle(
        canonical_manifest_bytes=_canonical_bytes(manifest),
        members=tuple(members),
    )


def validate_resolution_operation_paths(operations: Any) -> tuple[str, ...]:
    if not isinstance(operations, list) or not operations:
        raise RevisionArtifactError("resolution operations must be a non-empty list")
    touched: dict[str, str] = {}
    for index, operation in enumerate(operations):
        if not isinstance(operation, dict) or operation.get("target", "document") != "document":
            raise RevisionArtifactError("revision artifacts can replace documents only")
        document_id = _require_string(
            operation.get("document_id"), f"operations[{index}].document_id"
        )
        path = _require_string(operation.get("path"), f"operations[{index}].path")
        segments = path.split(".")
        if any(
            not segment
            or not _PATH_SEGMENT.fullmatch(segment)
            or unicodedata.normalize("NFKC", segment).casefold() != segment
            for segment in segments
        ):
            raise RevisionArtifactError("resolution path contains unsafe or non-canonical segments")
        root = segments[0]
        if root in _PROTECTED_ROOTS or root not in _ALLOWED_FACT_ROOTS:
            raise RevisionArtifactError(
                f"resolution path targets protected/generated field: {path}"
            )
        key = normalized_identity(document_id)
        previous = touched.get(key)
        if previous is not None and previous != document_id:
            raise RevisionArtifactError("normalized duplicate touched document_id")
        touched[key] = document_id
    return tuple(touched[key] for key in sorted(touched))


def _value_at_path(root: Mapping[str, Any], path: str) -> Any:
    cursor: Any = root
    for name, index in re.findall(r"(?:^|\.)([^.\[]+)|\[(\d+)\]", path):
        if name:
            if not isinstance(cursor, Mapping) or name not in cursor:
                raise RevisionArtifactError(f"mapping target does not exist: {path}")
            cursor = cursor[name]
        else:
            position = int(index)
            if not isinstance(cursor, list) or position >= len(cursor):
                raise RevisionArtifactError(f"mapping target index does not exist: {path}")
            cursor = cursor[position]
    return cursor


def _scalar_leaf_paths(value: Any, prefix: str = "fields") -> set[str]:
    if isinstance(value, dict):
        result: set[str] = set()
        for key, item in value.items():
            result.update(_scalar_leaf_paths(item, f"{prefix}.{key}"))
        return result
    if isinstance(value, list):
        result = set()
        for index, item in enumerate(value):
            result.update(_scalar_leaf_paths(item, f"{prefix}[{index}]"))
        return result
    return {prefix}


def _fixed_mapping_source_key(source: Any) -> tuple[Any, ...] | None:
    """Project the exact JSON-native Builder source shape without serializing it."""

    coordinates = source.get("coordinates")
    if (
        type(source) is dict
        and len(source) == len(_FIXED_MAPPING_SOURCE_KEYS)
        and all(key in source for key in _FIXED_MAPPING_SOURCE_KEYS)
        and all(type(source[key]) is str for key in _FIXED_MAPPING_SOURCE_STRING_KEYS)
        and type(coordinates) is dict
        and len(coordinates) == len(_FIXED_MAPPING_COORDINATE_KEYS)
        and all(key in coordinates for key in _FIXED_MAPPING_COORDINATE_KEYS)
        and type(coordinates["row"]) is int
        and type(coordinates["column"]) is int
    ):
        return (
            "fixed-source-v1",
            source["source_id"],
            source["document_id"],
            source["source_hash"],
            source["locator"],
            source["kind"],
            coordinates["row"],
            coordinates["column"],
            source["column"],
            source["raw_value"],
        )
    return None


def _canonical_mapping_source_key(source: Mapping[str, Any]) -> tuple[Any, ...]:
    """Preserve canonical-JSON identity for every non-fixed Python mapping."""

    encoded = json.dumps(
        source,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    # A Mapping subclass can serialize to the same JSON object as the exact
    # Builder shape.  Bridge that cold fallback into the same tuple domain only
    # after a strict JSON round trip; overridden Mapping methods therefore
    # cannot create a false equality with the fast path.
    decoded = json.loads(encoded)
    round_trip = json.dumps(
        decoded,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    if round_trip == encoded:
        fixed = _fixed_mapping_source_key(decoded)
        if fixed is not None:
            return fixed
    return ("canonical-json", encoded)


def _mapping_source_key(source: Mapping[str, Any]) -> tuple[Any, ...]:
    """Return an exact identity key, avoiding JSON for the Builder's fixed shape."""

    fixed = _fixed_mapping_source_key(source)
    if fixed is not None:
        return fixed
    return _canonical_mapping_source_key(source)


def _validate_mapping_closure(
    document: dict[str, Any], *, expected_source_id: str,
    parser_evidence: ArtifactBuildEvidence,
    reference_registry: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    mappings = document.get("mapping_provenance")
    if not isinstance(mappings, list) or not mappings:
        raise RevisionArtifactError("rebuilt document has no mapping provenance")
    if len(mappings) > MAX_ARTIFACT_MAPPINGS:
        raise RevisionArtifactError(
            f"rebuilt document exceeds {MAX_ARTIFACT_MAPPINGS} mapping entries"
        )
    if (
        parser_evidence.consumption_plan_version
        != PARSER_CONSUMPTION_PLAN_VERSION
    ):
        raise RevisionArtifactError(
            "ROW_CONSUMPTION_MISMATCH: parser evidence plan version is unsupported"
        )

    def source_key(source: Any) -> tuple[Any, ...]:
        if not isinstance(source, dict):
            raise RevisionArtifactError(
                "SOURCE_CELL_ROLE_MISMATCH: mapping parser evidence source is not an object"
            )
        return _mapping_source_key(source)

    def entry_sources(entry: dict[str, Any]) -> list[dict[str, Any]]:
        if entry.get("mapping_kind") == "AGGREGATED_IDENTICAL_VALUES":
            sources = entry.get("sources")
            if not isinstance(sources, list):
                raise RevisionArtifactError(
                    "EXPECTED_CONTRIBUTOR_MISSING: aggregate parser evidence has no sources"
                )
            return sources
        return [entry.get("source")]

    parser_cells_by_source: dict[tuple[Any, ...], dict[str, Any]] = {}
    for cell in parser_evidence.parser_cells():
        if set(cell) != {"canonical_name", "row_number", "source"}:
            raise RevisionArtifactError(
                "ROW_CONSUMPTION_MISMATCH: parser cell index has an invalid shape"
            )
        canonical_name = _require_string(
            cell.get("canonical_name"), "parser cell canonical role"
        )
        row_number = cell.get("row_number")
        source = cell.get("source")
        key = source_key(source)
        coordinates = source.get("coordinates") if isinstance(source, dict) else None
        if (
            isinstance(row_number, bool)
            or not isinstance(row_number, int)
            or row_number <= 0
            or not isinstance(coordinates, dict)
            or coordinates.get("row") != row_number
            or source.get("document_id") != document["document_id"]
            or source.get("source_hash") != document["source_hash"]
            or source.get("source_id") != expected_source_id
            or not isinstance(source.get("column"), str)
            or not source["column"].strip()
            or not canonical_name
        ):
            raise RevisionArtifactError(
                "SOURCE_CELL_ROLE_MISMATCH: parser cell identity is inconsistent"
            )
        if key in parser_cells_by_source:
            raise RevisionArtifactError(
                "ROW_CONSUMPTION_MISMATCH: parser cell index contains a duplicate cell"
            )
        parser_cells_by_source[key] = cell
    if not parser_cells_by_source or len(parser_cells_by_source) > MAX_ARTIFACT_MAPPINGS:
        raise RevisionArtifactError(
            "ROW_CONSUMPTION_MISMATCH: parser cell index is empty or exceeds limits"
        )

    expected_by_target: dict[str, dict[str, Any]] = {}
    planned_cell_keys: set[tuple[Any, ...]] = set()
    planned_roles: set[tuple[str, tuple[Any, ...]]] = set()
    for expected in parser_evidence.expected_mappings():
        target = _require_string(expected.get("target"), "parser evidence target")
        if target in expected_by_target:
            raise RevisionArtifactError(
                "ROW_CONSUMPTION_MISMATCH: parser plan repeats an expected target"
            )
        for source in entry_sources(expected):
            key = source_key(source)
            if key not in parser_cells_by_source:
                raise RevisionArtifactError(
                    "SOURCE_CELL_ROLE_MISMATCH: expected role is not backed by a parser cell"
                )
            role = (target, key)
            if role in planned_roles:
                raise RevisionArtifactError(
                    "ROW_CONSUMPTION_MISMATCH: parser cell role is duplicated"
                )
            planned_roles.add(role)
            planned_cell_keys.add(key)
        expected_by_target[target] = expected
    if len(expected_by_target) > MAX_ARTIFACT_MAPPINGS:
        raise RevisionArtifactError("parser evidence exceeds the mapping entry limit")
    if planned_cell_keys != set(parser_cells_by_source):
        raise RevisionArtifactError(
            "ROW_CONSUMPTION_MISMATCH: parser data cells and expected role consumption differ"
        )

    by_target: dict[str, dict[str, Any]] = {}
    direct_rows_by_prefix: dict[str, set[int]] = {}
    derived_targets: list[str] = []
    derived_reference_targets: set[str] = set()
    for entry in mappings:
        if not isinstance(entry, dict):
            raise RevisionArtifactError("mapping provenance entries must be objects")
        target = _require_string(entry.get("target"), "mapping target")
        if target in by_target:
            raise RevisionArtifactError(f"duplicate mapping target: {target}")
        kind = entry.get("mapping_kind")
        is_locator = target.endswith(".locator")
        if is_locator and kind != "DERIVED_LOCATOR":
            raise RevisionArtifactError(f"mapping {target} has wrong mapping_kind")
        if not is_locator and kind not in {
            "DIRECT_CELL_VALUE",
            "AGGREGATED_IDENTICAL_VALUES",
            "DERIVED_REFERENCE_IDENTITY",
        }:
            raise RevisionArtifactError(f"mapping {target} has wrong mapping_kind")
        actual = _value_at_path(document, target)
        if entry.get("value") != actual:
            raise RevisionArtifactError(f"mapping value differs from final field: {target}")
        if kind == "DERIVED_REFERENCE_IDENTITY":
            role = entry.get("reference_role")
            registry_identity = (
                reference_registry.get(role)
                if isinstance(reference_registry, Mapping) and isinstance(role, str)
                else None
            )
            leaf = target.rsplit(".", 1)[-1]
            if (
                not isinstance(role, str)
                or not target.startswith(f"fields.references.{role}.")
                or leaf not in {"document_type", "source_hash"}
                or entry.get("derivation_contract")
                != DERIVED_REFERENCE_IDENTITY_CONTRACT_VERSION
                or not isinstance(registry_identity, Mapping)
                or entry.get("target_document_id")
                != registry_identity.get("document_id")
                or entry.get("target_revision") != registry_identity.get("revision")
                or entry.get("target_source_hash")
                != registry_identity.get("source_hash")
                or actual != registry_identity.get(leaf)
            ):
                raise RevisionArtifactError(
                    "SOURCE_CELL_ROLE_MISMATCH: derived reference identity is not backed by target bytes"
                )
            derived_reference_targets.add(target)
        elif kind == "DERIVED_LOCATOR":
            source = entry.get("source")
            if not isinstance(source, dict):
                raise RevisionArtifactError("mapping source must be an object")
            if (
                source.get("document_id") != document["document_id"]
                or source.get("source_hash") != document["source_hash"]
                or source.get("source_id") != expected_source_id
            ):
                raise RevisionArtifactError(
                    "SOURCE_CELL_ROLE_MISMATCH: mapping source identity does not match parser evidence document"
                )
            _require_string(source.get("locator"), "mapping source locator")
            coordinates = source.get("coordinates")
            if (
                not isinstance(coordinates, dict)
                or set(coordinates) != {"row", "column"}
                or any(
                    isinstance(value, bool) or not isinstance(value, int) or value <= 0
                    for value in coordinates.values()
                )
            ):
                raise RevisionArtifactError("mapping source coordinates are invalid")
            if entry.get("derivation_contract") != DERIVED_LOCATOR_CONTRACT_VERSION:
                raise RevisionArtifactError("derived locator is not tied to its canonical source cell")
            row_prefix = target.rsplit(".", 1)[0] + "."
            derived_targets.append(target)
        else:
            sources = entry_sources(entry)
            for source in sources:
                if not isinstance(source, dict) or (
                    source.get("document_id") != document["document_id"]
                    or source.get("source_hash") != document["source_hash"]
                    or source.get("source_id") != expected_source_id
                ):
                    raise RevisionArtifactError(
                        "SOURCE_CELL_ROLE_MISMATCH: mapping source identity does not match parser evidence document"
                    )
                coordinates = source.get("coordinates")
                _require_string(source.get("locator"), "mapping source locator")
                if not isinstance(coordinates, dict):
                    raise RevisionArtifactError("mapping source coordinates are invalid")
                row_prefix = target.rsplit(".", 1)[0] + "."
                direct_rows_by_prefix.setdefault(row_prefix, set()).add(
                    coordinates["row"]
                )
        by_target[target] = entry

    expected_targets = set(expected_by_target)
    actual_targets = set(by_target) - derived_reference_targets
    if expected_targets != actual_targets:
        raise RevisionArtifactError(
            "ROW_CONSUMPTION_MISMATCH: actual mapping targets differ from the independent parser plan"
        )
    for target, expected in expected_by_target.items():
        actual_entry = by_target[target]
        if actual_entry == expected:
            continue
        expected_source_keys = {source_key(item) for item in entry_sources(expected)}
        actual_source_keys = {source_key(item) for item in entry_sources(actual_entry)}
        missing = expected_source_keys - actual_source_keys
        unexpected = actual_source_keys - expected_source_keys
        if missing and not unexpected:
            raise RevisionArtifactError(
                f"EXPECTED_CONTRIBUTOR_MISSING: mapping parser evidence omits contributors for {target}"
            )
        if unexpected or any(
            key not in parser_cells_by_source for key in actual_source_keys
        ):
            if target.endswith(".locator"):
                raise RevisionArtifactError(
                    "SOURCE_CELL_ROLE_MISMATCH: derived locator uses the wrong parser evidence cell/role"
                )
            raise RevisionArtifactError(
                f"SOURCE_CELL_ROLE_MISMATCH: mapping parser evidence uses the wrong cell/role for {target}"
            )
        if target.endswith(".locator"):
            raise RevisionArtifactError(
                "SOURCE_CELL_ROLE_MISMATCH: derived locator differs from its parser role plan"
            )
        raise RevisionArtifactError(
            f"SOURCE_CELL_ROLE_MISMATCH: mapping differs from independent parser evidence plan for {target}"
        )
    for target in derived_targets:
        entry = by_target[target]
        source = entry["source"]
        coordinates = source["coordinates"]
        row_prefix = target.rsplit(".", 1)[0] + "."
        direct_rows = direct_rows_by_prefix.get(row_prefix)
        if direct_rows != {coordinates["row"]}:
            raise RevisionArtifactError("derived locator crosses parser rows")
        anchor_field = (
            "failure_mode_id" if target.startswith("fields.risks[")
            else "characteristic_id"
        )
        anchor = by_target.get(f"{row_prefix}{anchor_field}")
        if (
            not isinstance(anchor, dict)
            or entry.get("anchor_target") != f"{row_prefix}{anchor_field}"
            or anchor.get("mapping_kind") != "DIRECT_CELL_VALUE"
            or anchor.get("source") != source
            or entry.get("value") != source["locator"]
        ):
            raise RevisionArtifactError(
                "derived locator is not tied to its canonical source cell"
            )
    leaves = _scalar_leaf_paths(document["fields"])
    if leaves != set(by_target):
        missing = sorted(leaves - set(by_target))
        extra = sorted(set(by_target) - leaves)
        raise RevisionArtifactError(
            f"mapping targets do not form a leaf bijection; missing={missing}, extra={extra}"
        )
    return sorted(mappings, key=lambda item: str(item["target"]))


def prepare_artifact_context(
    bundle: RevisionArtifactBundle,
    pre_case: Mapping[str, Any],
    operations: Any,
    *,
    reference_bundle: ControlledReferenceBundle | None = None,
    _baseline_reference_context: _ControlledReferenceContext | None = None,
) -> ArtifactContext:
    """Rebuild and close every touched document from immutable member bytes."""

    if type(bundle) is not RevisionArtifactBundle:
        raise RevisionArtifactError("actual replay requires an internal RevisionArtifactBundle")
    touched = validate_resolution_operation_paths(operations)
    try:
        manifest = strict_json_loads(bundle.canonical_manifest_bytes.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise RevisionArtifactError("bundle manifest is invalid") from error
    manifest, canonical_manifest_bytes = canonicalize_artifact_manifest(manifest)
    specs = {normalized_identity(item["document_id"]): item for item in manifest["documents"]}
    touched_by_key = {normalized_identity(item): item for item in touched}
    touched_keys = set(touched_by_key)
    if set(specs) != touched_keys:
        missing = sorted(touched_keys - set(specs))
        extra = sorted(set(specs) - touched_keys)
        raise RevisionArtifactError(
            f"artifact set must exactly cover all touched documents; missing={missing}, extra={extra}"
        )
    members: dict[str, ArtifactMemberBytes] = {}
    for member in bundle.members:
        key = normalized_identity(member.document_id)
        if key in members:
            raise RevisionArtifactError("normalized duplicate artifact bundle member")
        members[key] = member
    if set(members) != touched_keys:
        raise RevisionArtifactError("artifact bundle members differ from manifest/touched documents")
    pre_documents: dict[str, Mapping[str, Any]] = {}
    pre_normalized_ids: set[str] = set()
    raw_pre_documents = pre_case.get("documents", [])
    if not isinstance(raw_pre_documents, list):
        raise RevisionArtifactError("pre-case documents must be a list")
    for item in raw_pre_documents:
        if not isinstance(item, Mapping):
            raise RevisionArtifactError("pre-case document must be an object")
        document_id = item.get("document_id")
        if not isinstance(document_id, str) or not document_id.strip():
            raise RevisionArtifactError("pre-case document_id must be non-empty")
        normalized_document_id = normalized_identity(document_id)
        if normalized_document_id in pre_normalized_ids:
            raise RevisionArtifactError(
                "pre-case contains duplicate normalized document_id identities"
            )
        pre_normalized_ids.add(normalized_document_id)
        pre_documents[document_id] = item
    if reference_bundle is not None and _baseline_reference_context is not None:
        raise RevisionArtifactError(
            "artifact replay requires exactly one controlled-reference authority"
        )
    if _baseline_reference_context is not None:
        if not _is_sealed_reference_context(_baseline_reference_context):
            raise RevisionArtifactError(
                "artifact replay requires a sealed baseline reference context"
            )
        baseline_reference_context = _baseline_reference_context
    else:
        baseline_reference_context = (
            _prepare_controlled_reference_context(reference_bundle)
            if type(reference_bundle) is ControlledReferenceBundle
            else None
        )
    build_records: list[dict[str, Any]] = []
    for key in sorted(touched_keys):
        spec = specs[key]
        member = members[key]
        touched_document_id = touched_by_key[key]
        if spec["document_id"] != touched_document_id:
            raise RevisionArtifactError(
                "manifest document_id must exactly equal the touched document_id"
            )
        if member.document_id != touched_document_id:
            raise RevisionArtifactError(
                "artifact member document_id must exactly equal the touched document_id"
            )
        if member.source_id != spec["source_id"]:
            raise RevisionArtifactError("artifact member source_id differs from manifest")
        if member.filename != Path(spec["source_path"]).name:
            raise RevisionArtifactError("artifact member filename differs from manifest")
        old = pre_documents.get(touched_document_id)
        if old is None:
            raise RevisionArtifactError("artifact supersedes an unknown pre-case document")
        supersedes = spec["supersedes"]
        if supersedes["document_id"] != touched_document_id:
            raise RevisionArtifactError(
                "supersedes document_id must exactly equal the touched document_id"
            )
        expected_supersedes = {
            "document_id": old["document_id"],
            "revision": old["revision"],
            "source_hash": old["source_hash"],
        }
        if supersedes != expected_supersedes:
            raise RevisionArtifactError("artifact supersedes does not match exact pre-case document")
        build_spec = {name: value for name, value in spec.items() if name != "supersedes"}
        try:
            (
                document,
                logical_fingerprint,
                mapping_config,
                parser_evidence,
            ) = build_document_from_artifact_bytes(
                build_spec, member.raw_bytes, filename=member.filename
            )
        except (CaseBuilderError, IngestionError) as error:
            raise RevisionArtifactError(
                f"replacement artifact cannot be safely rebuilt: {error}"
            ) from error
        if document["revision"] == old["revision"]:
            raise RevisionArtifactError("replacement document must have a new revision")
        if document["source_hash"] == old["source_hash"]:
            raise RevisionArtifactError("replacement document must have a new source hash")
        declared_format = Path(member.filename).suffix[1:].upper()
        detected_format = document["source"]["format"]
        if declared_format != detected_format:
            raise RevisionArtifactError("declared and detected artifact formats differ")
        build_records.append(
            {
                "document": document,
                "spec": spec,
                "member": member,
                "logical_fingerprint": logical_fingerprint,
                "mapping_config": mapping_config,
                "parser_evidence": parser_evidence,
                "declared_format": declared_format,
                "detected_format": detected_format,
                "supersedes": supersedes,
                "index": ArtifactIndexEntry(
                document_id=document["document_id"],
                source_id=spec["source_id"],
                source_path=spec["source_path"],
                source_hash=document["source_hash"],
                size_bytes=len(member.raw_bytes),
                declared_format=declared_format,
                detected_format=detected_format,
                supersedes_document_id=supersedes["document_id"],
                supersedes_revision=supersedes["revision"],
                supersedes_source_hash=supersedes["source_hash"],
                ),
            }
        )
    reference_registry: dict[str, dict[str, Any]] = (
        baseline_reference_context.references()
        if _is_sealed_reference_context(baseline_reference_context)
        else {}
    )
    reference_witnesses: dict[str, _ReferenceWitness] = (
        baseline_reference_context.witness_by_type()
        if _is_sealed_reference_context(baseline_reference_context)
        else {}
    )
    reference_documents: dict[str, dict[str, Any]] = (
        {
            document["document_type"]: document
            for document in baseline_reference_context.documents()
        }
        if _is_sealed_reference_context(baseline_reference_context)
        else {}
    )
    for record in build_records:
        document = record["document"]
        document_type = document["document_type"]
        if document_type in {"SOP", "CONTROL_PLAN"}:
            reference_registry[document["document_type"]] = {
                "document_type": document["document_type"],
                "document_id": document["document_id"],
                "revision": document["revision"],
                "source_hash": document["source_hash"],
                "artifact_id": f"sha256:{document['source_hash']}",
            }
        if document_type in {"SOP", "CONTROL_PLAN", "INSPECTION_RECORD"}:
            reference_documents[document_type] = document
            reference_witnesses[document_type] = _ReferenceWitness(
                source_id=record["spec"]["source_id"],
                document_type=document_type,
                document_id=document["document_id"],
                revision=document["revision"],
                filename=record["member"].filename,
                relative_path=record["member"].filename,
                source_hash=document["source_hash"],
                raw_bytes=record["member"].raw_bytes,
            )
    rebuilt_inspection = next(
        (
            record["document"]
            for record in build_records
            if record["document"]["document_type"] == "INSPECTION_RECORD"
        ),
        None,
    )
    controlled_replacement = any(
        record["document"]["document_type"]
        in {"SOP", "CONTROL_PLAN", "INSPECTION_RECORD"}
        for record in build_records
    )
    inspection_for_context: dict[str, Any] | None = None
    if controlled_replacement:
        if not _is_sealed_reference_context(baseline_reference_context):
            raise RevisionArtifactError(
                "Inspection replacement requires raw controlled-reference witness bytes"
            )
        try:
            inspection_for_context = rebuilt_inspection
            if inspection_for_context is None:
                inspection_for_context = next(
                    document
                    for document in baseline_reference_context.documents()
                    if document.get("document_type") == "INSPECTION_RECORD"
                    and document.get("status") == "APPROVED"
                )
            else:
                _finalize_inspection_reference_with_registry(
                    inspection_for_context, reference_registry
                )
        except (ValueError, CaseBuilderError) as error:
            raise RevisionArtifactError(
                f"Inspection controlled references cannot be resolved: {error}"
            ) from error
    for record in build_records:
        document = record["document"]
        mappings = _validate_mapping_closure(
            document,
            expected_source_id=record["spec"]["source_id"],
            parser_evidence=record["parser_evidence"],
            reference_registry=(
                reference_registry
                if document["document_type"] == "INSPECTION_RECORD"
                else None
            ),
        )
        # The exact canonical list is both the digest input and the trusted
        # final document.  Keeping Builder order here would allow one approval
        # subject to produce multiple resolved case identities.
        document["mapping_provenance"] = mappings
    if controlled_replacement:
        try:
            resolved_reference_context = _seal_controlled_reference_context_from_registry(
                inspection_for_context,
                reference_registry,
                reference_witnesses,
                {
                    role: reference_documents[role]
                    for role in ("SOP", "CONTROL_PLAN")
                },
            )
        except (ValueError, CaseBuilderError) as error:
            raise RevisionArtifactError(
                f"Inspection controlled references cannot be resolved: {error}"
            ) from error
    else:
        resolved_reference_context = baseline_reference_context
    digest_documents: list[dict[str, Any]] = []
    built_documents: list[dict[str, Any]] = []
    index: list[ArtifactIndexEntry] = []
    for record in build_records:
        document = record["document"]
        spec = record["spec"]
        member = record["member"]
        mappings = document["mapping_provenance"]
        fact_names = [
            "document_id",
            "document_type",
            "revision",
            "status",
            "owner",
            "revision_date",
            "fields",
        ]
        if "reference_contract_version" in document:
            fact_names.append("reference_contract_version")
        facts = {name: document[name] for name in fact_names}
        digest_documents.append(
            {
                "document_id": document["document_id"],
                "source_id": spec["source_id"],
                "source_path": spec["source_path"],
                "member_filename": member.filename,
                "metadata_and_fields_digest": canonical_hash(facts),
                "raw_source_hash": document["source_hash"],
                "logical_table_fingerprint": f"sha256:{record['logical_fingerprint']}",
                "mapping_config": record["mapping_config"],
                "mapping_digest": canonical_hash(mappings),
                "supersedes": record["supersedes"],
                "declared_format": record["declared_format"],
                "detected_format": record["detected_format"],
            }
        )
        built_documents.append(document)
        index.append(record["index"])
    digest_documents.sort(key=lambda item: artifact_document_sort_key(item["document_id"]))
    digest_subject = {
        "artifact_contract_version": ARTIFACT_CONTRACT_VERSION,
        "case_schema_version": CASE_SCHEMA_VERSION,
        "parser_contract_version": INGESTION_POLICY_VERSION,
        "mapping_contract_version": MAPPING_CONTRACT_VERSION,
        "security_root_policy_version": ARTIFACT_SECURITY_ROOT_POLICY_VERSION,
        "replacement_set_id": manifest["replacement_set_id"],
        "reference_contract_version": (
            resolved_reference_context.contract_version
            if resolved_reference_context is not None
            else None
        ),
        "controlled_reference_set_hash": (
            resolved_reference_context.reference_set_hash
            if resolved_reference_context is not None
            else None
        ),
        "controlled_reference_source_set_hash": (
            baseline_reference_context.reference_set_hash
            if baseline_reference_context is not None
            else None
        ),
        "documents": digest_documents,
    }
    artifact_set_hash = hashlib.sha256(_DOMAIN + _canonical_bytes(digest_subject)).hexdigest()
    final_documents: list[dict[str, Any]] = []
    for document, entry in zip(built_documents, index, strict=True):
        document["revision_artifact"] = {
            "contract_version": ARTIFACT_CONTRACT_VERSION,
            "artifact_id": f"sha256:{entry.source_hash}",
            "replacement_set_id": manifest["replacement_set_id"],
            "artifact_set_hash": artifact_set_hash,
            "case_schema_version": CASE_SCHEMA_VERSION,
            "parser_contract_version": INGESTION_POLICY_VERSION,
            "mapping_contract_version": MAPPING_CONTRACT_VERSION,
            "security_root_policy_version": ARTIFACT_SECURITY_ROOT_POLICY_VERSION,
            "supersedes": {
                "document_id": entry.supersedes_document_id,
                "revision": entry.supersedes_revision,
                "source_hash": entry.supersedes_source_hash,
            },
            "attestation": "DESCRIPTIVE_ONLY_REBUILT_FROM_CAPTURED_BYTES",
        }
        final_documents.append(document)
    final_documents.sort(key=lambda item: normalized_identity(item["document_id"]))
    index.sort(key=lambda item: normalized_identity(item.document_id))
    return ArtifactContext(
        replacement_set_id=manifest["replacement_set_id"],
        artifact_set_hash=artifact_set_hash,
        documents_json=_canonical_bytes(final_documents),
        canonical_manifest_bytes=canonical_manifest_bytes,
        members=tuple(
            sorted(
                bundle.members,
                key=lambda item: artifact_document_sort_key(item.document_id),
            )
        ),
        artifact_index=tuple(index),
        reference_context=resolved_reference_context,
        source_reference_set_hash=(
            baseline_reference_context.reference_set_hash
            if baseline_reference_context is not None
            else None
        ),
        _seal=_CONTEXT_SEAL,
    )
