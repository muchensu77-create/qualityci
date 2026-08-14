"""Manifest-driven bridge from controlled evidence tables to a QualityCI case.

This module deliberately does not infer business semantics from arbitrary Office
documents.  A manifest names every accepted source column and the builder only
consumes table cells with stable row/column locators produced by
``ingest_document``.  Missing or ambiguous mappings fail closed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .controlled_references import (
    DERIVED_REFERENCE_IDENTITY_CONTRACT_VERSION,
    _ControlledReferenceContext,
    _ReferenceWitness,
    _seal_controlled_reference_context,
)
from .ingestion import ingest_document_bytes, read_source_bytes
from .loader import (
    CASE_SCHEMA_VERSION,
    CONTROLLED_REFERENCE_CONTRACT_VERSION,
    LOWERCASE_SHA256,
    load_json,
    relationship_key,
    validate_case,
)


MANIFEST_VERSION = "qualityci-case-builder-0.4"
MAPPING_CONTRACT_VERSION = "qualityci-explicit-mapping-0.5"
DERIVED_LOCATOR_CONTRACT_VERSION = "qualityci-derived-locator-0.1"
IDENTICAL_VALUE_AGGREGATION_CONTRACT_VERSION = "qualityci-identical-value-aggregate-0.1"
MAPPING_VALUE_CONVERSION_CONTRACT_VERSION = "qualityci-mapping-value-conversion-0.1"
PARSER_CONSUMPTION_PLAN_VERSION = "qualityci-parser-consumption-plan-0.1"
DOCUMENT_TYPES = (
    "PROCESS_FLOW",
    "PFMEA",
    "CONTROL_PLAN",
    "SOP",
    "INSPECTION_RECORD",
)

_DOCUMENT_METADATA_KEYS = (
    "document_id",
    "document_type",
    "revision",
    "status",
    "owner",
    "revision_date",
)
_DOCUMENT_SPEC_KEYS = {
    "source_id",
    "source_path",
    *_DOCUMENT_METADATA_KEYS,
    "columns",
    "header_row",
    "table_selector",
}
_ROOT_KEYS = {"manifest_version", "case", "event", "documents"}
_CASE_KEYS = {"case_id", "title", "synthetic_for_competition", "source_provenance"}
_EVENT_KEYS = {
    "event_id",
    "event_type",
    "revision",
    "approved_at",
    "risk_level",
    "affected_process_steps",
    "affected_characteristics",
    "affected_links",
    "change_summary",
    "validation_evidence",
    "validation_plan",
    "approvals",
    "provenance",
}
_REQUIRED_COLUMNS = {
    "PROCESS_FLOW": {"process_step_id"},
    "PFMEA": {
        "process_step_id",
        "failure_mode_id",
        "characteristic_id",
        "special_characteristic",
    },
    "CONTROL_PLAN": {
        "process_step_id",
        "control_id",
        "characteristic_id",
        "target",
        "minimum",
        "maximum",
        "unit",
        "control_method",
        "frequency",
        "reaction_plan",
    },
    "SOP": {
        "process_step_id",
        "characteristic_id",
        "target",
        "minimum",
        "maximum",
        "unit",
    },
    "INSPECTION_RECORD": {
        "process_step_id",
        "characteristic_id",
        "target",
        "minimum",
        "maximum",
        "unit",
        "sop_document_id",
        "sop_revision",
        "control_plan_document_id",
        "control_plan_revision",
    },
}
_OPTIONAL_COLUMNS = {
    "PROCESS_FLOW": set(),
    "PFMEA": {"effect"},
    "CONTROL_PLAN": set(),
    "SOP": set(),
    "INSPECTION_RECORD": set(),
}


class CaseBuilderError(ValueError):
    """Base class for an input pack that cannot be mapped deterministically."""


class ManifestError(CaseBuilderError):
    """Raised when the manifest contract is malformed or inconsistent."""


class MissingColumnError(CaseBuilderError):
    """Raised when a manifest-named source column is absent."""


class DuplicateIdentifierError(CaseBuilderError):
    """Raised when an entity identifier occurs more than once."""


class AmbiguousMappingError(CaseBuilderError):
    """Raised when a source value has more than one possible mapping."""


@dataclass(frozen=True)
class _Cell:
    row: int
    column: int
    text: str
    locator: str
    source_hash: str
    source_kind: str


@dataclass(frozen=True)
class _MappedRow:
    row_number: int
    cells: dict[str, _Cell]


@dataclass(frozen=True)
class _MappedTable:
    rows: tuple[_MappedRow, ...]
    source_headers: dict[str, str]


@dataclass(frozen=True)
class _SelectedTable:
    cells: tuple[Mapping[str, Any], ...]
    canonical_selector: tuple[str, str | int]
    logical_fingerprint: str


@dataclass(frozen=True)
class ArtifactBuildEvidence:
    """Immutable parser cells and an independently derived mapping-role plan."""

    parser_cells_json: bytes
    expected_mappings_json: bytes
    consumption_plan_version: str = PARSER_CONSUMPTION_PLAN_VERSION

    @staticmethod
    def _records(raw: bytes, label: str) -> tuple[dict[str, Any], ...]:
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise CaseBuilderError(f"internal parser {label} is invalid")
        return tuple(value)

    def parser_cells(self) -> tuple[dict[str, Any], ...]:
        return self._records(self.parser_cells_json, "cell evidence")

    def expected_mappings(self) -> tuple[dict[str, Any], ...]:
        return self._records(self.expected_mappings_json, "mapping-role plan")


class _ProvenanceList(list[dict[str, Any]]):
    """Target-indexed mappings that retain every identical aggregate contributor."""

    def __init__(self) -> None:
        super().__init__()
        self.by_target: dict[str, dict[str, Any]] = {}
        self.source_keys_by_target: dict[str, set[str]] = {}

    def append(self, entry: dict[str, Any]) -> None:
        target = entry.get("target")
        existing = self.by_target.get(str(target))
        if existing is not None:
            if (
                entry.get("mapping_kind") == "DIRECT_CELL_VALUE"
                and existing.get("value") == entry.get("value")
                and existing.get("mapping_kind")
                in {"DIRECT_CELL_VALUE", "AGGREGATED_IDENTICAL_VALUES"}
            ):
                source = _copy_evidence_source(entry["source"])
                source_key = json.dumps(
                    source,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if existing["mapping_kind"] == "DIRECT_CELL_VALUE":
                    sources = [
                        _copy_evidence_source(existing.pop("source")),
                        source,
                    ]
                    existing["mapping_kind"] = "AGGREGATED_IDENTICAL_VALUES"
                    existing["aggregation_contract"] = (
                        IDENTICAL_VALUE_AGGREGATION_CONTRACT_VERSION
                    )
                    existing["conversion_contract"] = (
                        MAPPING_VALUE_CONVERSION_CONTRACT_VERSION
                    )
                    existing["sources"] = sources
                    self.source_keys_by_target[str(target)] = {
                        json.dumps(
                            item,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        for item in sources
                    }
                else:
                    if source_key in self.source_keys_by_target[str(target)]:
                        raise AmbiguousMappingError(
                            f"aggregate mapping repeats one parser cell: {target}"
                        )
                    existing["sources"].append(source)
                    self.source_keys_by_target[str(target)].add(source_key)
                return
            raise AmbiguousMappingError(
                f"mapping target has conflicting source values: {target}"
            )
        super().append(entry)
        self.by_target[str(target)] = entry

    def finalize_aggregates(self) -> None:
        for entry in self:
            if entry.get("mapping_kind") == "AGGREGATED_IDENTICAL_VALUES":
                entry["sources"].sort(
                    key=lambda item: (
                        int(item["coordinates"]["row"]),
                        int(item["coordinates"]["column"]),
                        str(item["locator"]),
                    )
                )

    def __deepcopy__(self, memo: dict[int, Any]) -> list[dict[str, Any]]:
        return [copy.deepcopy(item, memo) for item in list.__iter__(self)]


def _build_case_from_ingested_documents(
    manifest: Mapping[str, Any],
    evidence_documents: Mapping[str, Mapping[str, Any]],
    reference_witnesses: Mapping[str, _ReferenceWitness],
) -> tuple[dict[str, Any], _ControlledReferenceContext]:
    """Internal bridge for evidence just produced by ``ingest_document``.

    This is deliberately private: a caller-supplied Mapping cannot prove that
    its evidence still matches the source bytes named by its hash.  The public
    path-oriented entry point re-ingests each source immediately before calling
    this helper.
    """

    normalized_manifest, document_specs = _validate_manifest(manifest)
    expected_sources = {spec["source_id"] for spec in document_specs}
    actual_sources = set(evidence_documents)
    if actual_sources != expected_sources:
        missing = sorted(expected_sources - actual_sources)
        unexpected = sorted(actual_sources - expected_sources)
        raise ManifestError(
            f"evidence source set differs from manifest; missing={missing}, "
            f"unexpected={unexpected}"
        )

    selected_sources: set[tuple[str, tuple[str, str | int]]] = set()
    selected_table_fingerprints: set[str] = set()
    selected_tables: list[_SelectedTable] = []
    documents: list[dict[str, Any]] = []
    for spec in document_specs:
        source = evidence_documents[spec["source_id"]]
        _validate_evidence_document(spec, source)
        fields = source["fields"]
        selected_table = _select_table_cells(
            fields["structure"]["format"],
            fields["evidence"],
            spec.get("table_selector"),
            spec["source_id"],
            spec["header_row"],
        )
        source_key = (source["source_hash"], selected_table.canonical_selector)
        if source_key in selected_sources:
            raise AmbiguousMappingError(
                "each logical document must use a distinct source hash + selected table"
            )
        if selected_table.logical_fingerprint in selected_table_fingerprints:
            raise AmbiguousMappingError(
                "each logical document must use a distinct normalized table content"
            )
        selected_sources.add(source_key)
        selected_table_fingerprints.add(selected_table.logical_fingerprint)
        selected_tables.append(selected_table)
        documents.append(_build_document(spec, source, selected_table))
    _finalize_controlled_references(documents)
    reference_context = _seal_controlled_reference_context(
        documents, reference_witnesses
    )
    case = copy.deepcopy(normalized_manifest["case"])
    case["schema_version"] = CASE_SCHEMA_VERSION
    case["event"] = copy.deepcopy(normalized_manifest["event"])
    case["documents"] = documents
    if (
        "validation_plan" not in case["event"]
        and isinstance(case["event"].get("validation_evidence"), list)
    ):
        # A document pack can still carry the pre-0.4 descriptive evidence
        # list.  Preserve it only as an explicit, non-inferential migration;
        # it cannot create a sealed validation context or R006 PASS.
        case["validation_migration"] = {
            "source_schema_version": "qualityci-case-0.3",
            "target_schema_version": CASE_SCHEMA_VERSION,
            "status": "LEGACY_UNATTESTED",
            "inference_scope": "NONE",
            "evidence_ids": [
                item.get("evidence_id", "")
                for item in case["event"]["validation_evidence"]
                if isinstance(item, dict)
            ],
        }
    case["builder_provenance"] = {
        "manifest_version": MANIFEST_VERSION,
        "mode": "EXPLICIT_TABLE_COLUMN_MAPPING",
        "sources": [
            {
                "source_id": spec["source_id"],
                "source_path": spec["source_path"],
                "document_id": spec["document_id"],
                "source_hash": document["source_hash"],
                "canonical_table_selector": {
                    "format": selected_table.canonical_selector[0],
                    "value": selected_table.canonical_selector[1],
                },
                "logical_table_fingerprint": (
                    f"sha256:{selected_table.logical_fingerprint}"
                ),
                "mapped_value_count": len(document["mapping_provenance"]),
            }
            for spec, document, selected_table in zip(
                document_specs, documents, selected_tables, strict=True
            )
        ],
    }
    validate_case(case)
    return case, reference_context


def _build_case_and_reference_context_from_pack(
    manifest_path: str | Path,
) -> tuple[dict[str, Any], _ControlledReferenceContext]:
    path = Path(manifest_path).resolve(strict=True)
    manifest = load_json(path)
    _, document_specs = _validate_manifest(manifest)
    evidence_documents: dict[str, dict[str, Any]] = {}
    reference_witnesses: dict[str, _ReferenceWitness] = {}
    for spec in document_specs:
        relative_source = Path(spec["source_path"])
        if relative_source.is_absolute() or ".." in relative_source.parts:
            raise ManifestError(
                f"source_path must stay relative to the manifest directory: "
                f"{spec['source_path']!r}"
            )
        if relative_source.suffix.casefold() not in {".csv", ".xlsx", ".docx"}:
            raise ManifestError(
                "build_case_from_pack only accepts controlled CSV/XLSX/DOCX sources"
            )
        filename, display_path, raw_bytes = read_source_bytes(
            path.parent / relative_source,
            root_dir=path.parent,
        )
        source = ingest_document_bytes(
            raw_bytes,
            filename=filename,
            relative_path=display_path,
            document_id=spec["document_id"],
            document_type=spec["document_type"],
            revision=spec["revision"],
            status=spec["status"],
            owner=spec["owner"],
            revision_date=spec["revision_date"],
        )
        evidence_documents[spec["source_id"]] = source
        if spec["document_type"] in {
            "SOP",
            "CONTROL_PLAN",
            "INSPECTION_RECORD",
        }:
            reference_witnesses[spec["document_type"]] = _ReferenceWitness(
                source_id=spec["source_id"],
                document_type=spec["document_type"],
                document_id=spec["document_id"],
                revision=spec["revision"],
                filename=filename,
                relative_path=display_path,
                source_hash=source["source_hash"],
                raw_bytes=raw_bytes,
            )
    return _build_case_from_ingested_documents(
        manifest, evidence_documents, reference_witnesses
    )


def _build_case_and_reference_context_from_source_bundle(
    bundle: object,
) -> tuple[dict[str, Any], _ControlledReferenceContext]:
    """Build from one already-captured A08 source bundle without reopening files.

    The import is intentionally local: :mod:`case_source_assurance` owns the
    raw carrier and imports this module's deterministic mapping implementation.
    Neither a caller Mapping nor a serialized source identity is accepted here.
    """

    from .case_source_assurance import (
        CaseSourceBundle,
        CaseSourceMember,
        _canonical_json_text,
    )
    from .loader import strict_json_loads

    if type(bundle) is not CaseSourceBundle:
        raise TypeError("case source build requires an exact CaseSourceBundle")
    try:
        manifest_text = bundle.manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ManifestError("case source manifest must be UTF-8 JSON") from error
    manifest = strict_json_loads(manifest_text)
    if type(manifest) is not dict:
        raise ManifestError("case source manifest root must be an object")
    _normalized_manifest, document_specs = _validate_manifest(manifest)

    members_by_type: dict[str, CaseSourceMember] = {}
    for member in bundle.members:
        if type(member) is not CaseSourceMember:
            raise TypeError("case source members must use the exact member type")
        if member.document_type in members_by_type:
            raise ManifestError("case source bundle repeats a document_type")
        members_by_type[member.document_type] = member
    if set(members_by_type) != set(DOCUMENT_TYPES):
        raise ManifestError(
            "case source bundle must contain exactly the five document roles"
        )

    evidence_documents: dict[str, dict[str, Any]] = {}
    reference_witnesses: dict[str, _ReferenceWitness] = {}
    specs_by_type = {spec["document_type"]: spec for spec in document_specs}
    for document_type in DOCUMENT_TYPES:
        spec = specs_by_type[document_type]
        member = members_by_type[document_type]
        expected_selector = (
            None
            if spec.get("table_selector") is None
            else _canonical_json_text(spec["table_selector"])
        )
        if (
            member.source_id != spec["source_id"]
            or member.source_path != spec["source_path"]
            or member.declared_table_selector_json != expected_selector
        ):
            raise ManifestError(
                f"case source member identity differs from manifest: {document_type}"
            )
        expected_kind = Path(spec["source_path"]).suffix.removeprefix(".").upper()
        if member.source_kind != expected_kind:
            raise ManifestError(
                f"case source member kind differs from manifest: {document_type}"
            )

        filename = Path(member.source_path).name
        source = ingest_document_bytes(
            member.raw_bytes,
            filename=filename,
            relative_path=member.source_path,
            document_id=spec["document_id"],
            document_type=spec["document_type"],
            revision=spec["revision"],
            status=spec["status"],
            owner=spec["owner"],
            revision_date=spec["revision_date"],
        )
        evidence_documents[spec["source_id"]] = source
        if document_type in {"SOP", "CONTROL_PLAN", "INSPECTION_RECORD"}:
            reference_witnesses[document_type] = _ReferenceWitness(
                source_id=spec["source_id"],
                document_type=document_type,
                document_id=spec["document_id"],
                revision=spec["revision"],
                filename=filename,
                relative_path=member.source_path,
                source_hash=source["source_hash"],
                raw_bytes=member.raw_bytes,
            )
    return _build_case_from_ingested_documents(
        manifest, evidence_documents, reference_witnesses
    )


def build_case_from_pack(manifest_path: str | Path) -> dict[str, Any]:
    """Build serializable case facts; serialized JSON remains untrusted for R005 PASS."""

    case, _reference_context = _build_case_and_reference_context_from_pack(manifest_path)
    return case


def build_case_from_csv_pack(manifest_path: str | Path) -> dict[str, Any]:
    """Backward-compatible name for the path-bound pack builder.

    The v0.1 name is retained for callers, while the implementation now safely
    accepts controlled CSV/XLSX/DOCX paths declared by the manifest.
    """

    return build_case_from_pack(manifest_path)


def build_document_from_artifact_bytes(
    spec: Mapping[str, Any],
    raw_bytes: bytes,
    *,
    filename: str,
) -> tuple[dict[str, Any], str, dict[str, Any], ArtifactBuildEvidence]:
    """Build one complete document from an already captured immutable buffer."""

    normalized_spec = _validate_document_spec(dict(spec), 0)
    if Path(filename).suffix.casefold() not in {".csv", ".xlsx", ".docx"}:
        raise ManifestError(
            "revision artifact mapping only accepts controlled CSV/XLSX/DOCX sources"
        )
    source = ingest_document_bytes(
        raw_bytes,
        filename=filename,
        relative_path=filename,
        document_id=normalized_spec["document_id"],
        document_type=normalized_spec["document_type"],
        revision=normalized_spec["revision"],
        status=normalized_spec["status"],
        owner=normalized_spec["owner"],
        revision_date=normalized_spec["revision_date"],
    )
    fields = source["fields"]
    selected_table = _select_table_cells(
        fields["structure"]["format"],
        fields["evidence"],
        normalized_spec.get("table_selector"),
        normalized_spec["source_id"],
        normalized_spec["header_row"],
    )
    _validate_evidence_document(normalized_spec, source)
    table = _map_table(normalized_spec, source, selected_table)
    evidence = _build_artifact_evidence(normalized_spec, table)
    document = _build_document_from_mapped_table(normalized_spec, source, table)
    mapping_config = {
        "source_id": normalized_spec["source_id"],
        "document_id": normalized_spec["document_id"],
        "columns": copy.deepcopy(normalized_spec["columns"]),
        "header_row": normalized_spec["header_row"],
        "table_selector": copy.deepcopy(normalized_spec.get("table_selector")),
        "canonical_table_selector": {
            "format": selected_table.canonical_selector[0],
            "value": selected_table.canonical_selector[1],
        },
        "consumption_plan_version": PARSER_CONSUMPTION_PLAN_VERSION,
    }
    return document, selected_table.logical_fingerprint, mapping_config, evidence


def _validate_manifest(
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(manifest, Mapping):
        raise ManifestError("manifest must be an object")
    unknown_root = set(manifest) - _ROOT_KEYS
    if unknown_root:
        raise ManifestError(f"manifest has unsupported keys: {sorted(unknown_root)}")
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        raise ManifestError(
            f"manifest_version must be {MANIFEST_VERSION!r}"
        )

    case = _require_mapping(manifest.get("case"), "case")
    unknown_case = set(case) - _CASE_KEYS
    if unknown_case:
        raise ManifestError(f"case manifest has unsupported keys: {sorted(unknown_case)}")
    _require_nonempty_string(case.get("case_id"), "case.case_id")
    if "title" in case and not isinstance(case["title"], str):
        raise ManifestError("case.title must be a string")
    source_provenance = case.get("source_provenance")
    if source_provenance is not None:
        if not isinstance(source_provenance, list) or any(
            not isinstance(item, Mapping) for item in source_provenance
        ):
            raise ManifestError("case.source_provenance must be a list of objects")
        for index, item in enumerate(source_provenance):
            if set(item) != {"type", "url", "use"}:
                raise ManifestError(
                    f"case.source_provenance[{index}] must contain exactly type, url, use"
                )
            for key in ("type", "url", "use"):
                _require_nonempty_string(
                    item[key], f"case.source_provenance[{index}].{key}"
                )
            parsed = urlparse(item["url"])
            if not parsed.scheme or (parsed.scheme in {"http", "https"} and not parsed.netloc):
                raise ManifestError(
                    f"case.source_provenance[{index}].url must be an absolute URI"
                )
    if case.get("synthetic_for_competition") is not True:
        raise ManifestError("case.synthetic_for_competition must be true")

    event = _require_mapping(manifest.get("event"), "event")
    unknown_event = set(event) - _EVENT_KEYS
    if unknown_event:
        raise ManifestError(f"event manifest has unsupported keys: {sorted(unknown_event)}")
    for key in (
        "event_id",
        "event_type",
        "revision",
        "risk_level",
        "affected_process_steps",
        "affected_characteristics",
        "affected_links",
    ):
        if key not in event:
            raise ManifestError(f"event is missing required key: {key}")
    if "provenance" in event and not isinstance(event["provenance"], Mapping):
        raise ManifestError("event.provenance must be an object")
    _reject_duplicate_strings(
        event["affected_process_steps"], "event.affected_process_steps"
    )
    _reject_duplicate_strings(
        event["affected_characteristics"], "event.affected_characteristics"
    )
    if not isinstance(event["affected_links"], list) or any(
        not isinstance(item, Mapping) for item in event["affected_links"]
    ):
        raise ManifestError("event.affected_links must be a list of objects")
    link_keys: set[tuple[str, str]] = set()
    for index, link in enumerate(event["affected_links"]):
        if set(link) != {"process_step_id", "characteristic_id"}:
            raise ManifestError(
                f"event.affected_links[{index}] must contain exactly "
                "process_step_id and characteristic_id"
            )
        _require_nonempty_string(
            link["process_step_id"],
            f"event.affected_links[{index}].process_step_id",
        )
        _require_nonempty_string(
            link["characteristic_id"],
            f"event.affected_links[{index}].characteristic_id",
        )
        key = relationship_key(link["process_step_id"], link["characteristic_id"])
        if key in link_keys:
            raise DuplicateIdentifierError(
                "duplicate normalized event.affected_links pair"
            )
        link_keys.add(key)

    raw_documents = manifest.get("documents")
    if not isinstance(raw_documents, list) or any(
        not isinstance(item, Mapping) for item in raw_documents
    ):
        raise ManifestError("documents must be a list of objects")
    specs = [_validate_document_spec(dict(item), index) for index, item in enumerate(raw_documents)]
    source_ids = [spec["source_id"] for spec in specs]
    source_paths = [spec["source_path"] for spec in specs]
    document_ids = [spec["document_id"] for spec in specs]
    document_types = [spec["document_type"] for spec in specs]
    _reject_duplicates(source_ids, "source_id")
    _reject_duplicates(source_paths, "source_path")
    _reject_duplicates(document_ids, "document_id")
    _reject_duplicates(document_types, "document_type")
    if set(document_types) != set(DOCUMENT_TYPES):
        raise ManifestError(
            "manifest must contain exactly one source for each required document_type"
        )

    normalized = {
        "manifest_version": manifest["manifest_version"],
        "case": copy.deepcopy(dict(case)),
        "event": copy.deepcopy(dict(event)),
        "documents": copy.deepcopy(specs),
    }
    return normalized, specs


def _validate_document_spec(spec: dict[str, Any], index: int) -> dict[str, Any]:
    unknown = set(spec) - _DOCUMENT_SPEC_KEYS
    if unknown:
        raise ManifestError(
            f"documents[{index}] has unsupported keys: {sorted(unknown)}"
        )
    for key in ("source_id", "source_path", *_DOCUMENT_METADATA_KEYS):
        _require_nonempty_string(spec.get(key), f"documents[{index}].{key}")
    document_type = spec["document_type"]
    if document_type not in DOCUMENT_TYPES:
        raise ManifestError(f"unsupported document_type: {document_type!r}")
    columns = _require_mapping(spec.get("columns"), f"documents[{index}].columns")
    if any(
        not isinstance(key, str)
        or not key.strip()
        or not isinstance(value, str)
        or not value.strip()
        for key, value in columns.items()
    ):
        raise ManifestError("column mappings must map non-empty strings to non-empty strings")
    required = _REQUIRED_COLUMNS[document_type]
    allowed = required | _OPTIONAL_COLUMNS[document_type]
    missing = sorted(required - set(columns))
    unknown_columns = sorted(set(columns) - allowed)
    if missing:
        raise ManifestError(
            f"{document_type} column mapping is missing canonical fields: {missing}"
        )
    if unknown_columns:
        raise ManifestError(
            f"{document_type} column mapping has unsupported canonical fields: "
            f"{unknown_columns}"
        )
    normalized_source_columns = [_normalize_header(value) for value in columns.values()]
    if len(normalized_source_columns) != len(set(normalized_source_columns)):
        raise AmbiguousMappingError(
            f"{document_type} maps more than one canonical field to the same source column"
        )
    header_row = spec.get("header_row", 1)
    if isinstance(header_row, bool) or not isinstance(header_row, int) or header_row <= 0:
        raise ManifestError(f"documents[{index}].header_row must be a positive integer")
    table_selector = spec.get("table_selector")
    if table_selector is not None and not isinstance(table_selector, Mapping):
        raise ManifestError(f"documents[{index}].table_selector must be an object")
    spec["columns"] = dict(columns)
    spec["header_row"] = header_row
    if table_selector is not None:
        spec["table_selector"] = dict(table_selector)
    return spec


def _build_document(
    spec: Mapping[str, Any],
    source: Mapping[str, Any],
    selected_table: _SelectedTable,
) -> dict[str, Any]:
    _validate_evidence_document(spec, source)
    table = _map_table(spec, source, selected_table)
    return _build_document_from_mapped_table(spec, source, table)


def _build_document_from_mapped_table(
    spec: Mapping[str, Any], source: Mapping[str, Any], table: _MappedTable
) -> dict[str, Any]:
    fields, provenance = _build_fields(spec, table)
    if isinstance(provenance, _ProvenanceList):
        provenance.finalize_aggregates()
    _record_derived_locators(fields, provenance)
    document = {
        key: spec[key]
        for key in _DOCUMENT_METADATA_KEYS
    }
    document["source_hash"] = source["source_hash"]
    document["source"] = copy.deepcopy(source["source"])
    document["fields"] = fields
    document["mapping_provenance"] = provenance
    return document


def _validate_evidence_document(
    spec: Mapping[str, Any], source: Mapping[str, Any]
) -> None:
    if not isinstance(source, Mapping):
        raise CaseBuilderError(f"{spec['source_id']} evidence document must be an object")
    for key in _DOCUMENT_METADATA_KEYS:
        if source.get(key) != spec[key]:
            raise ManifestError(
                f"{spec['source_id']} metadata mismatch for {key}: "
                f"manifest={spec[key]!r}, evidence={source.get(key)!r}"
            )
    source_hash = source.get("source_hash")
    if (
        not isinstance(source_hash, str)
        or len(source_hash) != 64
        or any(character not in "0123456789abcdef" for character in source_hash)
    ):
        raise CaseBuilderError(f"{spec['source_id']} has no valid SHA-256 source_hash")
    source_metadata = source.get("source")
    if (
        not isinstance(source_metadata, Mapping)
        or source_metadata.get("read_only") is not True
        or source_metadata.get("content_executed") is not False
    ):
        raise CaseBuilderError(
            f"{spec['source_id']} is not a read-only, non-executed ingestion result"
        )
    fields = source.get("fields")
    if not isinstance(fields, Mapping):
        raise CaseBuilderError(f"{spec['source_id']} fields must be an object")
    structure = fields.get("structure")
    if not isinstance(structure, Mapping) or structure.get("format") not in {
        "CSV",
        "XLSX",
        "DOCX",
    }:
        raise CaseBuilderError(
            f"{spec['source_id']} must contain a supported structured table"
        )
    evidence = fields.get("evidence")
    if not isinstance(evidence, list) or any(
        not isinstance(item, Mapping) for item in evidence
    ):
        raise CaseBuilderError(f"{spec['source_id']} evidence must be a list of objects")


def _map_table(
    spec: Mapping[str, Any],
    source: Mapping[str, Any],
    selected_table: _SelectedTable,
) -> _MappedTable:
    source_format = source["fields"]["structure"]["format"]
    cells_by_coordinate: dict[tuple[int, int], _Cell] = {}
    seen_locators: set[str] = set()
    for item in selected_table.cells:
        if (
            item.get("formula") is not None
            or (
                item.get("potential_spreadsheet_formula") is True
                and not (
                    source_format == "CSV"
                    and _is_finite_numeric_literal(item.get("text"))
                )
            )
        ):
            raise CaseBuilderError(
                f"{spec['source_id']} contains a mapped table formula at "
                f"{item.get('locator', '<unknown>')}; formula cache values are not evidence"
            )
        coordinates = item.get("coordinates")
        if not isinstance(coordinates, Mapping):
            raise CaseBuilderError(
                f"{spec['source_id']} evidence lacks structured coordinates"
            )
        row = coordinates.get("row")
        column = coordinates.get("column")
        if (
            isinstance(row, bool)
            or not isinstance(row, int)
            or row <= 0
            or isinstance(column, bool)
            or not isinstance(column, int)
            or column <= 0
        ):
            raise CaseBuilderError(
                f"{spec['source_id']} evidence has invalid row/column coordinates"
            )
        locator = item.get("locator")
        text = item.get("text")
        item_hash = item.get("source_hash")
        if not isinstance(locator, str) or not locator.strip() or not isinstance(text, str):
            raise CaseBuilderError(
                f"{spec['source_id']} evidence has invalid locator or text"
            )
        if item_hash != source["source_hash"]:
            raise CaseBuilderError(
                f"{spec['source_id']} evidence source_hash does not match its document"
            )
        coordinate = (row, column)
        if coordinate in cells_by_coordinate or locator in seen_locators:
            raise AmbiguousMappingError(
                f"{spec['source_id']} contains duplicate table coordinates or locators"
            )
        seen_locators.add(locator)
        cells_by_coordinate[coordinate] = _Cell(
            row=row,
            column=column,
            text=text,
            locator=locator,
            source_hash=item_hash,
            source_kind=str(item.get("kind", "CELL")),
        )

    header_row = spec["header_row"]
    headers: dict[str, list[_Cell]] = {}
    for (row, _), cell in cells_by_coordinate.items():
        if row != header_row or not cell.text.strip():
            continue
        headers.setdefault(_normalize_header(cell.text), []).append(cell)
    duplicate_headers = {
        name: matches for name, matches in headers.items() if len(matches) != 1
    }
    if duplicate_headers:
        details = {
            name: [cell.locator for cell in matches]
            for name, matches in duplicate_headers.items()
        }
        raise AmbiguousMappingError(
            f"{spec['source_id']} has normalized duplicate headers: {details}"
        )

    canonical_columns: dict[str, int] = {}
    source_headers: dict[str, str] = {}
    for canonical_name, requested_header in spec["columns"].items():
        matches = headers.get(_normalize_header(requested_header), [])
        if not matches:
            raise MissingColumnError(
                f"{spec['source_id']} is missing manifest column {requested_header!r} "
                f"for {canonical_name}"
            )
        if len(matches) != 1:
            raise AmbiguousMappingError(
                f"{spec['source_id']} column {requested_header!r} is ambiguous"
            )
        canonical_columns[canonical_name] = matches[0].column
        source_headers[canonical_name] = matches[0].text

    row_numbers = sorted(
        {
            row
            for row, column in cells_by_coordinate
            if row > header_row and column in canonical_columns.values()
        }
    )
    rows: list[_MappedRow] = []
    for row_number in row_numbers:
        mapped_cells = {
            canonical_name: cells_by_coordinate.get((row_number, column))
            for canonical_name, column in canonical_columns.items()
        }
        if not any(cell is not None and cell.text.strip() for cell in mapped_cells.values()):
            continue
        rows.append(
            _MappedRow(
                row_number=row_number,
                cells={
                    name: cell for name, cell in mapped_cells.items() if cell is not None
                },
            )
        )
    if not rows:
        raise CaseBuilderError(f"{spec['source_id']} contains no mapped data rows")
    return _MappedTable(rows=tuple(rows), source_headers=source_headers)


def _select_table_cells(
    source_format: str,
    evidence: list[Mapping[str, Any]],
    selector: Mapping[str, Any] | None,
    source_id: str,
    header_row: int,
) -> _SelectedTable:
    if source_format == "CSV":
        if selector is not None:
            raise ManifestError("CSV sources do not accept table_selector")
        selected = [item for item in evidence if item.get("kind") == "CELL"]
        canonical_selector = ("CSV", "<single-table>")
    elif source_format == "XLSX":
        sheets = {
            item.get("coordinates", {}).get("sheet")
            for item in evidence
            if item.get("kind") == "CELL" and isinstance(item.get("coordinates"), Mapping)
        }
        if selector is None:
            if len(sheets) != 1:
                raise AmbiguousMappingError(
                    f"{source_id} has {len(sheets)} worksheets; table_selector.sheet is required"
                )
            selected_sheet = next(iter(sheets))
        else:
            if set(selector) != {"sheet"}:
                raise ManifestError("XLSX table_selector must contain exactly 'sheet'")
            selected_sheet = selector["sheet"]
            _require_nonempty_string(selected_sheet, "table_selector.sheet")
        _require_nonempty_string(selected_sheet, "selected worksheet name")
        selected = [
            item
            for item in evidence
            if item.get("kind") == "CELL"
            and isinstance(item.get("coordinates"), Mapping)
            and item["coordinates"].get("sheet") == selected_sheet
        ]
        canonical_selector = ("XLSX", selected_sheet)
    elif source_format == "DOCX":
        tables = {
            item.get("coordinates", {}).get("table")
            for item in evidence
            if item.get("kind") == "TABLE_CELL"
            and isinstance(item.get("coordinates"), Mapping)
        }
        if selector is None:
            if len(tables) != 1:
                raise AmbiguousMappingError(
                    f"{source_id} has {len(tables)} tables; table_selector.table is required"
                )
            selected_table = next(iter(tables))
        else:
            if set(selector) != {"table"}:
                raise ManifestError("DOCX table_selector must contain exactly 'table'")
            selected_table = selector["table"]
            if (
                isinstance(selected_table, bool)
                or not isinstance(selected_table, int)
                or selected_table <= 0
            ):
                raise ManifestError("table_selector.table must be a positive integer")
        if (
            isinstance(selected_table, bool)
            or not isinstance(selected_table, int)
            or selected_table <= 0
        ):
            raise CaseBuilderError(f"{source_id} evidence has an invalid table number")
        selected = [
            item
            for item in evidence
            if item.get("kind") == "TABLE_CELL"
            and isinstance(item.get("coordinates"), Mapping)
            and item["coordinates"].get("table") == selected_table
        ]
        canonical_selector = ("DOCX", selected_table)
    else:  # guarded by _validate_evidence_document
        raise CaseBuilderError(f"unsupported structured table format: {source_format}")
    if not selected:
        raise CaseBuilderError(f"{source_id} selected table contains no cells")
    return _SelectedTable(
        cells=tuple(selected),
        canonical_selector=canonical_selector,
        logical_fingerprint=_logical_table_fingerprint(selected, source_id, header_row),
    )


def _evidence_source(
    spec: Mapping[str, Any],
    table: _MappedTable,
    canonical_name: str,
    cell: _Cell,
) -> dict[str, Any]:
    """Build one parser-cell identity without consulting mapping provenance."""

    return {
        "source_id": spec["source_id"],
        "document_id": spec["document_id"],
        "source_hash": cell.source_hash,
        "locator": cell.locator,
        "kind": cell.source_kind,
        "coordinates": {"row": cell.row, "column": cell.column},
        "column": table.source_headers[canonical_name],
        "raw_value": cell.text,
    }


def _copy_evidence_source(source: Mapping[str, Any]) -> dict[str, Any]:
    """Copy the fixed parser-cell identity without generic graph traversal."""

    copied = dict(source)
    coordinates = source.get("coordinates")
    if isinstance(coordinates, Mapping):
        copied["coordinates"] = dict(coordinates)
    return copied


def _evidence_source_key(source: Mapping[str, Any]) -> tuple[Any, ...]:
    """Return the exact structural key of a Builder-produced source cell."""

    coordinates = source["coordinates"]
    return (
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


def _immutable_mapping_value(value: Any) -> str | int | float | bool:
    """Admit only the immutable JSON scalar leaves emitted by the Builder."""

    if type(value) not in {str, int, float, bool}:
        raise CaseBuilderError("mapping values must be immutable JSON scalars")
    if type(value) is float and not math.isfinite(value):
        raise CaseBuilderError("mapping values must be finite JSON scalars")
    return value


def _mapping_value_key(value: Any) -> tuple[str, Any]:
    """Match the old canonical-JSON scalar identity without serializing it."""

    value = _immutable_mapping_value(value)
    if type(value) is float:
        # ``float.hex`` preserves signed zero, which canonical JSON also
        # distinguished, while remaining allocation-light on the hot path.
        return ("float", value.hex())
    return (type(value).__name__, value)


class _IndependentEvidencePlan:
    """Parser-cell role plan built independently of ``_record_mapping``."""

    def __init__(self, spec: Mapping[str, Any], table: _MappedTable) -> None:
        self.spec = spec
        self.table = table
        self._contributors: dict[str, tuple[Any, list[dict[str, Any]]]] = {}
        self._source_keys: dict[str, set[tuple[Any, ...]]] = {}
        self._derived: dict[str, dict[str, Any]] = {}

    def add(
        self,
        target: str,
        canonical_name: str,
        cell: _Cell,
        value: Any,
    ) -> None:
        source = _evidence_source(self.spec, self.table, canonical_name, cell)
        value = _immutable_mapping_value(value)
        value_key = _mapping_value_key(value)
        existing = self._contributors.get(target)
        if existing is None:
            # Parser mapping values are immutable JSON scalars.  Retaining the
            # scalar is byte-equivalent to deepcopy and cannot introduce a
            # mutable alias.
            self._contributors[target] = (value, [source])
            self._source_keys[target] = {_evidence_source_key(source)}
            return
        expected_value, sources = existing
        if _mapping_value_key(expected_value) != value_key:
            raise AmbiguousMappingError(
                f"parser role target has conflicting source values: {target}"
            )
        source_key = _evidence_source_key(source)
        if source_key in self._source_keys[target]:
            raise AmbiguousMappingError(
                f"parser role target repeats one source cell: {target}"
            )
        sources.append(source)
        self._source_keys[target].add(source_key)

    def add_derived(
        self,
        target: str,
        value: str,
        anchor_target: str,
        canonical_name: str,
        cell: _Cell,
    ) -> None:
        if target in self._derived or target in self._contributors:
            raise AmbiguousMappingError(f"duplicate parser role target: {target}")
        self._derived[target] = {
            "mapping_kind": "DERIVED_LOCATOR",
            "target": target,
            "value": value,
            "derivation_contract": DERIVED_LOCATOR_CONTRACT_VERSION,
            "anchor_target": anchor_target,
            "source": _evidence_source(
                self.spec, self.table, canonical_name, cell
            ),
        }

    def parser_cells(self) -> list[dict[str, Any]]:
        cells: list[dict[str, Any]] = []
        for row in self.table.rows:
            for canonical_name, cell in row.cells.items():
                cells.append(
                    {
                        "canonical_name": canonical_name,
                        "row_number": row.row_number,
                        "source": _evidence_source(
                            self.spec, self.table, canonical_name, cell
                        ),
                    }
                )
        return sorted(
            cells,
            key=lambda item: (
                int(item["row_number"]),
                int(item["source"]["coordinates"]["column"]),
                str(item["canonical_name"]),
            ),
        )

    def expected_mappings(self) -> list[dict[str, Any]]:
        mappings: list[dict[str, Any]] = []
        for target, (value, raw_sources) in self._contributors.items():
            sources = sorted(
                [_copy_evidence_source(item) for item in raw_sources],
                key=lambda item: (
                    int(item["coordinates"]["row"]),
                    int(item["coordinates"]["column"]),
                    str(item["locator"]),
                ),
            )
            if len(sources) == 1:
                mappings.append(
                    {
                        "mapping_kind": "DIRECT_CELL_VALUE",
                        "conversion_contract": (
                            MAPPING_VALUE_CONVERSION_CONTRACT_VERSION
                        ),
                        "target": target,
                        "value": value,
                        "source": sources[0],
                    }
                )
            else:
                mappings.append(
                    {
                        "mapping_kind": "AGGREGATED_IDENTICAL_VALUES",
                        "aggregation_contract": (
                            IDENTICAL_VALUE_AGGREGATION_CONTRACT_VERSION
                        ),
                        "conversion_contract": (
                            MAPPING_VALUE_CONVERSION_CONTRACT_VERSION
                        ),
                        "target": target,
                        "value": value,
                        "sources": sources,
                    }
                )
        mappings.extend(
            {
                **entry,
                "source": _copy_evidence_source(entry["source"]),
            }
            for entry in self._derived.values()
        )
        return sorted(mappings, key=lambda item: str(item["target"]))


def _plan_characteristic_row(
    plan: _IndependentEvidencePlan,
    spec: Mapping[str, Any],
    row: _MappedRow,
    index: int,
    *,
    include_controls: bool,
) -> tuple[str, str]:
    characteristic_cell, characteristic_id = _required_text(
        row, "characteristic_id", spec["source_id"]
    )
    step_cell, step = _required_text(row, "process_step_id", spec["source_id"])
    prefix = f"fields.characteristics[{index}]."
    plan.add(
        f"{prefix}characteristic_id",
        "characteristic_id",
        characteristic_cell,
        characteristic_id,
    )
    plan.add(f"{prefix}process_step_id", "process_step_id", step_cell, step)
    if include_controls:
        control_cell, control_id = _required_text(
            row, "control_id", spec["source_id"]
        )
        plan.add(f"{prefix}control_id", "control_id", control_cell, control_id)
    for canonical in ("target", "minimum", "maximum"):
        cell = _required_cell(row, canonical, spec["source_id"])
        plan.add(
            f"{prefix}specification.{canonical}",
            canonical,
            cell,
            _parse_number(cell.text, canonical),
        )
    unit_cell, unit = _required_text(row, "unit", spec["source_id"])
    plan.add(f"{prefix}specification.unit", "unit", unit_cell, unit)
    if include_controls:
        for canonical in ("control_method", "frequency", "reaction_plan"):
            cell, value = _required_text(row, canonical, spec["source_id"])
            plan.add(f"{prefix}{canonical}", canonical, cell, value)
    plan.add_derived(
        f"{prefix}locator",
        characteristic_cell.locator,
        f"{prefix}characteristic_id",
        "characteristic_id",
        characteristic_cell,
    )
    return step, characteristic_id


def _build_artifact_evidence(
    spec: Mapping[str, Any], table: _MappedTable
) -> ArtifactBuildEvidence:
    """Derive cell and target-role evidence directly from the mapped parser table."""

    plan = _IndependentEvidencePlan(spec, table)
    document_type = spec["document_type"]
    if document_type == "PROCESS_FLOW":
        seen_steps: set[str] = set()
        for index, row in enumerate(table.rows):
            cell, step = _required_text(row, "process_step_id", spec["source_id"])
            if step in seen_steps:
                raise DuplicateIdentifierError(f"duplicate process_step_id: {step}")
            seen_steps.add(step)
            plan.add(f"fields.process_steps[{index}]", "process_step_id", cell, step)
    elif document_type == "PFMEA":
        step_indexes: dict[str, int] = {}
        failure_modes: set[str] = set()
        for index, row in enumerate(table.rows):
            step_cell, step = _required_text(
                row, "process_step_id", spec["source_id"]
            )
            step_index = step_indexes.setdefault(step, len(step_indexes))
            plan.add(
                f"fields.process_steps[{step_index}]",
                "process_step_id",
                step_cell,
                step,
            )
            failure_cell, failure_id = _required_text(
                row, "failure_mode_id", spec["source_id"]
            )
            if failure_id in failure_modes:
                raise DuplicateIdentifierError(
                    f"duplicate failure_mode_id: {failure_id}"
                )
            failure_modes.add(failure_id)
            characteristic_cell, characteristic_id = _required_text(
                row, "characteristic_id", spec["source_id"]
            )
            special_cell = _required_cell(
                row, "special_characteristic", spec["source_id"]
            )
            special = _parse_boolean(
                special_cell.text, "special_characteristic"
            )
            prefix = f"fields.risks[{index}]."
            for canonical, cell, value in (
                ("failure_mode_id", failure_cell, failure_id),
                ("process_step_id", step_cell, step),
                ("characteristic_id", characteristic_cell, characteristic_id),
                ("special_characteristic", special_cell, special),
            ):
                plan.add(f"{prefix}{canonical}", canonical, cell, value)
            if "effect" in spec["columns"]:
                effect_cell, effect = _required_text(
                    row, "effect", spec["source_id"]
                )
                plan.add(f"{prefix}effect", "effect", effect_cell, effect)
            plan.add_derived(
                f"{prefix}locator",
                failure_cell.locator,
                f"{prefix}failure_mode_id",
                "failure_mode_id",
                failure_cell,
            )
    else:
        step_indexes: dict[str, int] = {}
        relationship_ids: set[tuple[str, str]] = set()
        control_ids: set[str] = set()
        include_controls = document_type == "CONTROL_PLAN"
        for index, row in enumerate(table.rows):
            step_cell, step = _required_text(
                row, "process_step_id", spec["source_id"]
            )
            step_index = step_indexes.setdefault(step, len(step_indexes))
            plan.add(
                f"fields.process_steps[{step_index}]",
                "process_step_id",
                step_cell,
                step,
            )
            planned_step, characteristic_id = _plan_characteristic_row(
                plan,
                spec,
                row,
                index,
                include_controls=include_controls,
            )
            relation = relationship_key(planned_step, characteristic_id)
            if relation in relationship_ids:
                raise DuplicateIdentifierError(
                    f"duplicate {document_type} process_step_id + characteristic_id pair: {relation}"
                )
            relationship_ids.add(relation)
            if include_controls:
                _control_cell, control_id = _required_text(
                    row, "control_id", spec["source_id"]
                )
                if control_id in control_ids:
                    raise DuplicateIdentifierError(
                        f"duplicate CONTROL_PLAN control_id: {control_id}"
                    )
                control_ids.add(control_id)
            if document_type == "INSPECTION_RECORD":
                for canonical, target_name, target_leaf in (
                    ("sop_document_id", "SOP", "document_id"),
                    ("sop_revision", "SOP", "revision"),
                    (
                        "control_plan_document_id",
                        "CONTROL_PLAN",
                        "document_id",
                    ),
                    ("control_plan_revision", "CONTROL_PLAN", "revision"),
                ):
                    cell, value = _required_text(
                        row, canonical, spec["source_id"]
                    )
                    plan.add(
                        f"fields.references.{target_name}.{target_leaf}",
                        canonical,
                        cell,
                        value,
                    )

    parser_cells = plan.parser_cells()
    expected_mappings = plan.expected_mappings()
    return ArtifactBuildEvidence(
        parser_cells_json=json.dumps(
            parser_cells,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8"),
        expected_mappings_json=json.dumps(
            expected_mappings,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8"),
    )


def _build_fields(
    spec: Mapping[str, Any], table: _MappedTable
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    document_type = spec["document_type"]
    provenance: list[dict[str, Any]] = _ProvenanceList()
    if document_type == "PROCESS_FLOW":
        fields = _build_process_flow(spec, table, provenance)
    elif document_type == "PFMEA":
        fields = _build_pfmea(spec, table, provenance)
    elif document_type == "CONTROL_PLAN":
        fields = _build_control_plan(spec, table, provenance)
    elif document_type == "SOP":
        fields = _build_characteristic_document(spec, table, provenance)
    else:
        fields = _build_inspection_record(spec, table, provenance)
    return fields, provenance


def _build_process_flow(
    spec: Mapping[str, Any],
    table: _MappedTable,
    provenance: list[dict[str, Any]],
) -> dict[str, Any]:
    steps: list[str] = []
    seen: set[str] = set()
    for row in table.rows:
        cell, step = _required_text(row, "process_step_id", spec["source_id"])
        if step in seen:
            raise DuplicateIdentifierError(f"duplicate process_step_id: {step}")
        seen.add(step)
        index = len(steps)
        steps.append(step)
        _record_mapping(
            spec, table, provenance, f"fields.process_steps[{index}]", "process_step_id", cell, step
        )
    return {"process_steps": steps}


def _build_pfmea(
    spec: Mapping[str, Any],
    table: _MappedTable,
    provenance: list[dict[str, Any]],
) -> dict[str, Any]:
    steps: list[str] = []
    step_indexes: dict[str, int] = {}
    risks: list[dict[str, Any]] = []
    failure_modes: set[str] = set()
    for row in table.rows:
        step_cell, step = _required_text(row, "process_step_id", spec["source_id"])
        step_index = step_indexes.setdefault(step, len(steps))
        if step_index == len(steps):
            steps.append(step)
        _record_mapping(
            spec,
            table,
            provenance,
            f"fields.process_steps[{step_index}]",
            "process_step_id",
            step_cell,
            step,
        )
        failure_cell, failure_id = _required_text(
            row, "failure_mode_id", spec["source_id"]
        )
        if failure_id in failure_modes:
            raise DuplicateIdentifierError(f"duplicate failure_mode_id: {failure_id}")
        failure_modes.add(failure_id)
        characteristic_cell, characteristic_id = _required_text(
            row, "characteristic_id", spec["source_id"]
        )
        special_cell = _required_cell(row, "special_characteristic", spec["source_id"])
        special = _parse_boolean(special_cell.text, "special_characteristic")
        risk_index = len(risks)
        risk: dict[str, Any] = {
            "failure_mode_id": failure_id,
            "process_step_id": step,
            "characteristic_id": characteristic_id,
            "special_characteristic": special,
            "locator": failure_cell.locator,
        }
        for canonical, cell, value in (
            ("failure_mode_id", failure_cell, failure_id),
            ("process_step_id", step_cell, step),
            ("characteristic_id", characteristic_cell, characteristic_id),
            ("special_characteristic", special_cell, special),
        ):
            _record_mapping(
                spec,
                table,
                provenance,
                f"fields.risks[{risk_index}].{canonical}",
                canonical,
                cell,
                value,
            )
        if "effect" in spec["columns"]:
            effect_cell, effect = _required_text(row, "effect", spec["source_id"])
            risk["effect"] = effect
            _record_mapping(
                spec,
                table,
                provenance,
                f"fields.risks[{risk_index}].effect",
                "effect",
                effect_cell,
                effect,
            )
        risks.append(risk)
    return {"process_steps": steps, "risks": risks}


def _build_control_plan(
    spec: Mapping[str, Any],
    table: _MappedTable,
    provenance: list[dict[str, Any]],
) -> dict[str, Any]:
    steps: list[str] = []
    step_indexes: dict[str, int] = {}
    characteristics: list[dict[str, Any]] = []
    relationship_ids: set[tuple[str, str]] = set()
    control_ids: set[str] = set()
    for row in table.rows:
        step_cell, step = _required_text(row, "process_step_id", spec["source_id"])
        step_index = step_indexes.setdefault(step, len(steps))
        if step_index == len(steps):
            steps.append(step)
        _record_mapping(
            spec,
            table,
            provenance,
            f"fields.process_steps[{step_index}]",
            "process_step_id",
            step_cell,
            step,
        )
        characteristic = _build_characteristic(
            spec, table, row, len(characteristics), provenance, include_controls=True
        )
        relationship_id = relationship_key(
            characteristic["process_step_id"], characteristic["characteristic_id"]
        )
        if relationship_id in relationship_ids:
            raise DuplicateIdentifierError(
                "duplicate CONTROL_PLAN process_step_id + characteristic_id pair: "
                f"{relationship_id}"
            )
        control_id = characteristic["control_id"]
        if control_id in control_ids:
            raise DuplicateIdentifierError(
                f"duplicate CONTROL_PLAN control_id: {control_id}"
            )
        relationship_ids.add(relationship_id)
        control_ids.add(control_id)
        characteristics.append(characteristic)
    return {"process_steps": steps, "characteristics": characteristics}


def _build_characteristic_document(
    spec: Mapping[str, Any],
    table: _MappedTable,
    provenance: list[dict[str, Any]],
) -> dict[str, Any]:
    steps: list[str] = []
    step_indexes: dict[str, int] = {}
    characteristics: list[dict[str, Any]] = []
    identifiers: set[tuple[str, str]] = set()
    for row in table.rows:
        step_cell, step = _required_text(row, "process_step_id", spec["source_id"])
        step_index = step_indexes.setdefault(step, len(steps))
        if step_index == len(steps):
            steps.append(step)
        _record_mapping(
            spec,
            table,
            provenance,
            f"fields.process_steps[{step_index}]",
            "process_step_id",
            step_cell,
            step,
        )
        characteristic = _build_characteristic(
            spec, table, row, len(characteristics), provenance, include_controls=False
        )
        identifier = relationship_key(
            characteristic["process_step_id"], characteristic["characteristic_id"]
        )
        if identifier in identifiers:
            raise DuplicateIdentifierError(
                f"duplicate {spec['document_type']} process_step_id + "
                f"characteristic_id pair: {identifier}"
            )
        identifiers.add(identifier)
        characteristics.append(characteristic)
    return {"process_steps": steps, "characteristics": characteristics}


def _build_inspection_record(
    spec: Mapping[str, Any],
    table: _MappedTable,
    provenance: list[dict[str, Any]],
) -> dict[str, Any]:
    fields = _build_characteristic_document(spec, table, provenance)
    references: dict[str, dict[str, str]] = {}
    for row in table.rows:
        for canonical, target_name, target_leaf in (
            ("sop_document_id", "SOP", "document_id"),
            ("sop_revision", "SOP", "revision"),
            ("control_plan_document_id", "CONTROL_PLAN", "document_id"),
            ("control_plan_revision", "CONTROL_PLAN", "revision"),
        ):
            cell, value = _required_text(row, canonical, spec["source_id"])
            identity = references.setdefault(target_name, {})
            previous = identity.get(target_leaf)
            if previous is not None and previous != value:
                raise AmbiguousMappingError(
                    f"{spec['source_id']} has conflicting {canonical} values: "
                    f"{previous!r} and {value!r}"
                )
            identity[target_leaf] = value
            _record_mapping(
                spec,
                table,
                provenance,
                f"fields.references.{target_name}.{target_leaf}",
                canonical,
                cell,
                value,
            )
    fields["references"] = references
    return fields


def _finalize_controlled_references(documents: list[dict[str, Any]]) -> None:
    """Derive reference type/hash from the same raw-built target registry."""

    by_exact_id: dict[str, dict[str, Any]] = {}
    for document in documents:
        document_id = document["document_id"]
        if document_id in by_exact_id:
            raise DuplicateIdentifierError(
                f"duplicate exact document_id in controlled reference registry: {document_id}"
            )
        by_exact_id[document_id] = document
    inspection = next(
        (
            document
            for document in documents
            if document.get("document_type") == "INSPECTION_RECORD"
            and document.get("status") == "APPROVED"
        ),
        None,
    )
    if not isinstance(inspection, dict):
        raise ManifestError("controlled references require an approved Inspection record")
    registry: dict[str, dict[str, str]] = {}
    references = inspection.get("fields", {}).get("references", {})
    for role in ("SOP", "CONTROL_PLAN"):
        observation = references.get(role) if isinstance(references, dict) else None
        target = by_exact_id.get(
            observation.get("document_id") if isinstance(observation, dict) else None
        )
        if not isinstance(target, dict):
            raise ManifestError(f"Inspection reference target does not exist: {role}")
        source_hash = target.get("source_hash")
        if not isinstance(source_hash, str) or LOWERCASE_SHA256.fullmatch(source_hash) is None:
            raise ManifestError(f"Inspection reference target is not byte-addressed: {role}")
        registry[role] = {
            "document_type": role,
            "document_id": target["document_id"],
            "revision": target["revision"],
            "source_hash": source_hash,
        }
    _finalize_inspection_reference_with_registry(inspection, registry)


def _finalize_inspection_reference_with_registry(
    inspection: dict[str, Any],
    registry: Mapping[str, Mapping[str, str]],
) -> None:
    """Overlay computed target identities on directly parsed ID/revision cells."""

    inspection["reference_contract_version"] = CONTROLLED_REFERENCE_CONTRACT_VERSION
    references = inspection.get("fields", {}).get("references")
    if not isinstance(references, dict):
        raise ManifestError("Inspection references are missing")
    provenance = inspection.get("mapping_provenance")
    if not isinstance(provenance, list):
        raise ManifestError("Inspection mapping provenance is missing")
    for role in ("SOP", "CONTROL_PLAN"):
        identity = references.get(role)
        target = registry.get(role)
        if not isinstance(identity, dict) or not isinstance(target, Mapping):
            raise ManifestError(f"Inspection reference is missing: {role}")
        if (
            target.get("document_type") != role
            or target.get("document_id") != identity.get("document_id")
            or target.get("revision") != identity.get("revision")
        ):
            raise ManifestError(f"Inspection reference target identity differs: {role}")
        source_hash = target.get("source_hash")
        if not isinstance(source_hash, str) or LOWERCASE_SHA256.fullmatch(source_hash) is None:
            raise ManifestError(f"Inspection reference target is not byte-addressed: {role}")
        identity["document_type"] = role
        identity["source_hash"] = source_hash
        for leaf, value in (("document_type", role), ("source_hash", source_hash)):
            provenance.append(
                {
                    "mapping_kind": "DERIVED_REFERENCE_IDENTITY",
                    "target": f"fields.references.{role}.{leaf}",
                    "value": value,
                    "reference_role": role,
                    "target_document_id": target["document_id"],
                    "target_revision": target["revision"],
                    "target_source_hash": source_hash,
                    "derivation_contract": (
                        DERIVED_REFERENCE_IDENTITY_CONTRACT_VERSION
                    ),
                }
            )
    provenance.sort(
        key=lambda item: (
            str(item.get("target", "")),
            str(item.get("mapping_kind", "")),
            json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
    )


def _build_characteristic(
    spec: Mapping[str, Any],
    table: _MappedTable,
    row: _MappedRow,
    index: int,
    provenance: list[dict[str, Any]],
    *,
    include_controls: bool,
) -> dict[str, Any]:
    characteristic_cell, characteristic_id = _required_text(
        row, "characteristic_id", spec["source_id"]
    )
    process_step_cell, process_step_id = _required_text(
        row, "process_step_id", spec["source_id"]
    )
    characteristic: dict[str, Any] = {
        "process_step_id": process_step_id,
        "characteristic_id": characteristic_id,
        "specification": {},
        "locator": characteristic_cell.locator,
    }
    _record_mapping(
        spec,
        table,
        provenance,
        f"fields.characteristics[{index}].characteristic_id",
        "characteristic_id",
        characteristic_cell,
        characteristic_id,
    )
    _record_mapping(
        spec,
        table,
        provenance,
        f"fields.characteristics[{index}].process_step_id",
        "process_step_id",
        process_step_cell,
        process_step_id,
    )
    if include_controls:
        control_cell, control_id = _required_text(
            row, "control_id", spec["source_id"]
        )
        characteristic["control_id"] = control_id
        _record_mapping(
            spec,
            table,
            provenance,
            f"fields.characteristics[{index}].control_id",
            "control_id",
            control_cell,
            control_id,
        )
    for canonical in ("target", "minimum", "maximum"):
        cell = _required_cell(row, canonical, spec["source_id"])
        value = _parse_number(cell.text, canonical)
        characteristic["specification"][canonical] = value
        _record_mapping(
            spec,
            table,
            provenance,
            f"fields.characteristics[{index}].specification.{canonical}",
            canonical,
            cell,
            value,
        )
    unit_cell, unit = _required_text(row, "unit", spec["source_id"])
    characteristic["specification"]["unit"] = unit
    _record_mapping(
        spec,
        table,
        provenance,
        f"fields.characteristics[{index}].specification.unit",
        "unit",
        unit_cell,
        unit,
    )
    if include_controls:
        for canonical in ("control_method", "frequency", "reaction_plan"):
            cell, value = _required_text(row, canonical, spec["source_id"])
            characteristic[canonical] = value
            _record_mapping(
                spec,
                table,
                provenance,
                f"fields.characteristics[{index}].{canonical}",
                canonical,
                cell,
                value,
            )
    return characteristic


def _record_mapping(
    spec: Mapping[str, Any],
    table: _MappedTable,
    provenance: list[dict[str, Any]],
    target: str,
    canonical_name: str,
    cell: _Cell,
    value: Any,
) -> None:
    value = _immutable_mapping_value(value)
    provenance.append(
        {
            "mapping_kind": "DIRECT_CELL_VALUE",
            "conversion_contract": MAPPING_VALUE_CONVERSION_CONTRACT_VERSION,
            "target": target,
            # Builder mappings contain immutable JSON scalar leaves only.
            "value": value,
            "source": {
                "source_id": spec["source_id"],
                "document_id": spec["document_id"],
                "source_hash": cell.source_hash,
                "locator": cell.locator,
                "kind": cell.source_kind,
                "coordinates": {"row": cell.row, "column": cell.column},
                "column": table.source_headers[canonical_name],
                "raw_value": cell.text,
            },
        }
    )


def _record_derived_locators(
    fields: Mapping[str, Any], provenance: list[dict[str, Any]]
) -> None:
    """Attach explicit provenance to parser-derived row locator leaves."""

    by_target = {str(entry.get("target")): entry for entry in provenance}
    for collection_name in ("risks", "characteristics"):
        items = fields.get(collection_name, [])
        if not isinstance(items, list):
            continue
        for index, item in enumerate(items):
            if not isinstance(item, Mapping) or "locator" not in item:
                continue
            prefix = f"fields.{collection_name}[{index}]."
            anchor_field = (
                "failure_mode_id" if collection_name == "risks" else "characteristic_id"
            )
            preferred = f"{prefix}{anchor_field}"
            source_mapping = by_target.get(preferred)
            if source_mapping is None:
                raise CaseBuilderError(
                    f"cannot derive locator provenance for {prefix}locator"
                )
            provenance.append(
                {
                    "mapping_kind": "DERIVED_LOCATOR",
                    "target": f"{prefix}locator",
                    "value": item["locator"],
                    "derivation_contract": DERIVED_LOCATOR_CONTRACT_VERSION,
                    "anchor_target": preferred,
                    "source": _copy_evidence_source(source_mapping["source"]),
                }
            )


def _required_cell(row: _MappedRow, canonical_name: str, source_id: str) -> _Cell:
    cell = row.cells.get(canonical_name)
    if cell is None or not cell.text.strip():
        raise MissingColumnError(
            f"{source_id} row {row.row_number} has no value for {canonical_name}"
        )
    return cell


def _required_text(
    row: _MappedRow, canonical_name: str, source_id: str
) -> tuple[_Cell, str]:
    cell = _required_cell(row, canonical_name, source_id)
    return cell, cell.text.strip()


def _parse_boolean(value: str, label: str) -> bool:
    normalized = value.strip().casefold()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise CaseBuilderError(f"{label} must be the explicit literal true or false")


def _parse_number(value: str, label: str) -> int | float:
    stripped = value.strip()
    try:
        parsed = float(stripped)
    except ValueError as error:
        raise CaseBuilderError(f"{label} must be a finite number") from error
    if not math.isfinite(parsed):
        raise CaseBuilderError(f"{label} must be a finite number")
    return int(parsed) if parsed.is_integer() else parsed


def _is_finite_numeric_literal(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = float(value.strip())
    except ValueError:
        return False
    return math.isfinite(parsed)


def _logical_table_fingerprint(
    cells: list[Mapping[str, Any]], source_id: str, header_row: int
) -> str:
    """Hash the selected parsed cell grid, independent of source serialization."""

    normalized_cells: list[tuple[int, int, str]] = []
    for item in cells:
        coordinates = item.get("coordinates")
        if not isinstance(coordinates, Mapping):
            raise CaseBuilderError(
                f"{source_id} evidence lacks structured coordinates"
            )
        row = coordinates.get("row")
        column = coordinates.get("column")
        if (
            isinstance(row, bool)
            or not isinstance(row, int)
            or row <= 0
            or isinstance(column, bool)
            or not isinstance(column, int)
            or column <= 0
        ):
            raise CaseBuilderError(
                f"{source_id} evidence has invalid row/column coordinates"
            )
        text = item.get("text")
        if not isinstance(text, str):
            raise CaseBuilderError(f"{source_id} evidence has invalid text")
        normalized_text = unicodedata.normalize(
            "NFC", text.replace("\r\n", "\n").replace("\r", "\n")
        ).strip()
        if row == header_row:
            normalized_text = _normalize_header(normalized_text)
        if normalized_text:
            normalized_cells.append((row, column, normalized_text))

    if normalized_cells:
        minimum_row = min(row for row, _, _ in normalized_cells)
        minimum_column = min(column for _, column, _ in normalized_cells)
        normalized_cells = [
            (row - minimum_row + 1, column - minimum_column + 1, text)
            for row, column, text in normalized_cells
        ]

    digest = hashlib.sha256(b"qualityci-logical-table-v1\0")
    for row, column, text in sorted(normalized_cells):
        encoded = text.encode("utf-8")
        digest.update(row.to_bytes(8, "big"))
        digest.update(column.to_bytes(8, "big"))
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _normalize_header(value: str) -> str:
    return " ".join(value.strip().casefold().split())


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestError(f"{label} must be an object")
    return value


def _require_nonempty_string(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{label} must be a non-empty string")


def _reject_duplicates(values: list[str], label: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    if duplicates:
        raise DuplicateIdentifierError(
            f"duplicate {label} values: {sorted(duplicates)}"
        )


def _reject_duplicate_strings(value: Any, label: str) -> None:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ManifestError(f"{label} must be a list of non-empty strings")
    _reject_duplicates(value, label)
