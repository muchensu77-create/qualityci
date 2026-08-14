"""Internal controlled-document reference identity context.

The context is deliberately not a serializable trust marker.  It is created
only while the Case Builder still owns the immutable raw-byte snapshot from
which the Inspection, SOP, and Control Plan documents were rebuilt.  Public
JSON entrypoints never accept this object.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Mapping

from .loader import (
    CONTROLLED_REFERENCE_CONTRACT_VERSION,
    LOWERCASE_SHA256,
    REFERENCE_ROLES,
)


DERIVED_REFERENCE_IDENTITY_CONTRACT_VERSION = (
    "qualityci-derived-reference-identity-0.1"
)
CONTROLLED_REFERENCE_PACK_VERSION = "qualityci-controlled-reference-pack-0.1"
MAX_REFERENCE_MEMBERS = 16
MAX_REFERENCE_MEMBER_BYTES = 10 * 1024 * 1024

_REFERENCE_MANIFEST_ROOT_KEYS = {"contract_version", "documents"}
_REFERENCE_DOCUMENT_REQUIRED_KEYS = {
    "source_id",
    "source_path",
    "document_id",
    "document_type",
    "revision",
    "status",
    "owner",
    "revision_date",
    "columns",
}
_REFERENCE_DOCUMENT_OPTIONAL_KEYS = {"header_row", "table_selector"}

_CONTEXT_SEAL = object()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class _ReferenceWitness:
    source_id: str
    document_type: str
    document_id: str
    revision: str
    filename: str
    relative_path: str
    source_hash: str
    raw_bytes: bytes

    def __post_init__(self) -> None:
        raw = bytes(self.raw_bytes)
        object.__setattr__(self, "raw_bytes", raw)
        if hashlib.sha256(raw).hexdigest() != self.source_hash:
            raise ValueError("controlled reference witness hash differs from raw bytes")


@dataclass(frozen=True, init=False)
class _ControlledReferenceContext:
    contract_version: str
    reference_set_hash: str
    inspection_document_id: str
    documents_json: bytes
    references_json: bytes
    evidence_json: bytes
    witnesses: tuple[_ReferenceWitness, ...]
    _seal: object

    def __init__(
        self,
        *,
        contract_version: str,
        reference_set_hash: str,
        inspection_document_id: str,
        documents_json: bytes,
        references_json: bytes,
        evidence_json: bytes,
        witnesses: tuple[_ReferenceWitness, ...],
        _seal: object,
    ) -> None:
        if _seal is not _CONTEXT_SEAL:
            raise TypeError("controlled reference context is internal")
        object.__setattr__(self, "contract_version", contract_version)
        object.__setattr__(self, "reference_set_hash", reference_set_hash)
        object.__setattr__(self, "inspection_document_id", inspection_document_id)
        object.__setattr__(self, "documents_json", bytes(documents_json))
        object.__setattr__(self, "references_json", bytes(references_json))
        object.__setattr__(self, "evidence_json", bytes(evidence_json))
        object.__setattr__(self, "witnesses", tuple(witnesses))
        object.__setattr__(self, "_seal", _seal)

    def is_sealed(self) -> bool:
        return self._seal is _CONTEXT_SEAL

    def references(self) -> dict[str, dict[str, str]]:
        value = json.loads(self.references_json.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("internal controlled references are invalid")
        # json.loads() already creates a fresh object graph on every call.
        # Copying that graph again adds no caller-isolation and is costly for
        # the resolved 3,000-row controlled-document path.
        return value

    def documents(self) -> tuple[dict[str, Any], ...]:
        value = json.loads(self.documents_json.decode("utf-8"))
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ValueError("internal controlled reference documents are invalid")
        return tuple(value)

    def evidence(self) -> dict[str, dict[str, Any]]:
        value = json.loads(self.evidence_json.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("internal controlled reference evidence is invalid")
        return value

    def witness_by_type(self) -> dict[str, _ReferenceWitness]:
        return {item.document_type: item for item in self.witnesses}


@dataclass(frozen=True)
class ControlledReferenceMember:
    source_id: str
    document_id: str
    filename: str
    raw_bytes: bytes

    def __post_init__(self) -> None:
        if (
            type(self.source_id) is not str
            or type(self.document_id) is not str
            or type(self.filename) is not str
            or type(self.raw_bytes) is not bytes
        ):
            raise TypeError(
                "controlled reference member source_id/document_id/filename/raw_bytes "
                "require exact built-in str/bytes types"
            )
        if not self.source_id.strip():
            raise ValueError("controlled reference member source_id must be non-empty")
        if not self.document_id.strip():
            raise ValueError("controlled reference member document_id must be non-empty")
        if not self.filename.strip():
            raise ValueError("controlled reference member filename must be non-empty")
        if not self.raw_bytes:
            raise ValueError("controlled reference member raw_bytes must be non-empty bytes")
        if len(self.raw_bytes) > MAX_REFERENCE_MEMBER_BYTES:
            raise ValueError("controlled reference member exceeds byte limit")


@dataclass(frozen=True)
class ControlledReferenceBundle:
    """Immutable captured manifest and raw members; not itself a trust marker."""

    canonical_manifest_bytes: bytes
    members: tuple[ControlledReferenceMember, ...]

    def __post_init__(self) -> None:
        if type(self.canonical_manifest_bytes) is not bytes:
            raise TypeError("controlled reference manifest must be immutable bytes")
        if not isinstance(self.members, tuple):
            raise TypeError("controlled reference members must be an immutable tuple")
        if any(type(item) is not ControlledReferenceMember for item in self.members):
            raise TypeError("controlled reference bundle rejects member duck types")
        object.__setattr__(
            self, "canonical_manifest_bytes", bytes(self.canonical_manifest_bytes)
        )
        object.__setattr__(
            self,
            "members",
            tuple(
                ControlledReferenceMember(
                    item.source_id,
                    item.document_id,
                    item.filename,
                    bytes(item.raw_bytes),
                )
                for item in self.members
            ),
        )
        if not self.canonical_manifest_bytes:
            raise ValueError("controlled reference manifest must be non-empty")
        if not self.members or len(self.members) > MAX_REFERENCE_MEMBERS:
            raise ValueError("controlled reference member count is invalid")
        _validate_controlled_reference_bundle(self)


def _canonical_relative_filename(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("controlled reference source_path must be a canonical filename")
    path = Path(value)
    if (
        path.is_absolute()
        or len(path.parts) != 1
        or value in {".", ".."}
        or "\\" in value
    ):
        raise ValueError("controlled reference source_path must be one relative file")
    if any(ord(character) < 32 for character in value):
        raise ValueError("controlled reference source_path contains control characters")
    return value


def _validate_controlled_reference_bundle(
    bundle: ControlledReferenceBundle,
) -> dict[str, Any]:
    """Revalidate one captured bundle without trusting its constructor caller."""

    from .loader import normalized_identity, strict_json_loads

    try:
        manifest = strict_json_loads(bundle.canonical_manifest_bytes.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise ValueError("controlled reference manifest is not strict JSON") from error
    if not isinstance(manifest, dict) or set(manifest) != _REFERENCE_MANIFEST_ROOT_KEYS:
        raise ValueError("controlled reference manifest has unsupported root keys")
    if manifest["contract_version"] != CONTROLLED_REFERENCE_PACK_VERSION:
        raise ValueError("unsupported controlled reference pack version")
    documents = manifest["documents"]
    if (
        not isinstance(documents, list)
        or len(documents) != 3
        or any(not isinstance(item, dict) for item in documents)
    ):
        raise ValueError("controlled reference pack requires exactly three document specs")
    allowed_document_keys = (
        _REFERENCE_DOCUMENT_REQUIRED_KEYS | _REFERENCE_DOCUMENT_OPTIONAL_KEYS
    )
    for index, spec in enumerate(documents):
        if not _REFERENCE_DOCUMENT_REQUIRED_KEYS.issubset(spec) or not set(spec).issubset(
            allowed_document_keys
        ):
            raise ValueError(
                f"controlled reference documents[{index}] has unsupported shape"
            )
        for key in (
            "source_id",
            "document_id",
            "document_type",
            "revision",
            "status",
            "owner",
            "revision_date",
        ):
            if not isinstance(spec[key], str) or not spec[key].strip():
                raise ValueError(
                    f"controlled reference documents[{index}].{key} must be non-empty"
                )
        revision_date = spec["revision_date"]
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", revision_date) is None:
            raise ValueError(
                f"controlled reference documents[{index}].revision_date "
                "must use YYYY-MM-DD format"
            )
        try:
            date.fromisoformat(revision_date)
        except ValueError as error:
            raise ValueError(
                f"controlled reference documents[{index}].revision_date "
                "must be an ISO calendar date"
            ) from error
        _canonical_relative_filename(spec["source_path"])
        if spec["status"] != "APPROVED":
            raise ValueError("controlled reference documents must be APPROVED")
        columns = spec["columns"]
        if not isinstance(columns, dict) or not columns or any(
            not isinstance(key, str)
            or not key.strip()
            or not isinstance(value, str)
            or not value.strip()
            for key, value in columns.items()
        ):
            raise ValueError("controlled reference columns must be non-empty strings")
        header_row = spec.get("header_row", 1)
        if (
            isinstance(header_row, bool)
            or not isinstance(header_row, int)
            or header_row <= 0
        ):
            raise ValueError("controlled reference header_row must be positive")
        if "table_selector" in spec and not isinstance(spec["table_selector"], dict):
            raise ValueError("controlled reference table_selector must be an object")

    def reject_normalized_duplicates(values: list[str], label: str) -> None:
        if len({normalized_identity(value) for value in values}) != len(values):
            raise ValueError(f"controlled reference {label} collision")

    document_ids = [str(item["document_id"]) for item in documents]
    source_ids = [str(item["source_id"]) for item in documents]
    source_paths = [str(item["source_path"]) for item in documents]
    reject_normalized_duplicates(document_ids, "document_id")
    reject_normalized_duplicates(source_ids, "source_id")
    reject_normalized_duplicates(source_paths, "source_path")
    if {item["document_type"] for item in documents} != {
        "SOP",
        "CONTROL_PLAN",
        "INSPECTION_RECORD",
    }:
        raise ValueError(
            "controlled reference pack requires SOP, CONTROL_PLAN and INSPECTION_RECORD"
        )
    canonical_manifest = {
        "contract_version": CONTROLLED_REFERENCE_PACK_VERSION,
        "documents": sorted(
            documents,
            key=lambda item: (
                normalized_identity(item["document_id"]),
                item["document_id"],
            ),
        ),
    }
    if bundle.canonical_manifest_bytes != _canonical_bytes(canonical_manifest):
        raise ValueError("controlled reference manifest is not canonical")

    member_ids = [item.document_id for item in bundle.members]
    member_sources = [item.source_id for item in bundle.members]
    member_paths = [item.filename for item in bundle.members]
    reject_normalized_duplicates(member_ids, "member document_id")
    reject_normalized_duplicates(member_sources, "member source_id")
    reject_normalized_duplicates(member_paths, "member filename")
    if len(bundle.members) != len(documents):
        raise ValueError("controlled reference members differ from manifest")
    specs = {item["document_id"]: item for item in documents}
    members = {item.document_id: item for item in bundle.members}
    if set(specs) != set(members):
        raise ValueError("controlled reference members differ from manifest")
    for document_id, spec in specs.items():
        member = members[document_id]
        if (
            member.source_id != spec["source_id"]
            or member.filename != spec["source_path"]
        ):
            raise ValueError("controlled reference member identity differs from manifest")
    return canonical_manifest


def load_controlled_reference_bundle(
    manifest_path: str | Path,
) -> ControlledReferenceBundle:
    """Read each controlled member once from one allowlisted pack root."""

    from .loader import load_json, normalized_identity

    path = Path(manifest_path).resolve(strict=True)
    manifest = load_json(path)
    if not isinstance(manifest, dict) or set(manifest) != {
        "contract_version",
        "documents",
    }:
        raise ValueError("controlled reference manifest has unsupported shape")
    if manifest["contract_version"] != CONTROLLED_REFERENCE_PACK_VERSION:
        raise ValueError("unsupported controlled reference pack version")
    documents = manifest["documents"]
    if not isinstance(documents, list) or any(
        not isinstance(item, dict) for item in documents
    ):
        raise ValueError("controlled reference documents must be a non-empty list")
    if len(documents) != 3:
        raise ValueError(
            "controlled reference pack requires exactly three authoritative members"
        )
    document_ids = [item.get("document_id") for item in documents]
    source_ids = [item.get("source_id") for item in documents]
    source_paths = [_canonical_relative_filename(item.get("source_path")) for item in documents]
    if any(not isinstance(item, str) or not item.strip() for item in document_ids):
        raise ValueError("controlled reference document_id must be non-empty")
    if any(not isinstance(item, str) or not item.strip() for item in source_ids):
        raise ValueError("controlled reference source_id must be non-empty")
    if len({normalized_identity(item) for item in document_ids}) != len(document_ids):
        raise ValueError("controlled reference document_id collision")
    if len({normalized_identity(item) for item in source_ids}) != len(source_ids):
        raise ValueError("controlled reference source_id collision")
    if len({normalized_identity(item) for item in source_paths}) != len(source_paths):
        raise ValueError("controlled reference source_path collision")
    if {item.get("document_type") for item in documents} != {
        "SOP",
        "CONTROL_PLAN",
        "INSPECTION_RECORD",
    }:
        raise ValueError("controlled reference pack requires SOP, CONTROL_PLAN and INSPECTION_RECORD")
    members: list[ControlledReferenceMember] = []
    for spec, source_path in zip(documents, source_paths, strict=True):
        source = path.parent / source_path
        metadata = os.lstat(source)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError("controlled reference member must be a regular non-link file")
        if metadata.st_nlink != 1:
            raise ValueError("controlled reference hardlinks are not accepted")
        if metadata.st_size <= 0 or metadata.st_size > MAX_REFERENCE_MEMBER_BYTES:
            raise ValueError("controlled reference member size is invalid")
        raw_bytes = source.read_bytes()
        if len(raw_bytes) != metadata.st_size:
            raise ValueError("controlled reference member changed during capture")
        after = os.lstat(source)
        if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("controlled reference member changed during capture")
        members.append(
            ControlledReferenceMember(
                source_id=spec["source_id"],
                document_id=spec["document_id"],
                filename=source_path,
                raw_bytes=raw_bytes,
            )
        )
    canonical_manifest = {
        "contract_version": CONTROLLED_REFERENCE_PACK_VERSION,
        "documents": sorted(
            documents,
            key=lambda item: (normalized_identity(item["document_id"]), item["document_id"]),
        ),
    }
    members.sort(key=lambda item: (normalized_identity(item.document_id), item.document_id))
    return ControlledReferenceBundle(
        canonical_manifest_bytes=_canonical_bytes(canonical_manifest),
        members=tuple(members),
    )


def _prepare_controlled_reference_context(
    bundle: ControlledReferenceBundle,
) -> _ControlledReferenceContext:
    """Rebuild the registry from captured bytes, then resolve Inspection links."""

    if type(bundle) is not ControlledReferenceBundle:
        raise TypeError("controlled reference run requires captured raw bundle bytes")
    from .case_builder import (
        _finalize_controlled_references,
        build_document_from_artifact_bytes,
    )

    manifest = _validate_controlled_reference_bundle(bundle)
    specs = {item["document_id"]: item for item in manifest["documents"]}
    members = {item.document_id: item for item in bundle.members}
    if set(specs) != set(members):
        raise ValueError("controlled reference bundle differs from manifest")
    documents: list[dict[str, Any]] = []
    witnesses: dict[str, _ReferenceWitness] = {}
    for document_id in sorted(specs):
        member = members[document_id]
        spec = specs[document_id]
        if member.source_id != spec.get("source_id"):
            raise ValueError("controlled reference member source_id differs from manifest")
        if member.filename != spec.get("source_path"):
            raise ValueError("controlled reference member filename differs from manifest")
        document, _fingerprint, _mapping_config, _evidence = (
            build_document_from_artifact_bytes(
                spec,
                member.raw_bytes,
                filename=member.filename,
            )
        )
        documents.append(document)
        witnesses[document["document_type"]] = _ReferenceWitness(
            source_id=spec["source_id"],
            document_type=document["document_type"],
            document_id=document["document_id"],
            revision=document["revision"],
            filename=member.filename,
            relative_path=member.filename,
            source_hash=document["source_hash"],
            raw_bytes=member.raw_bytes,
        )
    _finalize_controlled_references(documents)
    return _seal_controlled_reference_context(documents, witnesses)


def _mapping_locator(document: Mapping[str, Any], target: str) -> str:
    for entry in document.get("mapping_provenance", []):
        if not isinstance(entry, Mapping) or entry.get("target") != target:
            continue
        source = entry.get("source")
        if isinstance(source, Mapping) and isinstance(source.get("locator"), str):
            return source["locator"]
        sources = entry.get("sources")
        if isinstance(sources, list) and sources:
            first = sources[0]
            if isinstance(first, Mapping) and isinstance(first.get("locator"), str):
                return first["locator"]
    return target


def _seal_controlled_reference_context(
    documents: list[dict[str, Any]],
    witnesses: Mapping[str, _ReferenceWitness],
) -> _ControlledReferenceContext:
    """Seal exact identities already derived from one Builder raw snapshot."""

    if set(witnesses) != {"SOP", "CONTROL_PLAN", "INSPECTION_RECORD"}:
        raise ValueError(
            "controlled reference context requires raw witnesses for Inspection, SOP and Control Plan"
        )
    if any(type(item) is not _ReferenceWitness for item in witnesses.values()):
        raise TypeError("controlled reference witness must be internally constructed")

    approved_by_type: dict[str, dict[str, Any]] = {}
    for document in documents:
        document_type = document.get("document_type")
        if (
            document.get("status") != "APPROVED"
            or document_type not in witnesses
        ):
            continue
        if document_type in approved_by_type:
            raise ValueError(
                f"controlled reference target type is ambiguous: {document_type}"
            )
        approved_by_type[str(document_type)] = document
    inspection = approved_by_type.get("INSPECTION_RECORD")
    if not isinstance(inspection, dict):
        raise ValueError("controlled reference context requires one approved Inspection record")
    if set(approved_by_type) != set(witnesses):
        raise ValueError("controlled reference documents differ from raw witness registry")
    for document_type, document in approved_by_type.items():
        witness = witnesses[document_type]
        expected_metadata = (
            witness.document_type,
            witness.document_id,
            witness.revision,
            witness.source_hash,
        )
        actual_metadata = (
            document.get("document_type"),
            document.get("document_id"),
            document.get("revision"),
            document.get("source_hash"),
        )
        if actual_metadata != expected_metadata:
            raise ValueError(
                f"controlled reference document differs from raw witness: {document_type}"
            )
        source = document.get("source")
        if not isinstance(source, Mapping) or (
            source.get("filename") != witness.filename
            or source.get("relative_path") != witness.relative_path
            or source.get("size_bytes") != len(witness.raw_bytes)
        ):
            raise ValueError(
                f"controlled reference source metadata differs from raw witness: {document_type}"
            )
    registry: dict[str, dict[str, Any]] = {}
    for role in sorted(REFERENCE_ROLES):
        target = approved_by_type.get(role)
        if not isinstance(target, dict):
            raise ValueError(f"controlled reference target is missing: {role}")
        expected = {
            "document_type": role,
            "document_id": target["document_id"],
            "revision": target["revision"],
            "source_hash": target["source_hash"],
        }
        if LOWERCASE_SHA256.fullmatch(target["source_hash"]) is None:
            raise ValueError(f"controlled reference target is not byte-addressed: {role}")
        revision_artifact = target.get("revision_artifact")
        if revision_artifact is not None and (
            not isinstance(revision_artifact, dict)
            or revision_artifact.get("artifact_id") != f"sha256:{target['source_hash']}"
        ):
            raise ValueError(f"controlled reference target artifact identity differs: {role}")
        if isinstance(revision_artifact, dict):
            expected["artifact_id"] = revision_artifact["artifact_id"]
        registry[role] = expected
    return _seal_controlled_reference_context_from_registry(
        inspection,
        registry,
        witnesses,
        {role: approved_by_type[role] for role in REFERENCE_ROLES},
    )


def _seal_controlled_reference_context_from_registry(
    inspection: dict[str, Any],
    registry: Mapping[str, Mapping[str, Any]],
    witnesses: Mapping[str, _ReferenceWitness],
    target_documents: Mapping[str, Mapping[str, Any]],
) -> _ControlledReferenceContext:
    """Seal a composite registry whose identities were each rebuilt from raw bytes."""

    if set(witnesses) != {"SOP", "CONTROL_PLAN", "INSPECTION_RECORD"}:
        raise ValueError("composite controlled reference witnesses are incomplete")
    if set(target_documents) != REFERENCE_ROLES:
        raise ValueError("composite controlled reference target documents are incomplete")
    inspection_witness = witnesses["INSPECTION_RECORD"]
    if type(inspection_witness) is not _ReferenceWitness:
        raise TypeError("Inspection raw witness is not internally constructed")
    if (
        inspection.get("document_type"),
        inspection.get("document_id"),
        inspection.get("revision"),
        inspection.get("source_hash"),
    ) != (
        inspection_witness.document_type,
        inspection_witness.document_id,
        inspection_witness.revision,
        inspection_witness.source_hash,
    ):
        raise ValueError("Inspection document differs from its raw witness")
    inspection_source = inspection.get("source")
    if not isinstance(inspection_source, Mapping) or (
        inspection_source.get("filename") != inspection_witness.filename
        or inspection_source.get("relative_path") != inspection_witness.relative_path
        or inspection_source.get("size_bytes") != len(inspection_witness.raw_bytes)
    ):
        raise ValueError("Inspection source metadata differs from raw witness")
    if inspection.get("reference_contract_version") != CONTROLLED_REFERENCE_CONTRACT_VERSION:
        raise ValueError("Inspection controlled reference contract is missing")
    observed = inspection.get("fields", {}).get("references")
    if not isinstance(observed, dict):
        raise ValueError("Inspection controlled reference observations are missing")

    canonical_references: dict[str, dict[str, str]] = {}
    evidence: dict[str, dict[str, Any]] = {}
    for role in sorted(REFERENCE_ROLES):
        identity = registry.get(role)
        witness = witnesses.get(role)
        target = target_documents.get(role)
        holder_claim = observed.get(role)
        if not isinstance(identity, Mapping):
            raise ValueError(f"controlled reference registry is missing {role}")
        if type(witness) is not _ReferenceWitness:
            raise TypeError(f"controlled reference raw witness is missing: {role}")
        if not isinstance(target, Mapping):
            raise ValueError(f"controlled reference raw-built target is missing: {role}")
        if (
            not isinstance(holder_claim, Mapping)
            or set(holder_claim)
            != {"document_type", "document_id", "revision", "source_hash"}
            or holder_claim.get("document_type") != role
            or LOWERCASE_SHA256.fullmatch(str(holder_claim.get("source_hash", "")))
            is None
        ):
            raise ValueError(
                f"raw Inspection controlled-reference holder claim is invalid: {role}"
            )
        witness_identity = {
            "document_type": witness.document_type,
            "document_id": witness.document_id,
            "revision": witness.revision,
            "source_hash": witness.source_hash,
        }
        if {key: identity.get(key) for key in witness_identity} != witness_identity:
            raise ValueError(f"controlled reference registry differs from raw bytes: {role}")
        if {key: target.get(key) for key in witness_identity} != witness_identity:
            raise ValueError(f"controlled reference target differs from raw bytes: {role}")
        # The authoritative claim belongs to the raw-built Inspection holder.
        # Target witnesses prove the current registry, but must never overwrite
        # an old or mismatching holder claim.  R005 compares both surfaces and
        # therefore produces CONTRADICTED until the Inspection artifact itself
        # is rebuilt with the new ID/revision observation.
        canonical_references[role] = {
            key: str(holder_claim[key])
            for key in ("document_type", "document_id", "revision", "source_hash")
        }
        artifact_id = identity.get("artifact_id")
        if artifact_id is not None and artifact_id != f"sha256:{witness.source_hash}":
            raise ValueError(f"controlled reference artifact differs from raw bytes: {role}")
        evidence[role] = {
            "inspection": {
                "document_id": inspection["document_id"],
                "revision": inspection["revision"],
                "source_hash": inspection["source_hash"],
                "document_id_locator": _mapping_locator(
                    inspection, f"fields.references.{role}.document_id"
                ),
                "revision_locator": _mapping_locator(
                    inspection, f"fields.references.{role}.revision"
                ),
            },
            "target": {
                **canonical_references[role],
                "source_id": witness.source_id,
                "filename": witness.filename,
                "relative_path": witness.relative_path,
                "size_bytes": len(witness.raw_bytes),
                "source_locator": "RAW_BYTES#sha256",
                "artifact_id": artifact_id,
            },
        }
    controlled_documents: list[dict[str, Any]] = []
    for source_document in (
        inspection,
        *(target_documents[role] for role in sorted(REFERENCE_ROLES)),
    ):
        # Sealing immediately serializes these locally owned raw-built
        # documents.  A shallow outer copy is sufficient to replace only the
        # ordering-sensitive provenance list without mutating its source;
        # json.dumps never mutates the shared nested values.  The resulting
        # context retains bytes only, so no source alias escapes this call.
        document = dict(source_document)
        mappings = document.get("mapping_provenance")
        if isinstance(mappings, list):
            document["mapping_provenance"] = sorted(
                mappings,
                key=lambda item: (
                    str(item.get("target", "")) if isinstance(item, Mapping) else "",
                    str(item.get("mapping_kind", ""))
                    if isinstance(item, Mapping)
                    else "",
                ),
            )
        controlled_documents.append(document)
    controlled_documents.sort(
        key=lambda item: (item["document_type"], item["document_id"])
    )
    documents_json = _canonical_bytes(controlled_documents)
    witness_subject = [
        {
            "source_id": item.source_id,
            "document_type": item.document_type,
            "document_id": item.document_id,
            "revision": item.revision,
            "filename": item.filename,
            "relative_path": item.relative_path,
            "source_hash": item.source_hash,
            "size_bytes": len(item.raw_bytes),
        }
        for item in sorted(witnesses.values(), key=lambda item: item.document_type)
    ]
    reference_set_hash = hashlib.sha256(
        b"QualityCI/controlled-reference-set/v1\0"
        + _canonical_bytes(
            {
                "contract_version": CONTROLLED_REFERENCE_CONTRACT_VERSION,
                # Serialize the full raw-built documents once.  The
                # domain-separated digest binds the exact same bytes without
                # a second O(document-size) JSON encoding pass.
                "documents_digest": hashlib.sha256(documents_json).hexdigest(),
                "witnesses": witness_subject,
            }
        )
    ).hexdigest()
    return _ControlledReferenceContext(
        contract_version=CONTROLLED_REFERENCE_CONTRACT_VERSION,
        reference_set_hash=reference_set_hash,
        inspection_document_id=inspection["document_id"],
        documents_json=documents_json,
        references_json=_canonical_bytes(canonical_references),
        evidence_json=_canonical_bytes(evidence),
        witnesses=tuple(witnesses[key] for key in sorted(witnesses)),
        _seal=_CONTEXT_SEAL,
    )


def _is_sealed_reference_context(value: object) -> bool:
    return type(value) is _ControlledReferenceContext and value.is_sealed()
