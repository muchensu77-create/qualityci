from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .approval_subject import (
    APPROVAL_ASSERTION_CONTRACT_VERSION,
    APPROVAL_SUBJECT_CONTRACT_VERSION,
    APPROVAL_USE_POLICY,
    SOURCE_APPROVAL_SUBJECT_CONTRACT_VERSION,
    approval_assertion_hash,
    approval_subject_hash,
    derive_approval_subject,
    validate_approval_assertions,
    validate_approval_assertion_shape,
    validate_approval_subject,
)
from .authorization_records import (
    AUTHORIZATION_RECORD_SET_VERSION,
    SIGNED_AUTHORIZATION_RECORD_SET_VERSION,
    AuthorizationRecordBundle,
    AuthorizationRecordContext,
    AuthorizationRecordMember,
    prepare_authorization_record_context,
)
from .authorization_authenticity import (
    AUTHORIZATION_AUTHENTICITY_PASS,
    AuthorizationAuthenticityContext,
    AuthorizationAuthenticityError,
    AuthorizationTrustSnapshotBundle,
    authorization_authenticity_binding_hash,
    prepare_authorization_authenticity_context,
    require_authenticated_assertion_records,
)
from .case_builder import (
    DERIVED_LOCATOR_CONTRACT_VERSION,
    DOCUMENT_TYPES,
    IDENTICAL_VALUE_AGGREGATION_CONTRACT_VERSION,
    MANIFEST_VERSION,
    MAPPING_CONTRACT_VERSION,
    MAPPING_VALUE_CONVERSION_CONTRACT_VERSION,
    PARSER_CONSUMPTION_PLAN_VERSION,
)
from .case_source_assurance import (
    CASE_SOURCE_BOUND,
    CASE_SOURCE_DERIVED,
    CASE_SOURCE_UNBOUND,
    CASE_SOURCE_LINEAGE_CONTRACT_VERSION,
    CASE_SOURCE_PACK_CONTRACT_VERSION,
    CASE_SOURCE_SET_CONTRACT_VERSION,
    RUN_IDENTITY_VERSION,
    RUN_RESULT_CONTRACT_VERSION,
    CaseMutationBundle,
    CaseSourceBundle,
    CaseSourceCapture,
    CaseSourceError,
    CaseSourceMember,
    CaseSourceSnapshot,
    CaseSourceLineage,
    _CaseSourceContext,
    _derive_case_source_native_replay,
    _derive_case_source_mutation,
    _is_sealed_case_source_context,
    _prepare_case_source_context,
)
from .controlled_references import (
    CONTROLLED_REFERENCE_PACK_VERSION,
    ControlledReferenceBundle,
    ControlledReferenceMember,
    DERIVED_REFERENCE_IDENTITY_CONTRACT_VERSION,
    _ControlledReferenceContext,
    _prepare_controlled_reference_context,
)
from .engine import (
    _evaluate_source_rooted_case,
    legacy_run_result_projection,
    run_case,
    _run_case_with_reference_context,
)
from .loader import (
    CASE_SCHEMA_VERSION,
    CONTROLLED_REFERENCE_CONTRACT_VERSION,
    canonical_hash,
    normalized_identity,
    prepare_case,
    strict_json_loads,
    validate_case,
)
from .ingestion import INGESTION_POLICY_VERSION
from .models import RunResult
from .validation_evidence import (
    VALIDATION_APPROVAL_POLICY_VERSION,
    VALIDATION_ASSURANCE_ATTESTED,
    VALIDATION_EVIDENCE_CONTRACT_VERSION,
    VALIDATION_PARSER_CONTRACT_VERSION,
    ValidationEvidenceBundle,
    ValidationEvidenceMember,
    _ValidationCaseIdentity,
    _ValidationEvidenceContext,
    _prepare_validation_case_identity,
    _prepare_validation_evidence_context,
    validation_evidence_pair_hash,
)
from .revision_artifacts import (
    ARTIFACT_CONTRACT_VERSION,
    ArtifactContext,
    ArtifactMemberBytes,
    RevisionArtifactBundle,
    RevisionArtifactError,
    canonicalize_artifact_manifest,
    prepare_artifact_context,
)
from .rules import RULESET_VERSION
from .workflow import (
    CaseMutationDerivationBundle,
    NativeReplayDerivationBundle,
    NATIVE_RESOLUTION_KEYS,
    REQUIRED_APPROVAL_ROLES,
    ApprovalGateError,
    ReplayResult,
    StatelessApprovalReplayResult,
    apply_approved_resolution,
    replay_with_source_assurance,
    _attest_approved_resolution,
    _approval_assertions_from_bytes,
    _native_resolution_from_bytes,
    _rebuild_prior_case_source_context,
    _replay_one_source_derivation,
    _replay_attested_resolution,
    _resolved_case_from_context,
    _subject_from_context,
    _source_subject_from_context,
    resolution_patch_hash_for_subject,
    validate_native_resolution,
)


REPLAY_ADMISSION_CONTRACT_VERSION = "qualityci-replay-admission-0.2"
_REPLAY_ADMISSION_DOMAIN = b"QualityCI/replay-admission/v1\0"
REPLAY_LEDGER_CONTRACT_VERSION = "qualityci-replay-ledger-0.2"
_REPLAY_LEDGER_DOMAIN = b"QualityCI/replay-ledger/v1\0"
_RESOLUTION_RECORD_DOMAIN = b"QualityCI/resolution-record/v1\0"
REPLAY_VALIDATION_BINDING_CONTRACT_VERSION = (
    "qualityci-replay-validation-binding-0.1"
)
_REPLAY_VALIDATION_BINDING_DOMAIN = b"QualityCI/replay-validation-binding/v1\0"
A05_REPLAY_ADMISSION_CONTRACT_VERSION = "qualityci-replay-admission-0.3"
A05_REPLAY_LEDGER_CONTRACT_VERSION = "qualityci-replay-ledger-0.3"
A06_REPLAY_ADMISSION_CONTRACT_VERSION = "qualityci-replay-admission-0.4"
A06_REPLAY_LEDGER_CONTRACT_VERSION = "qualityci-replay-ledger-0.4"
A08_REPLAY_ADMISSION_CONTRACT_VERSION = "qualityci-replay-admission-0.5"
A08_REPLAY_LEDGER_CONTRACT_VERSION = "qualityci-replay-ledger-0.5"
REPLAY_APPROVAL_EXPECTATION_CONTRACT_VERSION = (
    "qualityci-replay-approval-expectation-0.1"
)
APPROVAL_CONSUMPTION_CONTRACT_VERSION = "qualityci-approval-consumption-0.1"
A06_REPLAY_APPROVAL_EXPECTATION_CONTRACT_VERSION = (
    "qualityci-replay-approval-expectation-0.2"
)
A06_APPROVAL_CONSUMPTION_CONTRACT_VERSION = "qualityci-approval-consumption-0.2"
_A05_REPLAY_ADMISSION_DOMAIN = b"QualityCI/replay-admission/v2\0"
_A05_REPLAY_LEDGER_DOMAIN = b"QualityCI/replay-ledger/v2\0"
_A06_REPLAY_ADMISSION_DOMAIN = b"QualityCI/replay-admission/v3\0"
_A06_REPLAY_LEDGER_DOMAIN = b"QualityCI/replay-ledger/v3\0"
_A08_REPLAY_ADMISSION_DOMAIN = b"QualityCI/replay-admission/v4\0"
_A08_REPLAY_LEDGER_DOMAIN = b"QualityCI/replay-ledger/v4\0"
_APPROVAL_CONSUMPTION_DOMAIN = b"QualityCI/approval-consumption/v1\0"
_A06_APPROVAL_CONSUMPTION_DOMAIN = b"QualityCI/approval-consumption/v2\0"
_REPLAY_APPROVAL_EXPECTATION_DOMAIN = (
    b"QualityCI/replay-approval-expectation/v1\0"
)
_A06_REPLAY_APPROVAL_EXPECTATION_DOMAIN = (
    b"QualityCI/replay-approval-expectation/v2\0"
)
_APPROVAL_ASSERTION_SET_DOMAIN = b"QualityCI/approval-assertion-set/v1\0"

_RUN_PROFILE_LEGACY_V3 = "LEGACY_V3"
_RUN_PROFILE_CURRENT_V4 = "CURRENT_V4"
_CASE_SOURCE_ASSURANCE_KEYS = (
    "case_source_assurance_state",
    "case_source_pack_contract_version",
    "case_source_set_contract_version",
    "case_source_set_hash",
    "case_source_binding_hash",
    "case_source_lineage_contract_version",
    "case_source_lineage_hash",
)


def _stored_run_payload_profile(payload: dict[str, Any]) -> str | None:
    """Dispatch a stored Run payload only from its exact wire discriminators."""

    has_contract = "run_result_contract_version" in payload
    has_identity = "run_identity_version" in payload
    if not has_contract and not has_identity:
        return _RUN_PROFILE_LEGACY_V3
    if not has_contract or not has_identity:
        return None
    if (
        payload["run_result_contract_version"]
        != RUN_RESULT_CONTRACT_VERSION
        or payload["run_identity_version"] != RUN_IDENTITY_VERSION
        or payload.get("case_source_assurance_state")
        not in {CASE_SOURCE_UNBOUND, CASE_SOURCE_BOUND, CASE_SOURCE_DERIVED}
    ):
        return None
    return _RUN_PROFILE_CURRENT_V4
BASELINE_APPROVAL_BINDING_CONTRACT_VERSION = (
    "qualityci-baseline-approval-binding-0.1"
)
A06_BASELINE_APPROVAL_BINDING_CONTRACT_VERSION = (
    "qualityci-baseline-approval-binding-0.2"
)
_BASELINE_APPROVAL_BINDING_DOMAIN = b"QualityCI/baseline-approval-binding/v1\0"
_A06_BASELINE_APPROVAL_BINDING_DOMAIN = (
    b"QualityCI/baseline-approval-binding/v2\0"
)
REPLAY_AUTHORIZATION_AUTHENTICITY_BINDING_CONTRACT_VERSION = (
    "qualityci-replay-authorization-authenticity-binding-0.1"
)
_REPLAY_AUTHORIZATION_AUTHENTICITY_BINDING_DOMAIN = (
    b"QualityCI/replay-authorization-authenticity-binding/v1\0"
)
_A06_AUTHENTICITY_REF_KEYS = (
    "authorization_record_set_hash",
    "authorization_record_set_contract_version",
    "authorization_authenticity_state",
    "authorization_authenticity_context_hash",
    "authorization_authenticity_binding_hash",
    "authorization_trust_snapshot_hash",
    "authorization_trust_snapshot_contract_version",
    "authorization_trust_policy_hash",
    "authorization_trust_policy_version",
)

A08_STORE_FEATURE_PROFILE_VERSION = "qualityci-store-feature-a08-0.1"
STORE_FEATURE_LEGACY_PRE_A08 = "LEGACY_PRE_A08"
STORE_FEATURE_A08_0_1 = "A08_0_1"
STORE_FEATURE_PARTIAL_OR_UNKNOWN = "PARTIAL_OR_UNKNOWN"
A08_SCHEMA_MIGRATION_REQUIRED = "A08_SCHEMA_MIGRATION_REQUIRED"
A08_SCHEMA_PARTIAL_OR_UNKNOWN = "A08_SCHEMA_PARTIAL_OR_UNKNOWN"

_A08_TABLE_DDL = (
    (
        "case_source_sets",
        """
        CREATE TABLE case_source_sets (
          source_set_hash TEXT PRIMARY KEY
            CHECK(length(source_set_hash)=64
              AND source_set_hash NOT GLOB '*[^0-9a-f]*'),
          source_set_contract_version TEXT NOT NULL
            CHECK(source_set_contract_version='qualityci-case-source-set-0.1'),
          source_pack_contract_version TEXT NOT NULL
            CHECK(source_pack_contract_version='qualityci-case-source-pack-0.1'),
          manifest_source_hash TEXT NOT NULL
            CHECK(length(manifest_source_hash)=64
              AND manifest_source_hash NOT GLOB '*[^0-9a-f]*'),
          manifest_size_bytes INTEGER NOT NULL CHECK(manifest_size_bytes>=0),
          root_case_hash TEXT NOT NULL
            CHECK(length(root_case_hash)=64
              AND root_case_hash NOT GLOB '*[^0-9a-f]*'),
          root_binding_hash TEXT NOT NULL UNIQUE
            CHECK(length(root_binding_hash)=64
              AND root_binding_hash NOT GLOB '*[^0-9a-f]*'),
          case_schema_version TEXT NOT NULL
            CHECK(case_schema_version='qualityci-case-0.4'),
          builder_manifest_version TEXT NOT NULL
            CHECK(builder_manifest_version='qualityci-case-builder-0.4'),
          ingestion_policy_version TEXT NOT NULL
            CHECK(ingestion_policy_version='qualityci-ingestion-policy-0.2'),
          parser_consumption_plan_version TEXT NOT NULL
            CHECK(parser_consumption_plan_version='qualityci-parser-consumption-plan-0.1'),
          mapping_contract_version TEXT NOT NULL
            CHECK(mapping_contract_version='qualityci-explicit-mapping-0.5'),
          derived_locator_contract_version TEXT NOT NULL
            CHECK(derived_locator_contract_version='qualityci-derived-locator-0.1'),
          identical_value_aggregation_contract_version TEXT NOT NULL
            CHECK(identical_value_aggregation_contract_version=
              'qualityci-identical-value-aggregate-0.1'),
          mapping_value_conversion_contract_version TEXT NOT NULL
            CHECK(mapping_value_conversion_contract_version=
              'qualityci-mapping-value-conversion-0.1'),
          derived_reference_identity_contract_version TEXT NOT NULL
            CHECK(derived_reference_identity_contract_version=
              'qualityci-derived-reference-identity-0.1'),
          controlled_reference_contract_version TEXT NOT NULL
            CHECK(controlled_reference_contract_version=
              'qualityci-controlled-reference-0.1'),
          canonical_payload_json TEXT NOT NULL,
          UNIQUE(source_set_hash, root_binding_hash),
          FOREIGN KEY(manifest_source_hash)
            REFERENCES artifact_blobs(source_hash)
        )
        """,
    ),
    (
        "case_source_members",
        """
        CREATE TABLE case_source_members (
          source_set_hash TEXT NOT NULL,
          member_index INTEGER NOT NULL CHECK(member_index BETWEEN 0 AND 4),
          document_type TEXT NOT NULL CHECK(document_type IN
            ('PROCESS_FLOW','PFMEA','CONTROL_PLAN','SOP','INSPECTION_RECORD')),
          source_id TEXT NOT NULL CHECK(length(trim(source_id))>0),
          source_path TEXT NOT NULL CHECK(length(trim(source_path))>0),
          source_kind TEXT NOT NULL CHECK(source_kind IN ('CSV','XLSX','DOCX')),
          size_bytes INTEGER NOT NULL CHECK(size_bytes>=0),
          source_hash TEXT NOT NULL
            CHECK(length(source_hash)=64
              AND source_hash NOT GLOB '*[^0-9a-f]*'),
          declared_table_selector_json TEXT,
          canonical_payload_json TEXT NOT NULL,
          PRIMARY KEY(source_set_hash, member_index),
          UNIQUE(source_set_hash, document_type),
          UNIQUE(source_set_hash, source_id),
          UNIQUE(source_set_hash, source_path),
          UNIQUE(source_set_hash, source_hash),
          FOREIGN KEY(source_set_hash)
            REFERENCES case_source_sets(source_set_hash),
          FOREIGN KEY(source_hash)
            REFERENCES artifact_blobs(source_hash)
        )
        """,
    ),
    (
        "case_lineage_bindings",
        """
        CREATE TABLE case_lineage_bindings (
          lineage_hash TEXT PRIMARY KEY
            CHECK(length(lineage_hash)=64
              AND lineage_hash NOT GLOB '*[^0-9a-f]*'),
          lineage_contract_version TEXT NOT NULL
            CHECK(lineage_contract_version='qualityci-case-source-lineage-0.1'),
          root_binding_hash TEXT NOT NULL,
          parent_lineage_hash TEXT,
          input_case_hash TEXT NOT NULL
            CHECK(length(input_case_hash)=64
              AND input_case_hash NOT GLOB '*[^0-9a-f]*'),
          output_case_hash TEXT NOT NULL
            CHECK(length(output_case_hash)=64
              AND output_case_hash NOT GLOB '*[^0-9a-f]*'),
          operation_kind TEXT NOT NULL
            CHECK(operation_kind IN ('MUTATION','NATIVE_REPLAY')),
          operation_contract_version TEXT NOT NULL,
          operation_material_hash TEXT NOT NULL
            CHECK(length(operation_material_hash)=64
              AND operation_material_hash NOT GLOB '*[^0-9a-f]*'),
          operation_blob_source_hash TEXT NOT NULL
            CHECK(length(operation_blob_source_hash)=64
              AND operation_blob_source_hash NOT GLOB '*[^0-9a-f]*'),
          operation_blob_size_bytes INTEGER NOT NULL
            CHECK(operation_blob_size_bytes>=0),
          operation_material_source_hash TEXT NOT NULL
            CHECK(length(operation_material_source_hash)=64
              AND operation_material_source_hash NOT GLOB '*[^0-9a-f]*'),
          operation_material_size_bytes INTEGER NOT NULL
            CHECK(operation_material_size_bytes>=0),
          canonical_payload_json TEXT NOT NULL,
          CHECK(parent_lineage_hash IS NULL OR parent_lineage_hash<>lineage_hash),
          CHECK(
            (operation_kind='MUTATION' AND operation_contract_version=
              'qualityci-case-source-mutation-operation-0.1')
            OR
            (operation_kind='NATIVE_REPLAY' AND operation_contract_version=
              'qualityci-case-source-native-replay-operation-0.1')
          ),
          UNIQUE(lineage_hash, root_binding_hash),
          FOREIGN KEY(root_binding_hash)
            REFERENCES case_source_sets(root_binding_hash),
          FOREIGN KEY(parent_lineage_hash, root_binding_hash)
            REFERENCES case_lineage_bindings(lineage_hash, root_binding_hash),
          FOREIGN KEY(operation_blob_source_hash)
            REFERENCES artifact_blobs(source_hash),
          FOREIGN KEY(operation_material_source_hash)
            REFERENCES artifact_blobs(source_hash)
        )
        """,
    ),
    (
        "run_case_source_sets",
        """
        CREATE TABLE run_case_source_sets (
          run_id TEXT PRIMARY KEY
            CHECK(length(run_id)=16 AND run_id NOT GLOB '*[^0-9a-f]*'),
          case_source_assurance_state TEXT NOT NULL CHECK(
            case_source_assurance_state IN
              ('UNBOUND_SERIALIZED_CASE','BOUND_RAW_SOURCE_CASE',
               'SOURCE_ROOTED_DERIVATION')
          ),
          source_set_hash TEXT,
          root_binding_hash TEXT,
          terminal_lineage_hash TEXT,
          canonical_payload_json TEXT NOT NULL,
          CHECK(
            (case_source_assurance_state='UNBOUND_SERIALIZED_CASE'
              AND source_set_hash IS NULL
              AND root_binding_hash IS NULL
              AND terminal_lineage_hash IS NULL)
            OR
            (case_source_assurance_state='BOUND_RAW_SOURCE_CASE'
              AND source_set_hash IS NOT NULL
              AND root_binding_hash IS NOT NULL
              AND terminal_lineage_hash IS NULL)
            OR
            (case_source_assurance_state='SOURCE_ROOTED_DERIVATION'
              AND source_set_hash IS NOT NULL
              AND root_binding_hash IS NOT NULL
              AND terminal_lineage_hash IS NOT NULL)
          ),
          FOREIGN KEY(run_id) REFERENCES runs(run_id),
          FOREIGN KEY(source_set_hash, root_binding_hash)
            REFERENCES case_source_sets(source_set_hash, root_binding_hash),
          FOREIGN KEY(terminal_lineage_hash, root_binding_hash)
            REFERENCES case_lineage_bindings(lineage_hash, root_binding_hash)
        )
        """,
    ),
)

A08_REQUIRED_TABLES = frozenset(name for name, _statement in _A08_TABLE_DDL)


def _normalized_schema_sql(value: str | None) -> str:
    if not isinstance(value, str):
        return ""
    normalized = re.sub(
        r"\bCONSTRAINT\s+(?:\"[^\"]+\"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][A-Za-z0-9_]*)\s+",
        "",
        value,
        flags=re.IGNORECASE,
    )
    normalized = re.sub(
        r"\bCREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\b",
        "CREATE TABLE",
        normalized,
        flags=re.IGNORECASE,
    )
    normalized = normalized.strip().rstrip(";")
    parts = re.split(r"('(?:''|[^'])*')", normalized)
    return "".join(
        part if index % 2 else re.sub(r"\s+", "", part.casefold())
        for index, part in enumerate(parts)
    )


def _table_feature_signature(
    connection: sqlite3.Connection,
    table: str,
) -> tuple[Any, ...]:
    columns = tuple(
        (
            int(row[0]),
            str(row[1]),
            str(row[2]).upper(),
            int(row[3]),
            row[4],
            int(row[5]),
        )
        for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    )

    foreign_key_rows = connection.execute(
        f'PRAGMA foreign_key_list("{table}")'
    ).fetchall()
    foreign_key_groups: dict[int, list[tuple[Any, ...]]] = {}
    for row in foreign_key_rows:
        foreign_key_groups.setdefault(int(row[0]), []).append(
            (
                int(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]),
                str(row[6]),
                str(row[7]),
            )
        )
    foreign_keys = tuple(
        sorted(
            tuple(sorted(rows, key=lambda item: item[0]))
            for rows in foreign_key_groups.values()
        )
    )

    indexes: list[tuple[Any, ...]] = []
    for row in connection.execute(f'PRAGMA index_list("{table}")').fetchall():
        index_name = str(row[1])
        index_columns = tuple(
            str(item[2])
            for item in connection.execute(
                f'PRAGMA index_info("{index_name}")'
            ).fetchall()
        )
        indexes.append(
            (
                int(row[2]),
                str(row[3]),
                int(row[4]),
                index_columns,
            )
        )
    indexes.sort()

    schema_row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    schema_sql = _normalized_schema_sql(schema_row[0] if schema_row else None)
    return columns, foreign_keys, tuple(indexes), schema_sql


@lru_cache(maxsize=1)
def _expected_a08_feature_signatures() -> tuple[tuple[str, tuple[Any, ...]], ...]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        for _name, statement in _A08_TABLE_DDL:
            connection.execute(statement)
        return tuple(
            (name, _table_feature_signature(connection, name))
            for name, _statement in _A08_TABLE_DDL
        )
    finally:
        connection.close()


@dataclass(frozen=True)
class ReplayAdmission:
    """Content-addressed record of one independently reproducible replay."""

    replay_admission_hash: str
    canonical_payload_bytes: bytes

    def to_dict(self) -> dict[str, Any]:
        value = strict_json_loads(self.canonical_payload_bytes.decode("utf-8"))
        if not isinstance(value, dict):
            raise StoreIntegrityError("replay admission payload is not an object")
        return value


@dataclass(frozen=True)
class _NativeApprovalPersistence:
    """Exact native inputs carried through the single SQLite transaction."""

    subject: dict[str, Any]
    assertions: tuple[dict[str, Any], ...]
    authorization_bundle: AuthorizationRecordBundle
    authorization_context: AuthorizationRecordContext
    authorization_trust_bundle: AuthorizationTrustSnapshotBundle | None = None
    authenticity_context: AuthorizationAuthenticityContext | None = None
    a06_refs: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class _A08NativeStepPersistence:
    """One call-local native derivation rebuilt only from exact raw carriers."""

    before_context: _CaseSourceContext
    after_context: _CaseSourceContext
    bundle: NativeReplayDerivationBundle
    result: StatelessApprovalReplayResult


@dataclass(frozen=True)
class _A08DerivationPersistence:
    """One complete caller- or Store-owned ordered raw derivation closure."""

    root_bundle: CaseSourceBundle
    derivations: tuple[Any, ...]
    root_context: _CaseSourceContext
    terminal_context: _CaseSourceContext
    native_steps: tuple[_A08NativeStepPersistence, ...]
    reference_bundles: tuple[ControlledReferenceBundle, ...]


@dataclass(frozen=True)
class _A08SourceReplayPersistence:
    """Private complete A08 closure passed into the one Store transaction."""

    root_bundle: CaseSourceBundle
    prior_derivations: tuple[Any, ...]
    current_replay: NativeReplayDerivationBundle
    before_context: _CaseSourceContext
    after_context: _CaseSourceContext
    native_steps: tuple[_A08NativeStepPersistence, ...]
    reference_bundles: tuple[ControlledReferenceBundle, ...]


_NATIVE_STORE_SEAL = object()

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


def _native_subject_from_legacy_projection(
    resolution: dict[str, Any],
    legacy_projection: dict[str, Any],
    *,
    execution_nonce: str,
) -> dict[str, Any]:
    """Derive A05 identity without reopening the captured artifact bytes."""

    return derive_approval_subject(
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


def _json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        allow_nan=False,
    )


def _fingerprint(value: Any) -> str:
    def audit_value(item: Any) -> Any:
        if type(item) is bytes:
            return {
                "$bytes_sha256": hashlib.sha256(item).hexdigest(),
                "$size_bytes": len(item),
            }
        if isinstance(item, dict):
            return {key: audit_value(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [audit_value(child) for child in item]
        return item

    return canonical_hash(audit_value(value))


def _exact_cache_value(value: Any) -> tuple[Any, ...]:
    """Return a hashable, lossless projection for call-local verification caches."""

    if type(value) is dict:
        return (
            "dict",
            tuple(
                (key, _exact_cache_value(value[key]))
                for key in sorted(value)
            ),
        )
    if type(value) is list:
        return ("list", tuple(_exact_cache_value(item) for item in value))
    if type(value) is tuple:
        return ("tuple", tuple(_exact_cache_value(item) for item in value))
    if type(value) is bytes:
        return ("bytes", value)
    if value is None:
        return ("none",)
    if type(value) in {str, int, float, bool}:
        return (type(value).__name__, value)
    raise TypeError("verification cache values require exact JSON/bytes types")


def _is_exact_json_value(value: Any) -> bool:
    """Return whether a value graph contains only exact JSON runtime types."""

    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                return False
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
        elif item is None or type(item) in {str, int, float, bool}:
            continue
        else:
            return False
    return True


def _domain_hash(domain: bytes, payload: bytes) -> str:
    return hashlib.sha256(domain + payload).hexdigest()


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_lower_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length or value != value.lower():
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _native_a06_refs(native: _NativeApprovalPersistence) -> dict[str, str]:
    refs = dict(native.a06_refs)
    if (
        len(refs) != len(native.a06_refs)
        or set(refs) != set(_A06_AUTHENTICITY_REF_KEYS)
        or any(type(value) is not str or not value for value in refs.values())
        or refs["authorization_authenticity_state"] != "PASS"
    ):
        raise StoreIntegrityError(
            "native A06 persistence requires exact PASS authenticity refs"
        )
    for field in (
        "authorization_record_set_hash",
        "authorization_authenticity_context_hash",
        "authorization_authenticity_binding_hash",
        "authorization_trust_snapshot_hash",
        "authorization_trust_policy_hash",
    ):
        if not _is_lower_hex(refs[field], 64):
            raise StoreIntegrityError(
                f"native A06 persistence has invalid {field}"
            )
    return refs


def _a06_refs_from_payload(payload: dict[str, Any]) -> dict[str, str]:
    try:
        refs = {key: payload[key] for key in _A06_AUTHENTICITY_REF_KEYS}
    except (KeyError, TypeError) as error:
        raise StoreIntegrityError(
            "stored A06 entity is missing authenticity references"
        ) from error
    if (
        any(type(value) is not str or not value for value in refs.values())
        or refs["authorization_authenticity_state"]
        != AUTHORIZATION_AUTHENTICITY_PASS
    ):
        raise StoreIntegrityError(
            "stored A06 entity has invalid authenticity references"
        )
    for field in (
        "authorization_record_set_hash",
        "authorization_authenticity_context_hash",
        "authorization_authenticity_binding_hash",
        "authorization_trust_snapshot_hash",
        "authorization_trust_policy_hash",
    ):
        if not _is_lower_hex(refs[field], 64):
            raise StoreIntegrityError(f"stored A06 entity has invalid {field}")
    return refs


def _resolution_operations_are_valid(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for operation in value:
        if not isinstance(operation, dict):
            return False
        if operation.get("target", "document") != "document":
            return False
        if operation.get("op") not in {"set", "delete"}:
            return False
        if not _is_nonempty_string(operation.get("document_id")):
            return False
        if not isinstance(operation.get("path"), str) or not operation["path"]:
            return False
        if operation["op"] == "set" and "value" not in operation:
            return False
    return True


class StoreIntegrityError(ValueError):
    """Raised when an existing primary key carries different immutable content."""


class QualityCIStore:
    """Local store whose audit chain is cross-checked against entity payloads.

    This detects accidental or unsophisticated local tampering. It is not a
    substitute for an externally signed or remotely anchored audit log.
    """

    REQUIRED_TABLES = frozenset(
        {
            "cases",
            "runs",
            "run_reference_sets",
            "run_validation_sets",
            "approvals",
            "baselines",
            "artifact_blobs",
            "artifact_sets",
            "artifact_set_members",
            "controlled_reference_sets",
            "controlled_reference_members",
            "validation_evidence_sets",
            "validation_evidence_members",
            "replay_admissions",
            "replay_ledger",
            "replay_validation_bindings",
            "authorization_record_sets",
            "authorization_record_members",
            "authorization_trust_snapshots",
            "replay_authorization_authenticity_bindings",
            "approval_subjects",
            "approval_assertions",
            "approval_consumptions",
            "replay_approval_expectations",
            "baseline_approval_bindings",
            "audit_events",
        }
    )

    def __init__(self, path: str | Path = ":memory:", *, readonly: bool = False) -> None:
        self._readonly = readonly
        created_new = False
        if readonly:
            if str(path) == ":memory:":
                raise ValueError("readonly store requires a database path")
            encoded = quote(str(Path(path).resolve()), safe="/")
            self.connection = sqlite3.connect(f"file:{encoded}?mode=ro", uri=True)
        else:
            self.connection = sqlite3.connect(str(path))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        if readonly:
            self.connection.execute("PRAGMA query_only = ON")
        else:
            rows = self.connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            if not rows:
                self._create_schema()
                created_new = True

        profile = self.feature_profile()
        if profile == STORE_FEATURE_PARTIAL_OR_UNKNOWN:
            self.connection.close()
            raise StoreIntegrityError(A08_SCHEMA_PARTIAL_OR_UNKNOWN)
        if created_new and profile != STORE_FEATURE_A08_0_1:
            self.connection.close()
            raise StoreIntegrityError(A08_SCHEMA_PARTIAL_OR_UNKNOWN)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "QualityCIStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
              case_id TEXT NOT NULL,
              case_hash TEXT NOT NULL,
              synthetic INTEGER NOT NULL CHECK (synthetic IN (0, 1)),
              payload_json TEXT NOT NULL,
              PRIMARY KEY (case_id, case_hash)
            );
            CREATE TABLE IF NOT EXISTS runs (
              run_id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL,
              status TEXT NOT NULL,
              ruleset_version TEXT NOT NULL,
              payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS run_reference_sets (
              run_id TEXT PRIMARY KEY,
              reference_set_hash TEXT NOT NULL,
              FOREIGN KEY (run_id) REFERENCES runs(run_id),
              FOREIGN KEY (reference_set_hash)
                REFERENCES controlled_reference_sets(reference_set_hash)
            );
            CREATE TABLE IF NOT EXISTS run_validation_sets (
              run_id TEXT PRIMARY KEY,
              evidence_set_hash TEXT NOT NULL,
              FOREIGN KEY (run_id) REFERENCES runs(run_id),
              FOREIGN KEY (evidence_set_hash)
                REFERENCES validation_evidence_sets(evidence_set_hash)
            );
            CREATE TABLE IF NOT EXISTS approvals (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              resolution_id TEXT NOT NULL,
              case_id TEXT NOT NULL,
              event_id TEXT NOT NULL,
              event_revision TEXT NOT NULL,
              approved_case_hash TEXT NOT NULL,
              approved_patch_hash TEXT NOT NULL,
              role TEXT NOT NULL,
              decision TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              UNIQUE(resolution_id, case_id, event_id, event_revision, approved_case_hash, role)
            );
            CREATE TABLE IF NOT EXISTS baselines (
              baseline_id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL,
              source_run_id TEXT NOT NULL,
              payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifact_blobs (
              source_hash TEXT PRIMARY KEY,
              size_bytes INTEGER NOT NULL,
              raw_bytes BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifact_sets (
              artifact_set_hash TEXT PRIMARY KEY,
              replacement_set_id TEXT NOT NULL,
              manifest_bytes BLOB NOT NULL,
              controlled_reference_set_hash TEXT NOT NULL,
              resolved_reference_set_hash TEXT NOT NULL,
              reference_contract_version TEXT NOT NULL,
              artifact_contract_version TEXT NOT NULL,
              case_schema_version TEXT NOT NULL,
              parser_contract_version TEXT NOT NULL,
              mapping_contract_version TEXT NOT NULL,
              security_root_policy_version TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifact_set_members (
              artifact_set_hash TEXT NOT NULL,
              document_id TEXT NOT NULL,
              source_id TEXT NOT NULL,
              filename TEXT NOT NULL,
              source_hash TEXT NOT NULL,
              declared_format TEXT NOT NULL,
              detected_format TEXT NOT NULL,
              supersedes_json TEXT NOT NULL,
              PRIMARY KEY (artifact_set_hash, document_id),
              FOREIGN KEY (artifact_set_hash) REFERENCES artifact_sets(artifact_set_hash),
              FOREIGN KEY (source_hash) REFERENCES artifact_blobs(source_hash)
            );
            CREATE TABLE IF NOT EXISTS controlled_reference_sets (
              reference_set_hash TEXT PRIMARY KEY,
              contract_version TEXT NOT NULL,
              manifest_bytes BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS controlled_reference_members (
              reference_set_hash TEXT NOT NULL,
              document_id TEXT NOT NULL,
              document_type TEXT NOT NULL,
              revision TEXT NOT NULL,
              source_id TEXT NOT NULL,
              filename TEXT NOT NULL,
              source_hash TEXT NOT NULL,
              PRIMARY KEY (reference_set_hash, document_id),
              FOREIGN KEY (reference_set_hash)
                REFERENCES controlled_reference_sets(reference_set_hash),
              FOREIGN KEY (source_hash) REFERENCES artifact_blobs(source_hash)
            );
            CREATE TABLE IF NOT EXISTS validation_evidence_sets (
              evidence_set_hash TEXT PRIMARY KEY,
              phase TEXT NOT NULL CHECK (phase IN ('SOURCE','RESOLVED')),
              contract_version TEXT NOT NULL,
              parser_contract_version TEXT NOT NULL,
              manifest_bytes BLOB NOT NULL,
              case_subject_hash TEXT NOT NULL,
              scope_digest TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS validation_evidence_members (
              evidence_set_hash TEXT NOT NULL,
              evidence_id TEXT NOT NULL,
              source_id TEXT NOT NULL,
              filename TEXT NOT NULL,
              source_hash TEXT NOT NULL,
              PRIMARY KEY (evidence_set_hash, evidence_id),
              FOREIGN KEY (evidence_set_hash)
                REFERENCES validation_evidence_sets(evidence_set_hash),
              FOREIGN KEY (source_hash) REFERENCES artifact_blobs(source_hash)
            );
            CREATE TABLE IF NOT EXISTS replay_admissions (
              replay_admission_hash TEXT PRIMARY KEY,
              resolution_id TEXT NOT NULL,
              artifact_set_hash TEXT NOT NULL,
              approved_case_hash TEXT NOT NULL,
              resolution_json TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              UNIQUE (resolution_id, artifact_set_hash, approved_case_hash)
            );
            CREATE TABLE IF NOT EXISTS replay_ledger (
              replay_ledger_hash TEXT PRIMARY KEY,
              replay_admission_hash TEXT NOT NULL UNIQUE,
              consumption_hash TEXT UNIQUE,
              resolution_id TEXT NOT NULL,
              artifact_set_hash TEXT NOT NULL,
              approved_case_hash TEXT NOT NULL,
              after_run_id TEXT NOT NULL UNIQUE,
              payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS replay_validation_bindings (
              validation_binding_hash TEXT PRIMARY KEY,
              resolution_id TEXT NOT NULL,
              source_case_hash TEXT NOT NULL,
              after_case_hash TEXT NOT NULL UNIQUE,
              after_run_id TEXT NOT NULL UNIQUE,
              source_evidence_set_hash TEXT NOT NULL,
              resolved_evidence_set_hash TEXT NOT NULL,
              evidence_pair_hash TEXT NOT NULL UNIQUE,
              replay_admission_hash TEXT NOT NULL UNIQUE,
              payload_json TEXT NOT NULL,
              FOREIGN KEY (source_evidence_set_hash)
                REFERENCES validation_evidence_sets(evidence_set_hash),
              FOREIGN KEY (resolved_evidence_set_hash)
                REFERENCES validation_evidence_sets(evidence_set_hash),
              FOREIGN KEY (replay_admission_hash)
                REFERENCES replay_admissions(replay_admission_hash)
            );
            CREATE TABLE IF NOT EXISTS authorization_record_sets (
              record_set_hash TEXT PRIMARY KEY,
              contract_version TEXT NOT NULL,
              bundle_id TEXT NOT NULL UNIQUE,
              normalized_bundle_id TEXT NOT NULL UNIQUE,
              manifest_bytes BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS authorization_record_members (
              record_set_hash TEXT NOT NULL,
              record_id TEXT NOT NULL,
              normalized_record_id TEXT NOT NULL,
              source_path TEXT NOT NULL,
              normalized_source_path TEXT NOT NULL,
              content_hash TEXT NOT NULL,
              size_bytes INTEGER NOT NULL,
              raw_bytes BLOB NOT NULL,
              PRIMARY KEY (record_set_hash, record_id),
              UNIQUE (record_set_hash, normalized_record_id),
              UNIQUE (record_set_hash, normalized_source_path),
              FOREIGN KEY (record_set_hash)
                REFERENCES authorization_record_sets(record_set_hash)
            );
            CREATE TABLE IF NOT EXISTS authorization_trust_snapshots (
              trust_snapshot_hash TEXT PRIMARY KEY,
              contract_version TEXT NOT NULL,
              trust_policy_hash TEXT NOT NULL,
              trust_policy_version TEXT NOT NULL,
              snapshot_bytes BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_subjects (
              approval_subject_hash TEXT PRIMARY KEY,
              contract_version TEXT NOT NULL,
              resolution_id TEXT NOT NULL,
              execution_nonce TEXT NOT NULL UNIQUE,
              payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_assertions (
              assertion_hash TEXT PRIMARY KEY,
              approval_subject_hash TEXT NOT NULL,
              approval_id TEXT NOT NULL UNIQUE,
              normalized_approval_id TEXT NOT NULL UNIQUE,
              role_claim TEXT NOT NULL,
              authorization_record_set_hash TEXT NOT NULL,
              authorization_record_id TEXT NOT NULL,
              authorization_record_hash TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              UNIQUE (approval_subject_hash, role_claim),
              FOREIGN KEY (approval_subject_hash)
                REFERENCES approval_subjects(approval_subject_hash),
              FOREIGN KEY (authorization_record_set_hash, authorization_record_id)
                REFERENCES authorization_record_members(record_set_hash, record_id)
            );
            CREATE TABLE IF NOT EXISTS approval_consumptions (
              consumption_hash TEXT PRIMARY KEY,
              approval_subject_hash TEXT NOT NULL UNIQUE,
              assertion_set_hash TEXT NOT NULL UNIQUE,
              authorization_record_set_hash TEXT NOT NULL,
              execution_nonce TEXT NOT NULL UNIQUE,
              replay_admission_hash TEXT NOT NULL UNIQUE,
              after_run_id TEXT NOT NULL UNIQUE,
              payload_json TEXT NOT NULL,
              FOREIGN KEY (approval_subject_hash)
                REFERENCES approval_subjects(approval_subject_hash),
              FOREIGN KEY (authorization_record_set_hash)
                REFERENCES authorization_record_sets(record_set_hash),
              FOREIGN KEY (replay_admission_hash)
                REFERENCES replay_admissions(replay_admission_hash)
            );
            CREATE TABLE IF NOT EXISTS replay_approval_expectations (
              expectation_hash TEXT PRIMARY KEY,
              resolution_id TEXT NOT NULL,
              after_case_hash TEXT NOT NULL UNIQUE,
              after_run_id TEXT NOT NULL UNIQUE,
              artifact_set_hash TEXT NOT NULL,
              approval_subject_hash TEXT NOT NULL UNIQUE,
              assertion_set_hash TEXT NOT NULL UNIQUE,
              authorization_record_set_hash TEXT NOT NULL,
              consumption_hash TEXT NOT NULL UNIQUE,
              replay_admission_hash TEXT NOT NULL UNIQUE,
              baseline_id TEXT,
              baseline_binding_hash TEXT,
              payload_json TEXT NOT NULL,
              FOREIGN KEY (approval_subject_hash)
                REFERENCES approval_subjects(approval_subject_hash),
              FOREIGN KEY (authorization_record_set_hash)
                REFERENCES authorization_record_sets(record_set_hash),
              FOREIGN KEY (consumption_hash)
                REFERENCES approval_consumptions(consumption_hash),
              FOREIGN KEY (replay_admission_hash)
                REFERENCES replay_admissions(replay_admission_hash)
            );
            CREATE TABLE IF NOT EXISTS baseline_approval_bindings (
              baseline_binding_hash TEXT PRIMARY KEY,
              baseline_id TEXT NOT NULL UNIQUE,
              after_case_hash TEXT NOT NULL UNIQUE,
              after_run_id TEXT NOT NULL UNIQUE,
              resolution_id TEXT NOT NULL,
              artifact_set_hash TEXT NOT NULL,
              approval_subject_hash TEXT NOT NULL UNIQUE,
              assertion_set_hash TEXT NOT NULL,
              authorization_record_set_hash TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              FOREIGN KEY (baseline_id) REFERENCES baselines(baseline_id),
              FOREIGN KEY (approval_subject_hash)
                REFERENCES approval_subjects(approval_subject_hash),
              FOREIGN KEY (authorization_record_set_hash)
                REFERENCES authorization_record_sets(record_set_hash)
            );
            CREATE TABLE IF NOT EXISTS replay_authorization_authenticity_bindings (
              replay_authorization_authenticity_binding_hash TEXT PRIMARY KEY,
              replay_admission_hash TEXT NOT NULL UNIQUE,
              approval_subject_hash TEXT NOT NULL UNIQUE,
              approval_assertion_set_hash TEXT NOT NULL UNIQUE,
              authorization_record_set_hash TEXT NOT NULL,
              trust_snapshot_hash TEXT NOT NULL,
              authorization_authenticity_context_hash TEXT NOT NULL,
              stateless_authenticity_binding_hash TEXT NOT NULL UNIQUE,
              after_case_hash TEXT NOT NULL UNIQUE,
              after_run_id TEXT NOT NULL UNIQUE,
              payload_json TEXT NOT NULL,
              FOREIGN KEY (replay_admission_hash)
                REFERENCES replay_admissions(replay_admission_hash),
              FOREIGN KEY (approval_subject_hash)
                REFERENCES approval_subjects(approval_subject_hash),
              FOREIGN KEY (authorization_record_set_hash)
                REFERENCES authorization_record_sets(record_set_hash),
              FOREIGN KEY (trust_snapshot_hash)
                REFERENCES authorization_trust_snapshots(trust_snapshot_hash),
              FOREIGN KEY (after_run_id) REFERENCES runs(run_id)
            );
            CREATE TABLE IF NOT EXISTS audit_events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              action TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              previous_hash TEXT NOT NULL,
              event_hash TEXT NOT NULL UNIQUE
            );
            """
        )
        for _name, statement in _A08_TABLE_DDL:
            self.connection.execute(statement)
        self.connection.commit()

    def feature_profile(self) -> str:
        rows = self.connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        table_names = {str(row[0]) for row in rows}
        if not self.REQUIRED_TABLES.issubset(table_names):
            return STORE_FEATURE_PARTIAL_OR_UNKNOWN

        present = table_names & A08_REQUIRED_TABLES
        if not present:
            return STORE_FEATURE_LEGACY_PRE_A08
        if present != A08_REQUIRED_TABLES:
            return STORE_FEATURE_PARTIAL_OR_UNKNOWN

        try:
            expected = dict(_expected_a08_feature_signatures())
            for table in sorted(A08_REQUIRED_TABLES):
                if _table_feature_signature(self.connection, table) != expected[table]:
                    return STORE_FEATURE_PARTIAL_OR_UNKNOWN
        except sqlite3.Error:
            return STORE_FEATURE_PARTIAL_OR_UNKNOWN
        return STORE_FEATURE_A08_0_1

    def require_a08_schema(self) -> None:
        profile = self.feature_profile()
        if profile == STORE_FEATURE_LEGACY_PRE_A08:
            raise StoreIntegrityError(A08_SCHEMA_MIGRATION_REQUIRED)
        if profile != STORE_FEATURE_A08_0_1:
            raise StoreIntegrityError(A08_SCHEMA_PARTIAL_OR_UNKNOWN)

    def migrate_a08_schema(self) -> bool:
        if self._readonly:
            raise StoreIntegrityError("A08_SCHEMA_MIGRATION_REQUIRES_WRITABLE_STORE")
        profile = self.feature_profile()
        if profile == STORE_FEATURE_A08_0_1:
            return False
        if profile != STORE_FEATURE_LEGACY_PRE_A08:
            raise StoreIntegrityError(A08_SCHEMA_PARTIAL_OR_UNKNOWN)
        if self.connection.in_transaction:
            raise StoreIntegrityError("A08_SCHEMA_MIGRATION_REQUIRES_CLEAN_TRANSACTION")

        try:
            self.connection.execute("BEGIN IMMEDIATE")
            for table, statement in _A08_TABLE_DDL:
                self.connection.execute(statement)
                self._fault_point(f"a08_migration_after_{table}")
            if self.feature_profile() != STORE_FEATURE_A08_0_1:
                raise StoreIntegrityError("A08_SCHEMA_MIGRATION_PROFILE_MISMATCH")
            self._fault_point("a08_migration_before_commit")
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise
        return True

    def has_required_schema(self) -> bool:
        rows = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        return self.REQUIRED_TABLES.issubset({str(row["name"]) for row in rows})

    def _append_audit(self, entity_type: str, entity_id: str, action: str, payload: Any) -> str:
        previous = self.connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else "GENESIS"
        created_at = datetime.now(UTC).isoformat()
        payload_json = _json(payload)
        seed = "|".join((previous_hash, created_at, entity_type, entity_id, action, payload_json))
        event_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        self.connection.execute(
            """INSERT INTO audit_events
               (created_at, entity_type, entity_id, action, payload_json, previous_hash, event_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (created_at, entity_type, entity_id, action, payload_json, previous_hash, event_hash),
        )
        return event_hash

    @staticmethod
    def _case_entity(case_id: str, case_hash: str, synthetic: int, payload_json: str) -> dict[str, Any]:
        return {
            "case_id": case_id,
            "case_hash": case_hash,
            "synthetic": synthetic,
            "payload_json": payload_json,
        }

    @staticmethod
    def _run_entity(
        run_id: str,
        case_id: str,
        status: str,
        ruleset_version: str,
        payload_json: str,
    ) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "case_id": case_id,
            "status": status,
            "ruleset_version": ruleset_version,
            "payload_json": payload_json,
        }

    @staticmethod
    def _approval_entity(
        resolution_id: str,
        case_id: str,
        event_id: str,
        event_revision: str,
        approved_case_hash: str,
        approved_patch_hash: str,
        role: str,
        decision: str,
        payload_json: str,
    ) -> dict[str, Any]:
        return {
            "resolution_id": resolution_id,
            "case_id": case_id,
            "event_id": event_id,
            "event_revision": event_revision,
            "approved_case_hash": approved_case_hash,
            "approved_patch_hash": approved_patch_hash,
            "role": role,
            "decision": decision,
            "payload_json": payload_json,
        }

    @staticmethod
    def _baseline_entity(
        baseline_id: str,
        case_id: str,
        source_run_id: str,
        payload_json: str,
    ) -> dict[str, Any]:
        return {
            "baseline_id": baseline_id,
            "case_id": case_id,
            "source_run_id": source_run_id,
            "payload_json": payload_json,
        }

    def _save_case(self, case: dict[str, Any]) -> bool:
        case = prepare_case(case)
        payload_json = _json(case)
        case_id = str(case["case_id"])
        case_hash = canonical_hash(case)
        synthetic = int(case.get("synthetic_for_competition") is True)
        entity = self._case_entity(case_id, case_hash, synthetic, payload_json)
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO cases(case_id, case_hash, synthetic, payload_json) VALUES (?, ?, ?, ?)",
            (case_id, case_hash, synthetic, payload_json),
        ).rowcount
        if inserted:
            self._append_audit(
                "case",
                f"{case_id}@{case_hash}",
                "CASE_REGISTERED",
                {
                    "primary_key": {"case_id": case_id, "case_hash": case_hash},
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        else:
            row = self.connection.execute(
                "SELECT case_id, case_hash, synthetic, payload_json FROM cases WHERE case_id=? AND case_hash=?",
                (case_id, case_hash),
            ).fetchone()
            if row is None or _fingerprint(dict(row)) != _fingerprint(entity):
                raise StoreIntegrityError("case primary key conflicts with different stored content")
        return bool(inserted)

    def save_case(self, case: dict[str, Any]) -> bool:
        with self.connection:
            return self._save_case(case)

    def _registered_case_for_run(self, result: RunResult) -> dict[str, Any]:
        if not isinstance(result, RunResult):
            raise StoreIntegrityError("run must be a RunResult")
        row = self.connection.execute(
            "SELECT case_id, case_hash, synthetic, payload_json "
            "FROM cases WHERE case_id=? AND case_hash=?",
            (result.case_id, result.case_hash),
        ).fetchone()
        if row is None:
            case_id_exists = self.connection.execute(
                "SELECT 1 FROM cases WHERE case_id=? LIMIT 1",
                (result.case_id,),
            ).fetchone()
            if case_id_exists:
                raise StoreIntegrityError(
                    "run case_hash does not match any registered snapshot for its case_id"
                )
            raise StoreIntegrityError("exact run case must be registered before saving the run")
        try:
            case = strict_json_loads(row["payload_json"])
            if not isinstance(case, dict):
                raise ValueError("case payload root must be an object")
            validate_case(case)
        except (TypeError, ValueError) as error:
            raise StoreIntegrityError("registered run case payload is invalid") from error
        if (
            case.get("case_id") != row["case_id"]
            or canonical_hash(case) != row["case_hash"]
            or int(case.get("synthetic_for_competition") is True) != row["synthetic"]
        ):
            raise StoreIntegrityError("registered run case metadata does not match its payload")
        return case

    def _validate_run_against_registered_case(
        self,
        result: RunResult,
        reference_context: _ControlledReferenceContext | None = None,
        validation_context: _ValidationEvidenceContext | None = None,
    ) -> None:
        case = self._registered_case_for_run(result)
        expected = (
            _run_case_with_reference_context(
                case, reference_context, validation_context
            )
            if reference_context is not None
            else run_case(case)
        )
        if expected.to_dict() != result.to_dict():
            raise StoreIntegrityError(
                "run result does not match the exact recomputed registered case"
            )

    def _save_run(
        self,
        result: RunResult,
        reference_context: _ControlledReferenceContext | None = None,
        validation_context: _ValidationEvidenceContext | None = None,
    ) -> bool:
        self._validate_run_against_registered_case(
            result, reference_context, validation_context
        )
        payload_json = _json(result.to_dict())
        status = str(result.overall_status)
        entity = self._run_entity(
            result.run_id, result.case_id, status, result.ruleset_version, payload_json
        )
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO runs(run_id, case_id, status, ruleset_version, payload_json) VALUES (?, ?, ?, ?, ?)",
            (result.run_id, result.case_id, status, result.ruleset_version, payload_json),
        ).rowcount
        if inserted:
            self._append_audit(
                "run",
                result.run_id,
                "CHECK_RUN_RECORDED",
                {
                    "primary_key": {"run_id": result.run_id},
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        else:
            row = self.connection.execute(
                "SELECT run_id, case_id, status, ruleset_version, payload_json FROM runs WHERE run_id=?",
                (result.run_id,),
            ).fetchone()
            if row is None or _fingerprint(dict(row)) != _fingerprint(entity):
                raise StoreIntegrityError(
                    "run_id conflicts with different output; bump ruleset version or repair the store"
                )
        return bool(inserted)

    def _save_run_validation_link(
        self,
        run_id: str,
        validation_context: _ValidationEvidenceContext,
    ) -> bool:
        linked = self.connection.execute(
            "INSERT OR IGNORE INTO run_validation_sets(run_id,evidence_set_hash) "
            "VALUES (?,?)",
            (run_id, validation_context.evidence_set_hash),
        ).rowcount
        entity = {
            "run_id": run_id,
            "evidence_set_hash": validation_context.evidence_set_hash,
        }
        if not linked:
            row = self.connection.execute(
                "SELECT run_id,evidence_set_hash FROM run_validation_sets "
                "WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is None or dict(row) != entity:
                raise StoreIntegrityError(
                    "run identity conflicts with different validation bytes"
                )
        else:
            self._append_audit(
                "run_validation_set",
                run_id,
                "RUN_VALIDATION_SET_RECORDED",
                {
                    "primary_key": {"run_id": run_id},
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        return bool(linked)

    def _run_is_linked_to_replay_admission(self, run_id: str) -> bool:
        return (
            self.connection.execute(
                """SELECT 1 FROM replay_admissions
                   WHERE json_extract(payload_json,'$.before_run.run_id')=?
                      OR json_extract(payload_json,'$.after_run.run_id')=?
                   LIMIT 1""",
                (run_id, run_id),
            ).fetchone()
            is not None
        )

    def _assert_replay_runs_have_no_standalone_reference_links(
        self, replay: ReplayResult
    ) -> None:
        linked = self.connection.execute(
            """SELECT run_id FROM run_reference_sets
               WHERE run_id IN (?,?) LIMIT 1""",
            (replay.before.run_id, replay.after.run_id),
        ).fetchone()
        if linked is not None:
            raise StoreIntegrityError(
                "replay run already has a standalone controlled-reference link"
            )

    def _a08_replay_run_reference_links_match(
        self,
        replay: ReplayResult,
        before_context: _CaseSourceContext,
    ) -> bool:
        """Allow only the locator's already-attested before-run reference link."""

        before = self.connection.execute(
            "SELECT reference_set_hash FROM run_reference_sets WHERE run_id=?",
            (replay.before.run_id,),
        ).fetchone()
        after = self.connection.execute(
            "SELECT 1 FROM run_reference_sets WHERE run_id=?",
            (replay.after.run_id,),
        ).fetchone()
        return after is None and (
            before is None
            or before["reference_set_hash"]
            == before_context._reference_context.reference_set_hash
        )

    def _a08_prior_locator_reference_link_is_valid(self, run_id: str) -> bool:
        """Recognize a standalone source run reused only as an A08 before-run."""

        rows = self.connection.execute(
            "SELECT payload_json FROM replay_admissions WHERE "
            "json_extract(payload_json,'$.before_run.run_id')=? OR "
            "json_extract(payload_json,'$.after_run.run_id')=?",
            (run_id, run_id),
        ).fetchall()
        if len(rows) != 1:
            return False
        try:
            payload = strict_json_loads(rows[0]["payload_json"])
        except (TypeError, ValueError):
            return False
        return (
            type(payload) is dict
            and payload.get("contract_version")
            == A08_REPLAY_ADMISSION_CONTRACT_VERSION
            and payload.get("before_run", {}).get("run_id") == run_id
            and payload.get("after_run", {}).get("run_id") != run_id
        )

    def save_run(
        self,
        result: RunResult,
        *,
        reference_bundle: ControlledReferenceBundle | None = None,
        validation_bundle: ValidationEvidenceBundle | None = None,
    ) -> bool:
        if type(result) is not RunResult:
            raise StoreIntegrityError("only an actual RunResult can be saved")
        has_audit = self.connection.execute(
            "SELECT 1 FROM audit_events LIMIT 1"
        ).fetchone() is not None
        if has_audit and not self.verify_audit_chain():
            raise StoreIntegrityError(
                "standalone run persistence requires an intact semantic and "
                "audit store"
            )
        a08_profile = self.feature_profile() == STORE_FEATURE_A08_0_1
        if reference_bundle is None and validation_bundle is None:
            with self.connection:
                inserted = self._save_run(result)
                if a08_profile:
                    self._stage_unbound_run_case_source_set(result)
                self._fault_point("standalone_run_before_final_preflight")
                stored_run = self.connection.execute(
                    "SELECT run_id,case_id,status,ruleset_version,payload_json "
                    "FROM runs WHERE run_id=?",
                    (result.run_id,),
                ).fetchone()
                if (
                    stored_run is None
                    or not self._run_entity_is_semantically_valid(
                        dict(stored_run)
                    )
                    or not self.verify_audit_chain()
                ):
                    raise StoreIntegrityError(
                        "standalone run final semantic preflight failed"
                    )
                return inserted
        if type(reference_bundle) is not ControlledReferenceBundle:
            raise StoreIntegrityError("run persistence rejects reference context markers")
        if validation_bundle is not None and type(
            validation_bundle
        ) is not ValidationEvidenceBundle:
            raise StoreIntegrityError(
                "run persistence rejects validation context markers"
            )
        try:
            context = _prepare_controlled_reference_context(reference_bundle)
        except (TypeError, ValueError) as error:
            raise StoreIntegrityError("run reference bytes cannot be rebuilt") from error
        validation_context = None
        if validation_bundle is not None:
            try:
                validation_context = _prepare_validation_evidence_context(
                    validation_bundle,
                    self._registered_case_for_run(result),
                    expected_phase="SOURCE",
                )
            except (TypeError, ValueError) as error:
                raise StoreIntegrityError(
                    "run validation bytes cannot be rebuilt"
                ) from error
        with self.connection:
            if self._run_is_linked_to_replay_admission(result.run_id):
                raise StoreIntegrityError(
                    "admission-linked replay runs cannot gain standalone reference links"
                )
            created_reference_set = self._stage_controlled_reference_bundle(
                context.reference_set_hash, reference_bundle
            )
            created_validation_set = False
            if validation_context is not None:
                created_validation_set = self._stage_validation_evidence_bundle(
                    validation_context,
                    validation_bundle,
                )
            inserted = self._save_run(result, context, validation_context)
            linked = self.connection.execute(
                "INSERT OR IGNORE INTO run_reference_sets(run_id,reference_set_hash) VALUES (?,?)",
                (result.run_id, context.reference_set_hash),
            ).rowcount
            if not linked:
                row = self.connection.execute(
                    "SELECT reference_set_hash FROM run_reference_sets WHERE run_id=?",
                    (result.run_id,),
                ).fetchone()
                if row is None or row["reference_set_hash"] != context.reference_set_hash:
                    raise StoreIntegrityError(
                        "run identity conflicts with different controlled reference bytes"
                    )
            if linked:
                link_entity = {
                    "run_id": result.run_id,
                    "reference_set_hash": context.reference_set_hash,
                }
                self._append_audit(
                    "run_reference_set",
                    result.run_id,
                    "RUN_REFERENCE_SET_RECORDED",
                    {
                        "primary_key": {"run_id": result.run_id},
                        "entity_fingerprint": _fingerprint(link_entity),
                    },
                )
            if validation_context is not None:
                self._save_run_validation_link(result.run_id, validation_context)
            if created_reference_set:
                entity = self._controlled_reference_set_entity(
                    context.reference_set_hash
                )
                if entity is None:
                    raise StoreIntegrityError("controlled reference set disappeared")
                self._append_audit(
                    "controlled_reference_set",
                    context.reference_set_hash,
                    "CONTROLLED_REFERENCE_SET_RECORDED",
                    {
                        "primary_key": {
                            "reference_set_hash": context.reference_set_hash
                        },
                        "entity_fingerprint": _fingerprint(entity),
                    },
                )
            if created_validation_set and validation_context is not None:
                entity = self._validation_evidence_set_entity(
                    validation_context.evidence_set_hash
                )
                if entity is None:
                    raise StoreIntegrityError(
                        "validation evidence set disappeared"
                    )
                self._append_audit(
                    "validation_evidence_set",
                    validation_context.evidence_set_hash,
                    "VALIDATION_EVIDENCE_SET_RECORDED",
                    {
                        "primary_key": {
                            "evidence_set_hash": validation_context.evidence_set_hash
                        },
                        "entity_fingerprint": _fingerprint(entity),
                    },
                )
            if a08_profile:
                self._stage_unbound_run_case_source_set(result)
            self._fault_point("standalone_run_before_final_preflight")
            stored_run = self.connection.execute(
                "SELECT run_id,case_id,status,ruleset_version,payload_json "
                "FROM runs WHERE run_id=?",
                (result.run_id,),
            ).fetchone()
            if (
                stored_run is None
                or not self._run_entity_is_semantically_valid(dict(stored_run))
                or not self.verify_audit_chain()
            ):
                raise StoreIntegrityError(
                    "standalone run final semantic preflight failed"
                )
            return inserted

    def _fault_point(self, _stage: str) -> None:
        """Test hook for proving transaction rollback at security boundaries."""

    @contextmanager
    def _prevalidated_replay_transaction(self):
        """Bind private replay-run capabilities to exactly one Store call."""

        if getattr(self, "_active_prevalidated_transaction_seal", None) is not None:
            raise StoreIntegrityError("nested prevalidated replay transaction")
        transaction_seal = object()
        object.__setattr__(
            self,
            "_active_prevalidated_transaction_seal",
            transaction_seal,
        )
        try:
            with self.connection:
                yield transaction_seal
        finally:
            if (
                getattr(self, "_active_prevalidated_transaction_seal", None)
                is transaction_seal
            ):
                object.__setattr__(
                    self,
                    "_active_prevalidated_transaction_seal",
                    None,
                )

    @staticmethod
    def _case_source_set_payload(context: _CaseSourceContext) -> dict[str, Any]:
        source_set = context.case_source_set
        return {
            "case_source_set": source_set.to_dict(),
            "root_binding": {
                "case_source_binding_hash": context.case_source_binding_hash,
                "root_case_hash": context.root_case_hash,
                "case_schema_version": CASE_SCHEMA_VERSION,
                "builder_manifest_version": MANIFEST_VERSION,
                "ingestion_policy_version": INGESTION_POLICY_VERSION,
                "parser_consumption_plan_version": (
                    PARSER_CONSUMPTION_PLAN_VERSION
                ),
                "mapping_contract_version": MAPPING_CONTRACT_VERSION,
                "derived_locator_contract_version": (
                    DERIVED_LOCATOR_CONTRACT_VERSION
                ),
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
            },
        }

    @staticmethod
    def _case_source_member_payload(
        source_set_hash: str,
        member_index: int,
        member: Any,
    ) -> dict[str, Any]:
        return {
            "source_set_hash": source_set_hash,
            "member_index": member_index,
            **member.to_dict(),
        }

    def _stage_a08_blob(self, raw_bytes: bytes) -> str:
        source_hash = hashlib.sha256(raw_bytes).hexdigest()
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO artifact_blobs(source_hash,size_bytes,raw_bytes) "
            "VALUES (?,?,?)",
            (source_hash, len(raw_bytes), raw_bytes),
        ).rowcount
        if not inserted:
            row = self.connection.execute(
                "SELECT size_bytes,raw_bytes FROM artifact_blobs WHERE source_hash=?",
                (source_hash,),
            ).fetchone()
            if (
                row is None
                or row["size_bytes"] != len(raw_bytes)
                or bytes(row["raw_bytes"]) != raw_bytes
            ):
                raise StoreIntegrityError(
                    "case source hash conflicts with different stored bytes"
                )
        return source_hash

    def _case_source_set_entity(
        self,
        source_set_hash: str,
    ) -> dict[str, Any] | None:
        source_set = self.connection.execute(
            "SELECT * FROM case_source_sets WHERE source_set_hash=?",
            (source_set_hash,),
        ).fetchone()
        if source_set is None:
            return None
        manifest_blob = self.connection.execute(
            "SELECT source_hash,size_bytes,raw_bytes FROM artifact_blobs "
            "WHERE source_hash=?",
            (source_set["manifest_source_hash"],),
        ).fetchone()
        members = self.connection.execute(
            "SELECT m.*,b.size_bytes AS blob_size_bytes,b.raw_bytes "
            "FROM case_source_members m "
            "LEFT JOIN artifact_blobs b ON b.source_hash=m.source_hash "
            "WHERE m.source_set_hash=? ORDER BY m.member_index",
            (source_set_hash,),
        ).fetchall()
        return {
            "source_set": dict(source_set),
            "manifest_blob": (
                dict(manifest_blob) if manifest_blob is not None else None
            ),
            "members": [dict(row) for row in members],
        }

    def _stored_case_source_context(
        self,
        source_set_hash: str,
    ) -> _CaseSourceContext:
        self.require_a08_schema()
        row = self.connection.execute(
            "SELECT * FROM case_source_sets WHERE source_set_hash=?",
            (source_set_hash,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("stored case source set is missing")
        manifest_blob = self.connection.execute(
            "SELECT size_bytes,raw_bytes FROM artifact_blobs WHERE source_hash=?",
            (row["manifest_source_hash"],),
        ).fetchone()
        if manifest_blob is None:
            raise StoreIntegrityError("stored case source manifest blob is missing")
        manifest_bytes = bytes(manifest_blob["raw_bytes"])
        if (
            manifest_blob["size_bytes"] != len(manifest_bytes)
            or row["manifest_size_bytes"] != len(manifest_bytes)
            or hashlib.sha256(manifest_bytes).hexdigest()
            != row["manifest_source_hash"]
        ):
            raise StoreIntegrityError(
                "stored case source manifest hash or size differs from its bytes"
            )

        member_rows = self.connection.execute(
            "SELECT m.*,b.size_bytes AS blob_size_bytes,b.raw_bytes "
            "FROM case_source_members m "
            "LEFT JOIN artifact_blobs b ON b.source_hash=m.source_hash "
            "WHERE m.source_set_hash=? ORDER BY m.member_index",
            (source_set_hash,),
        ).fetchall()
        if len(member_rows) != len(DOCUMENT_TYPES):
            raise StoreIntegrityError(
                "stored case source set must contain exactly five members"
            )
        members: list[CaseSourceMember] = []
        captures: list[CaseSourceCapture] = [
            CaseSourceCapture(
                relative_path="_qualityci_store_manifest.json",
                size_bytes=len(manifest_bytes),
                source_kind="JSON",
                filesystem_safe=False,
            )
        ]
        for member_index, (expected_role, member_row) in enumerate(
            zip(DOCUMENT_TYPES, member_rows, strict=True)
        ):
            raw_value = member_row["raw_bytes"]
            if raw_value is None:
                raise StoreIntegrityError("stored case source member blob is missing")
            raw_bytes = bytes(raw_value)
            if (
                member_row["member_index"] != member_index
                or member_row["document_type"] != expected_role
                or member_row["blob_size_bytes"] != len(raw_bytes)
                or member_row["size_bytes"] != len(raw_bytes)
                or hashlib.sha256(raw_bytes).hexdigest()
                != member_row["source_hash"]
            ):
                raise StoreIntegrityError(
                    "stored case source member role, hash, or size differs from bytes"
                )
            try:
                member = CaseSourceMember(
                    document_type=member_row["document_type"],
                    source_id=member_row["source_id"],
                    source_path=member_row["source_path"],
                    source_kind=member_row["source_kind"],
                    raw_bytes=raw_bytes,
                    declared_table_selector_json=member_row[
                        "declared_table_selector_json"
                    ],
                )
            except (TypeError, ValueError) as error:
                raise StoreIntegrityError(
                    "stored case source member cannot be rebuilt"
                ) from error
            members.append(member)
            captures.append(
                CaseSourceCapture(
                    relative_path=member.source_path,
                    size_bytes=len(raw_bytes),
                    source_kind=member.source_kind,
                    filesystem_safe=False,
                )
            )
        try:
            bundle = CaseSourceBundle(
                manifest_bytes=manifest_bytes,
                members=tuple(members),
                snapshot=CaseSourceSnapshot(
                    source_kind="IN_MEMORY_BUNDLE",
                    captures=tuple(captures),
                ),
            )
            context = _prepare_case_source_context(bundle)
        except (TypeError, ValueError) as error:
            raise StoreIntegrityError(
                "stored case source bytes cannot rebuild their root context"
            ) from error

        expected_columns = {
            "source_set_hash": context.case_source_set.source_set_hash,
            "source_set_contract_version": CASE_SOURCE_SET_CONTRACT_VERSION,
            "source_pack_contract_version": CASE_SOURCE_PACK_CONTRACT_VERSION,
            "manifest_source_hash": context.case_source_set.manifest_source_hash,
            "manifest_size_bytes": context.case_source_set.manifest_size_bytes,
            "root_case_hash": context.root_case_hash,
            "root_binding_hash": context.case_source_binding_hash,
            "case_schema_version": CASE_SCHEMA_VERSION,
            "builder_manifest_version": MANIFEST_VERSION,
            "ingestion_policy_version": INGESTION_POLICY_VERSION,
            "parser_consumption_plan_version": (
                PARSER_CONSUMPTION_PLAN_VERSION
            ),
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
        if any(row[key] != value for key, value in expected_columns.items()):
            raise StoreIntegrityError(
                "stored case source columns differ from rebuilt raw bytes"
            )
        try:
            source_payload = strict_json_loads(row["canonical_payload_json"])
        except (TypeError, ValueError) as error:
            raise StoreIntegrityError(
                "stored case source payload is invalid JSON"
            ) from error
        expected_payload = self._case_source_set_payload(context)
        if (
            source_payload != expected_payload
            or row["canonical_payload_json"] != _json(expected_payload)
        ):
            raise StoreIntegrityError(
                "stored case source payload differs from rebuilt raw bytes"
            )
        for member_index, (member_row, rebuilt_member) in enumerate(
            zip(member_rows, context.case_source_set.members, strict=True)
        ):
            try:
                member_payload = strict_json_loads(
                    member_row["canonical_payload_json"]
                )
            except (TypeError, ValueError) as error:
                raise StoreIntegrityError(
                    "stored case source member payload is invalid JSON"
                ) from error
            expected_member_payload = self._case_source_member_payload(
                source_set_hash,
                member_index,
                rebuilt_member,
            )
            if (
                member_payload != expected_member_payload
                or member_row["canonical_payload_json"]
                != _json(expected_member_payload)
            ):
                raise StoreIntegrityError(
                    "stored case source member payload differs from rebuilt bytes"
                )
        return context

    def _stage_case_source_context(self, context: _CaseSourceContext) -> bool:
        self.require_a08_schema()
        if not _is_sealed_case_source_context(context):
            raise StoreIntegrityError(
                "case source persistence requires a freshly rebuilt sealed context"
            )
        source_set = context.case_source_set
        existing = self.connection.execute(
            "SELECT 1 FROM case_source_sets WHERE source_set_hash=?",
            (source_set.source_set_hash,),
        ).fetchone()
        if existing is not None:
            stored = self._stored_case_source_context(source_set.source_set_hash)
            supplied_members = tuple(
                (
                    item.document_type,
                    item.source_id,
                    item.source_path,
                    item.source_kind,
                    item.raw_bytes,
                    item.declared_table_selector_json,
                )
                for item in context.bundle.members
            )
            stored_members = tuple(
                (
                    item.document_type,
                    item.source_id,
                    item.source_path,
                    item.source_kind,
                    item.raw_bytes,
                    item.declared_table_selector_json,
                )
                for item in stored.bundle.members
            )
            if (
                stored.bundle.manifest_bytes != context.bundle.manifest_bytes
                or stored_members != supplied_members
                or stored.case_source_set.to_dict() != source_set.to_dict()
                or stored.root_case_hash != context.root_case_hash
                or stored.case_source_binding_hash
                != context.case_source_binding_hash
            ):
                raise StoreIntegrityError(
                    "existing case source set differs from supplied raw closure"
                )
            return False

        manifest_hash = self._stage_a08_blob(context.bundle.manifest_bytes)
        if manifest_hash != source_set.manifest_source_hash:
            raise StoreIntegrityError(
                "case source manifest differs from sealed source-set identity"
            )
        for member, identity in zip(
            context.bundle.members,
            source_set.members,
            strict=True,
        ):
            if self._stage_a08_blob(member.raw_bytes) != identity.source_hash:
                raise StoreIntegrityError(
                    "case source member differs from sealed source-set identity"
                )
        self._fault_point("a08_after_case_source_blobs")

        self.connection.execute(
            """INSERT INTO case_source_sets(
               source_set_hash,source_set_contract_version,
               source_pack_contract_version,manifest_source_hash,
               manifest_size_bytes,root_case_hash,root_binding_hash,
               case_schema_version,builder_manifest_version,
               ingestion_policy_version,parser_consumption_plan_version,
               mapping_contract_version,derived_locator_contract_version,
               identical_value_aggregation_contract_version,
               mapping_value_conversion_contract_version,
               derived_reference_identity_contract_version,
               controlled_reference_contract_version,canonical_payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                source_set.source_set_hash,
                CASE_SOURCE_SET_CONTRACT_VERSION,
                CASE_SOURCE_PACK_CONTRACT_VERSION,
                source_set.manifest_source_hash,
                source_set.manifest_size_bytes,
                context.root_case_hash,
                context.case_source_binding_hash,
                CASE_SCHEMA_VERSION,
                MANIFEST_VERSION,
                INGESTION_POLICY_VERSION,
                PARSER_CONSUMPTION_PLAN_VERSION,
                MAPPING_CONTRACT_VERSION,
                DERIVED_LOCATOR_CONTRACT_VERSION,
                IDENTICAL_VALUE_AGGREGATION_CONTRACT_VERSION,
                MAPPING_VALUE_CONVERSION_CONTRACT_VERSION,
                DERIVED_REFERENCE_IDENTITY_CONTRACT_VERSION,
                CONTROLLED_REFERENCE_CONTRACT_VERSION,
                _json(self._case_source_set_payload(context)),
            ),
        )
        self._fault_point("a08_after_case_source_set")
        for member_index, (member, identity) in enumerate(
            zip(context.bundle.members, source_set.members, strict=True)
        ):
            if (
                member.document_type != identity.document_type
                or member.source_id != identity.source_id
                or member.source_path != identity.source_path
                or member.source_kind != identity.source_kind
                or len(member.raw_bytes) != identity.size_bytes
                or member.declared_table_selector_json
                != identity.declared_table_selector_json
            ):
                raise StoreIntegrityError(
                    "case source member differs from sealed source-set projection"
                )
            self.connection.execute(
                """INSERT INTO case_source_members(
                   source_set_hash,member_index,document_type,source_id,
                   source_path,source_kind,size_bytes,source_hash,
                   declared_table_selector_json,canonical_payload_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    source_set.source_set_hash,
                    member_index,
                    identity.document_type,
                    identity.source_id,
                    identity.source_path,
                    identity.source_kind,
                    identity.size_bytes,
                    identity.source_hash,
                    identity.declared_table_selector_json,
                    _json(
                        self._case_source_member_payload(
                            source_set.source_set_hash,
                            member_index,
                            identity,
                        )
                    ),
                ),
            )
        self._fault_point("a08_after_case_source_members")
        entity = self._case_source_set_entity(source_set.source_set_hash)
        if entity is None:
            raise StoreIntegrityError("case source set disappeared during persistence")
        self._append_audit(
            "case_source_set",
            source_set.source_set_hash,
            "CASE_SOURCE_SET_RECORDED",
            {
                "primary_key": {"source_set_hash": source_set.source_set_hash},
                "entity_fingerprint": _fingerprint(entity),
            },
        )
        self._fault_point("a08_after_case_source_audit")
        self._stored_case_source_context(source_set.source_set_hash)
        return True

    def _case_source_set_entity_is_semantically_valid(
        self,
        entity: dict[str, Any],
    ) -> bool:
        try:
            source_set_hash = entity["source_set"]["source_set_hash"]
            context = self._stored_case_source_context(source_set_hash)
            current = self._case_source_set_entity(source_set_hash)
            return (
                context.case_source_set.source_set_hash == source_set_hash
                and current is not None
                and _fingerprint(current) == _fingerprint(entity)
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def verify_case_source_set_semantics(self, source_set_hash: str) -> bool:
        if type(source_set_hash) is not str:
            return False
        try:
            entity = self._case_source_set_entity(source_set_hash)
            return entity is not None and self._case_source_set_entity_is_semantically_valid(
                entity
            )
        except (TypeError, ValueError, sqlite3.Error):
            return False

    @staticmethod
    def _case_lineage_payload(lineage: CaseSourceLineage) -> dict[str, Any]:
        if type(lineage) is not CaseSourceLineage:
            raise StoreIntegrityError(
                "case lineage persistence requires exact rebuilt lineage"
            )
        return lineage.to_dict()

    def _case_lineage_entity(
        self,
        lineage_hash: str,
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM case_lineage_bindings WHERE lineage_hash=?",
            (lineage_hash,),
        ).fetchone()
        if row is None:
            return None
        blob = self.connection.execute(
            "SELECT source_hash,size_bytes,raw_bytes FROM artifact_blobs "
            "WHERE source_hash=?",
            (row["operation_blob_source_hash"],),
        ).fetchone()
        material = self.connection.execute(
            "SELECT source_hash,size_bytes,raw_bytes FROM artifact_blobs "
            "WHERE source_hash=?",
            (row["operation_material_source_hash"],),
        ).fetchone()
        return {
            "lineage": dict(row),
            "operation_blob": dict(blob) if blob is not None else None,
            "operation_material_blob": (
                dict(material) if material is not None else None
            ),
        }

    @staticmethod
    def _lineage_row_matches_rebuilt(
        row: sqlite3.Row,
        lineage: CaseSourceLineage,
    ) -> bool:
        material_bytes = lineage._operation_material_json.encode("utf-8")
        expected = {
            "lineage_hash": lineage.lineage_hash,
            "lineage_contract_version": lineage.contract_version,
            "root_binding_hash": lineage.root_binding_hash,
            "parent_lineage_hash": lineage.parent_lineage_hash,
            "input_case_hash": lineage.input_case_hash,
            "output_case_hash": lineage.output_case_hash,
            "operation_kind": lineage.operation_kind,
            "operation_contract_version": lineage.operation_contract_version,
            "operation_material_hash": lineage.operation_material_hash,
            "operation_blob_source_hash": lineage.operation_blob_source_hash,
            "operation_blob_size_bytes": len(lineage._operation_blob_bytes),
            "operation_material_source_hash": (
                lineage.operation_material_source_hash
            ),
            "operation_material_size_bytes": len(material_bytes),
            "canonical_payload_json": _json(lineage.to_dict()),
        }
        return all(row[key] == value for key, value in expected.items())

    def _stored_native_replay_bundle(
        self,
        material: dict[str, Any],
        resolution_bytes: bytes,
    ) -> NativeReplayDerivationBundle:
        """Rebuild one native carrier from Store-owned raw facts, never hashes alone."""

        try:
            subject_hash = material["approval_subject_hash"]
            subject_row = self.connection.execute(
                "SELECT payload_json FROM approval_subjects "
                "WHERE approval_subject_hash=?",
                (subject_hash,),
            ).fetchone()
            if subject_row is None:
                raise StoreIntegrityError(
                    "stored native lineage approval subject is missing"
                )
            subject = validate_approval_subject(
                strict_json_loads(subject_row["payload_json"])
            )
            if (
                subject_row["payload_json"] != _json(subject)
                or approval_subject_hash(subject) != subject_hash
            ):
                raise StoreIntegrityError(
                    "stored native lineage approval subject differs from its bytes"
                )
            assertion_rows = self.connection.execute(
                "SELECT assertion_hash,payload_json FROM approval_assertions "
                "WHERE approval_subject_hash=? ORDER BY assertion_hash",
                (subject_hash,),
            ).fetchall()
            assertions = tuple(
                validate_approval_assertion_shape(
                    strict_json_loads(row["payload_json"])
                )
                for row in assertion_rows
            )
            assertion_hashes = tuple(
                sorted(approval_assertion_hash(item) for item in assertions)
            )
            if (
                not assertions
                or assertion_hashes
                != tuple(row["assertion_hash"] for row in assertion_rows)
                or self._assertion_set_hash(assertion_hashes)
                != material["approval_assertion_set_hash"]
            ):
                raise StoreIntegrityError(
                    "stored native lineage assertion set differs from raw assertions"
                )
            return NativeReplayDerivationBundle(
                native_resolution_bytes=resolution_bytes,
                approval_subject_bytes=_json(subject).encode("utf-8"),
                approval_assertions_bytes=_json(
                    {"assertions": list(assertions)}
                ).encode("utf-8"),
                authorization_bundle=self._load_authorization_record_bundle(
                    material["authorization_record_set_hash"]
                ),
                authorization_trust_bundle=(
                    self._load_authorization_trust_snapshot_bundle(
                        material["authorization_trust_snapshot_hash"]
                    )
                ),
                artifact_bundle=self._load_artifact_bundle(
                    material["artifact_set_hash"]
                ),
                source_validation_bundle=self._load_validation_evidence_bundle(
                    material["source_validation_evidence_set_hash"]
                ),
                resolved_validation_bundle=self._load_validation_evidence_bundle(
                    material["resolved_validation_evidence_set_hash"]
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise StoreIntegrityError(
                "stored native lineage raw closure cannot be rebuilt"
            ) from error

    def _rebuild_a08_replay_from_source_payload(
        self,
        payload: dict[str, Any],
    ) -> tuple[
        CaseSourceBundle,
        tuple[Any, ...],
        NativeReplayDerivationBundle,
        _CaseSourceContext,
        _CaseSourceContext,
        StatelessApprovalReplayResult,
    ]:
        """Re-execute a 0.5 replay from the Store-owned root and lineage blobs."""

        before_source = payload.get("before_case_source")
        after_source = payload.get("after_case_source")
        if type(before_source) is not dict or type(after_source) is not dict:
            raise StoreIntegrityError("A08 replay source tuples are missing")
        source_set_hash = before_source.get("case_source_set_hash")
        if (
            source_set_hash != after_source.get("case_source_set_hash")
            or before_source.get("case_source_binding_hash")
            != after_source.get("case_source_binding_hash")
            or after_source.get("case_source_assurance_state")
            != CASE_SOURCE_DERIVED
        ):
            raise StoreIntegrityError(
                "A08 replay before/after source tuples cross a root"
            )
        root_context = self._stored_case_source_context(source_set_hash)
        terminal_hash = after_source.get("case_source_lineage_hash")
        if not _is_lower_hex(terminal_hash, 64):
            raise StoreIntegrityError("A08 replay after lineage is invalid")
        chain: list[sqlite3.Row] = []
        seen: set[str] = set()
        cursor: str | None = terminal_hash
        while cursor is not None:
            if cursor in seen:
                raise StoreIntegrityError("A08 replay lineage contains a cycle")
            seen.add(cursor)
            row = self.connection.execute(
                "SELECT * FROM case_lineage_bindings WHERE lineage_hash=?",
                (cursor,),
            ).fetchone()
            if (
                row is None
                or row["root_binding_hash"]
                != root_context.case_source_binding_hash
            ):
                raise StoreIntegrityError(
                    "A08 replay lineage ancestor is missing or crosses a root"
                )
            chain.append(row)
            cursor = row["parent_lineage_hash"]
        chain.reverse()
        before_terminal = before_source.get("case_source_lineage_hash")
        before_state = before_source.get("case_source_assurance_state")
        if before_state == CASE_SOURCE_BOUND:
            if before_terminal is not None:
                raise StoreIntegrityError(
                    "A08 bound before-case cannot name a lineage"
                )
            before_count = 0
        elif before_state == CASE_SOURCE_DERIVED:
            matching = [
                index
                for index, row in enumerate(chain)
                if row["lineage_hash"] == before_terminal
            ]
            if len(matching) != 1:
                raise StoreIntegrityError(
                    "A08 before lineage is not an ancestor of after"
                )
            before_count = matching[0] + 1
        else:
            raise StoreIntegrityError(
                "A08 replay before source state is unsupported"
            )
        if len(chain) != before_count + 1 or chain[-1][
            "operation_kind"
        ] != "NATIVE_REPLAY":
            raise StoreIntegrityError(
                "A08 replay after lineage must add exactly one native node"
            )

        def raw_and_material(row: sqlite3.Row) -> tuple[bytes, dict[str, Any]]:
            raw_row = self.connection.execute(
                "SELECT raw_bytes FROM artifact_blobs WHERE source_hash=?",
                (row["operation_blob_source_hash"],),
            ).fetchone()
            material_row = self.connection.execute(
                "SELECT raw_bytes FROM artifact_blobs WHERE source_hash=?",
                (row["operation_material_source_hash"],),
            ).fetchone()
            if raw_row is None or material_row is None:
                raise StoreIntegrityError("A08 replay lineage blobs are missing")
            raw = bytes(raw_row["raw_bytes"])
            material_bytes = bytes(material_row["raw_bytes"])
            try:
                material = strict_json_loads(material_bytes.decode("utf-8"))
            except (UnicodeError, ValueError) as error:
                raise StoreIntegrityError(
                    "A08 replay lineage material is invalid"
                ) from error
            if (
                type(material) is not dict
                or material_bytes != _json(material).encode("utf-8")
            ):
                raise StoreIntegrityError(
                    "A08 replay lineage material is not canonical"
                )
            return raw, material

        prior: list[Any] = []
        for row in chain[:before_count]:
            raw, material = raw_and_material(row)
            if row["operation_kind"] == "MUTATION":
                prior.append(
                    CaseMutationDerivationBundle(CaseMutationBundle(raw))
                )
            elif row["operation_kind"] == "NATIVE_REPLAY":
                prior.append(self._stored_native_replay_bundle(material, raw))
            else:
                raise StoreIntegrityError(
                    "A08 replay prior lineage kind is unsupported"
                )
        current_raw, current_material = raw_and_material(chain[-1])
        current = self._stored_native_replay_bundle(
            current_material,
            current_raw,
        )
        prior_tuple = tuple(prior)
        result = replay_with_source_assurance(
            root_context.bundle,
            prior_tuple,
            current,
        )
        before_context = _rebuild_prior_case_source_context(
            root_context.bundle,
            prior_tuple,
        )
        after_context, rebuilt = _replay_one_source_derivation(
            before_context,
            current,
        )
        if (
            rebuilt.to_dict() != result.to_dict()
            or before_context.assurance().to_dict() != before_source
            or after_context.assurance().to_dict() != after_source
            or after_context.lineages[-1].operation_material()
            != current_material
            or after_context.lineages[-1].lineage_hash != terminal_hash
        ):
            raise StoreIntegrityError(
                "A08 replay source tuples or native material differ on rebuild"
            )
        return (
            root_context.bundle,
            prior_tuple,
            current,
            before_context,
            after_context,
            result,
        )

    def _stored_case_source_context_with_lineage(
        self,
        source_set_hash: str,
        terminal_lineage_hash: str | None,
    ) -> _CaseSourceContext:
        context = self._stored_case_source_context(source_set_hash)
        if terminal_lineage_hash is None:
            return context
        if not _is_lower_hex(terminal_lineage_hash, 64):
            raise StoreIntegrityError("stored terminal lineage hash is invalid")

        chain: list[sqlite3.Row] = []
        seen: set[str] = set()
        current_hash: str | None = terminal_lineage_hash
        while current_hash is not None:
            if current_hash in seen:
                raise StoreIntegrityError("stored case lineage contains a cycle")
            seen.add(current_hash)
            row = self.connection.execute(
                "SELECT * FROM case_lineage_bindings WHERE lineage_hash=?",
                (current_hash,),
            ).fetchone()
            if row is None:
                raise StoreIntegrityError("stored case lineage ancestor is missing")
            if row["root_binding_hash"] != context.case_source_binding_hash:
                raise StoreIntegrityError(
                    "stored case lineage crosses its root binding"
                )
            chain.append(row)
            current_hash = row["parent_lineage_hash"]
        chain.reverse()

        for index, row in enumerate(chain):
            expected_parent = (
                None if index == 0 else chain[index - 1]["lineage_hash"]
            )
            if row["parent_lineage_hash"] != expected_parent:
                raise StoreIntegrityError(
                    "stored case lineage parent order is inconsistent"
                )
            operation_blob = self.connection.execute(
                "SELECT size_bytes,raw_bytes FROM artifact_blobs "
                "WHERE source_hash=?",
                (row["operation_blob_source_hash"],),
            ).fetchone()
            material_blob = self.connection.execute(
                "SELECT size_bytes,raw_bytes FROM artifact_blobs "
                "WHERE source_hash=?",
                (row["operation_material_source_hash"],),
            ).fetchone()
            if operation_blob is None or material_blob is None:
                raise StoreIntegrityError("stored case lineage material is missing")
            raw_bytes = bytes(operation_blob["raw_bytes"])
            material_bytes = bytes(material_blob["raw_bytes"])
            if (
                operation_blob["size_bytes"] != len(raw_bytes)
                or row["operation_blob_size_bytes"] != len(raw_bytes)
                or hashlib.sha256(raw_bytes).hexdigest()
                != row["operation_blob_source_hash"]
                or material_blob["size_bytes"] != len(material_bytes)
                or row["operation_material_size_bytes"] != len(material_bytes)
                or hashlib.sha256(material_bytes).hexdigest()
                != row["operation_material_source_hash"]
            ):
                raise StoreIntegrityError(
                    "stored case lineage material hash or size differs from bytes"
                )
            try:
                material_text = material_bytes.decode("utf-8")
                material = strict_json_loads(material_text)
            except (UnicodeError, ValueError) as error:
                raise StoreIntegrityError(
                    "stored case lineage material is invalid JSON"
                ) from error
            if type(material) is not dict or material_text != _json(material):
                raise StoreIntegrityError(
                    "stored case lineage material is not canonical JSON"
                )
            try:
                if row["operation_kind"] == "MUTATION":
                    context = _derive_case_source_mutation(
                        context,
                        CaseMutationBundle(raw_bytes),
                    )
                elif row["operation_kind"] == "NATIVE_REPLAY":
                    native_bundle = self._stored_native_replay_bundle(
                        material,
                        raw_bytes,
                    )
                    context, _result = _replay_one_source_derivation(
                        context,
                        native_bundle,
                    )
                else:
                    raise StoreIntegrityError(
                        "stored case lineage operation kind is unknown"
                    )
            except (ApprovalGateError, TypeError, ValueError) as error:
                raise StoreIntegrityError(
                    "stored operation bytes cannot rebuild their lineage"
                ) from error
            rebuilt = context.lineages[-1]
            if (
                rebuilt.operation_material() != material
                or rebuilt._operation_material_json != material_text
                or not self._lineage_row_matches_rebuilt(row, rebuilt)
            ):
                raise StoreIntegrityError(
                    "stored case lineage differs from rebuilt operation bytes"
                )
        if context.lineages[-1].lineage_hash != terminal_lineage_hash:
            raise StoreIntegrityError("stored terminal lineage cannot be reached")
        return context

    def _stored_a08_derivation_closure(
        self,
        source_set_hash: str,
        terminal_lineage_hash: str | None,
    ) -> _A08DerivationPersistence:
        """Recreate exact derivation carriers from Store-owned operation blobs."""

        verified_context = self._stored_case_source_context_with_lineage(
            source_set_hash,
            terminal_lineage_hash,
        )
        root_context = self._stored_case_source_context(source_set_hash)
        if terminal_lineage_hash is None:
            chain: list[sqlite3.Row] = []
        else:
            chain = []
            seen: set[str] = set()
            cursor: str | None = terminal_lineage_hash
            while cursor is not None:
                if cursor in seen:
                    raise StoreIntegrityError(
                        "stored prior-run lineage contains a cycle"
                    )
                seen.add(cursor)
                row = self.connection.execute(
                    "SELECT * FROM case_lineage_bindings WHERE lineage_hash=?",
                    (cursor,),
                ).fetchone()
                if (
                    row is None
                    or row["root_binding_hash"]
                    != root_context.case_source_binding_hash
                ):
                    raise StoreIntegrityError(
                        "stored prior-run lineage is missing or crosses its root"
                    )
                chain.append(row)
                cursor = row["parent_lineage_hash"]
            chain.reverse()

        derivations: list[Any] = []
        for row in chain:
            operation_row = self.connection.execute(
                "SELECT size_bytes,raw_bytes FROM artifact_blobs "
                "WHERE source_hash=?",
                (row["operation_blob_source_hash"],),
            ).fetchone()
            material_row = self.connection.execute(
                "SELECT size_bytes,raw_bytes FROM artifact_blobs "
                "WHERE source_hash=?",
                (row["operation_material_source_hash"],),
            ).fetchone()
            if operation_row is None or material_row is None:
                raise StoreIntegrityError(
                    "stored prior-run operation raw facts are missing"
                )
            operation_bytes = bytes(operation_row["raw_bytes"])
            material_bytes = bytes(material_row["raw_bytes"])
            if (
                operation_row["size_bytes"] != len(operation_bytes)
                or material_row["size_bytes"] != len(material_bytes)
                or hashlib.sha256(operation_bytes).hexdigest()
                != row["operation_blob_source_hash"]
                or hashlib.sha256(material_bytes).hexdigest()
                != row["operation_material_source_hash"]
            ):
                raise StoreIntegrityError(
                    "stored prior-run operation bytes differ from their identity"
                )
            try:
                material = strict_json_loads(material_bytes.decode("utf-8"))
            except (UnicodeError, ValueError) as error:
                raise StoreIntegrityError(
                    "stored prior-run operation material is invalid"
                ) from error
            if (
                type(material) is not dict
                or material_bytes != _json(material).encode("utf-8")
            ):
                raise StoreIntegrityError(
                    "stored prior-run operation material is not canonical"
                )
            if row["operation_kind"] == "MUTATION":
                derivations.append(
                    CaseMutationDerivationBundle(
                        CaseMutationBundle(operation_bytes)
                    )
                )
            elif row["operation_kind"] == "NATIVE_REPLAY":
                derivations.append(
                    self._stored_native_replay_bundle(
                        material,
                        operation_bytes,
                    )
                )
            else:
                raise StoreIntegrityError(
                    "stored prior-run operation kind is unsupported"
                )

        closure = self._rebuild_a08_derivation_closure(
            root_context.bundle,
            tuple(derivations),
        )
        if (
            closure.terminal_context.case() != verified_context.case()
            or closure.terminal_context.assurance().to_dict()
            != verified_context.assurance().to_dict()
            or tuple(
                lineage.lineage_hash
                for lineage in closure.terminal_context.lineages
            )
            != tuple(
                lineage.lineage_hash for lineage in verified_context.lineages
            )
        ):
            raise StoreIntegrityError(
                "stored prior-run raw closure differs after independent rebuild"
            )
        return closure

    def _stage_case_source_lineages(
        self,
        context: _CaseSourceContext,
    ) -> bool:
        self.require_a08_schema()
        if not _is_sealed_case_source_context(context):
            raise StoreIntegrityError(
                "case lineage persistence requires a sealed rebuilt context"
            )
        created = False
        for lineage in context.lineages:
            operation_material_bytes = lineage._operation_material_json.encode(
                "utf-8"
            )
            if (
                self._stage_a08_blob(lineage._operation_blob_bytes)
                != lineage.operation_blob_source_hash
                or self._stage_a08_blob(operation_material_bytes)
                != lineage.operation_material_source_hash
            ):
                raise StoreIntegrityError(
                    "case lineage raw material differs from its identity"
                )
            entity_values = (
                lineage.lineage_hash,
                lineage.contract_version,
                lineage.root_binding_hash,
                lineage.parent_lineage_hash,
                lineage.input_case_hash,
                lineage.output_case_hash,
                lineage.operation_kind,
                lineage.operation_contract_version,
                lineage.operation_material_hash,
                lineage.operation_blob_source_hash,
                len(lineage._operation_blob_bytes),
                lineage.operation_material_source_hash,
                len(operation_material_bytes),
                _json(self._case_lineage_payload(lineage)),
            )
            inserted = self.connection.execute(
                """INSERT OR IGNORE INTO case_lineage_bindings(
                   lineage_hash,lineage_contract_version,root_binding_hash,
                   parent_lineage_hash,input_case_hash,output_case_hash,
                   operation_kind,operation_contract_version,
                   operation_material_hash,operation_blob_source_hash,
                   operation_blob_size_bytes,operation_material_source_hash,
                   operation_material_size_bytes,canonical_payload_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                entity_values,
            ).rowcount
            if inserted:
                created = True
                entity = self._case_lineage_entity(lineage.lineage_hash)
                if entity is None:
                    raise StoreIntegrityError(
                        "case lineage disappeared during persistence"
                    )
                self._append_audit(
                    "case_lineage_binding",
                    lineage.lineage_hash,
                    "CASE_LINEAGE_BINDING_RECORDED",
                    {
                        "primary_key": {"lineage_hash": lineage.lineage_hash},
                        "entity_fingerprint": _fingerprint(entity),
                    },
                )
            else:
                row = self.connection.execute(
                    "SELECT * FROM case_lineage_bindings WHERE lineage_hash=?",
                    (lineage.lineage_hash,),
                ).fetchone()
                if row is None or not self._lineage_row_matches_rebuilt(
                    row, lineage
                ):
                    raise StoreIntegrityError(
                        "case lineage identity conflicts with stored content"
                    )
            self._fault_point("a08_after_case_lineage_binding")
        terminal = context.lineages[-1].lineage_hash if context.lineages else None
        rebuilt = self._stored_case_source_context_with_lineage(
            context.case_source_set.source_set_hash,
            terminal,
        )
        if (
            rebuilt.case() != context.case()
            or rebuilt.assurance().to_dict() != context.assurance().to_dict()
        ):
            raise StoreIntegrityError("case lineage final semantic preflight failed")
        return created

    def _case_lineage_entity_is_semantically_valid(
        self,
        entity: dict[str, Any],
    ) -> bool:
        try:
            lineage = entity["lineage"]
            source = self.connection.execute(
                "SELECT source_set_hash FROM case_source_sets "
                "WHERE root_binding_hash=?",
                (lineage["root_binding_hash"],),
            ).fetchone()
            if source is None:
                return False
            rebuilt = self._stored_case_source_context_with_lineage(
                source["source_set_hash"],
                lineage["lineage_hash"],
            )
            current = self._case_lineage_entity(lineage["lineage_hash"])
            return (
                rebuilt.lineages[-1].lineage_hash == lineage["lineage_hash"]
                and current is not None
                and _fingerprint(current) == _fingerprint(entity)
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    @staticmethod
    def _run_case_source_payload(
        run_id: str,
        context: _CaseSourceContext,
    ) -> dict[str, Any]:
        return {"run_id": run_id, **context.assurance().to_dict()}

    def _run_case_source_set_entity(
        self,
        run_id: str,
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM run_case_source_sets WHERE run_id=?",
            (run_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def _unbound_run_case_source_payload(run_id: str) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "case_source_assurance_state": CASE_SOURCE_UNBOUND,
            "case_source_pack_contract_version": None,
            "case_source_set_contract_version": None,
            "case_source_set_hash": None,
            "case_source_binding_hash": None,
            "case_source_lineage_contract_version": None,
            "case_source_lineage_hash": None,
        }

    @classmethod
    def _unbound_run_case_source_entity(
        cls,
        run_id: str,
    ) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "case_source_assurance_state": CASE_SOURCE_UNBOUND,
            "source_set_hash": None,
            "root_binding_hash": None,
            "terminal_lineage_hash": None,
            "canonical_payload_json": _json(
                cls._unbound_run_case_source_payload(run_id)
            ),
        }

    def _stage_unbound_run_case_source_set(
        self,
        result: RunResult,
    ) -> bool:
        """Persist the exact CURRENT_V4/U join for public standalone runs."""

        if type(result) is not RunResult or (
            result.run_result_contract_version != RUN_RESULT_CONTRACT_VERSION
            or result.run_identity_version != RUN_IDENTITY_VERSION
            or {
                key: getattr(result, key)
                for key in _CASE_SOURCE_ASSURANCE_KEYS
            }
            != {
                key: value
                for key, value in self._unbound_run_case_source_payload(
                    result.run_id
                ).items()
                if key != "run_id"
            }
        ):
            raise StoreIntegrityError(
                "standalone A08 run requires an exact CURRENT_V4/U source tuple"
            )
        entity = self._unbound_run_case_source_entity(result.run_id)
        inserted = self.connection.execute(
            """INSERT OR IGNORE INTO run_case_source_sets(
               run_id,case_source_assurance_state,source_set_hash,
               root_binding_hash,terminal_lineage_hash,canonical_payload_json)
               VALUES (?,?,?,?,?,?)""",
            tuple(entity.values()),
        ).rowcount
        if not inserted:
            if self._run_case_source_set_entity(result.run_id) != entity:
                raise StoreIntegrityError(
                    "standalone run source identity conflicts with stored content"
                )
            return False
        self._append_audit(
            "run_case_source_set",
            result.run_id,
            "RUN_CASE_SOURCE_SET_RECORDED",
            {
                "primary_key": {"run_id": result.run_id},
                "entity_fingerprint": _fingerprint(entity),
            },
        )
        self._fault_point("a08_after_run_case_source_set")
        return True

    def _stage_run_case_source_set(
        self,
        result: RunResult,
        context: _CaseSourceContext,
    ) -> bool:
        if type(result) is not RunResult or not _is_sealed_case_source_context(
            context
        ):
            raise StoreIntegrityError(
                "run source persistence requires internal rebuilt objects"
            )
        assurance = context.assurance()
        assurance_payload = assurance.to_dict()
        if any(
            getattr(result, key) != value
            for key, value in assurance_payload.items()
        ):
            raise StoreIntegrityError(
                "run source tuple differs from the rebuilt source context"
            )
        terminal = context.lineages[-1] if context.lineages else None
        payload = self._run_case_source_payload(result.run_id, context)
        entity = {
            "run_id": result.run_id,
            "case_source_assurance_state": assurance.case_source_assurance_state,
            "source_set_hash": assurance.case_source_set_hash,
            "root_binding_hash": assurance.case_source_binding_hash,
            "terminal_lineage_hash": (
                None if terminal is None else terminal.lineage_hash
            ),
            "canonical_payload_json": _json(payload),
        }
        inserted = self.connection.execute(
            """INSERT OR IGNORE INTO run_case_source_sets(
               run_id,case_source_assurance_state,source_set_hash,
               root_binding_hash,terminal_lineage_hash,canonical_payload_json)
               VALUES (?,?,?,?,?,?)""",
            tuple(entity.values()),
        ).rowcount
        if not inserted:
            row = self._run_case_source_set_entity(result.run_id)
            if row != entity:
                raise StoreIntegrityError(
                    "run source identity conflicts with different stored content"
                )
            return False
        self._append_audit(
            "run_case_source_set",
            result.run_id,
            "RUN_CASE_SOURCE_SET_RECORDED",
            {
                "primary_key": {"run_id": result.run_id},
                "entity_fingerprint": _fingerprint(entity),
            },
        )
        self._fault_point("a08_after_run_case_source_set")
        return True

    def _stage_a08_source_run(
        self,
        result: RunResult,
        context: _CaseSourceContext,
        validation_context: _ValidationEvidenceContext,
    ) -> bool:
        """Persist one internally rebuilt v4 run and its A08/validation joins."""

        if (
            type(result) is not RunResult
            or not _is_sealed_case_source_context(context)
            or type(validation_context) is not _ValidationEvidenceContext
            or not validation_context.is_sealed()
        ):
            raise StoreIntegrityError(
                "A08 replay run requires sealed call-local contexts"
            )
        expected = _evaluate_source_rooted_case(
            context.case(),
            context._reference_context,
            validation_context,
            context,
            expected_validation_phase=validation_context.phase,
        )
        if expected.to_dict() != result.to_dict():
            raise StoreIntegrityError(
                "A08 replay run differs from exact source re-evaluation"
            )
        self._save_case(context.case())
        entity = self._run_entity(
            result.run_id,
            result.case_id,
            str(result.overall_status),
            result.ruleset_version,
            _json(result.to_dict()),
        )
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO runs("
            "run_id,case_id,status,ruleset_version,payload_json) "
            "VALUES (?,?,?,?,?)",
            tuple(entity.values()),
        ).rowcount
        if inserted:
            self._append_audit(
                "run",
                result.run_id,
                "CHECK_RUN_RECORDED",
                {
                    "primary_key": {"run_id": result.run_id},
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        else:
            row = self.connection.execute(
                "SELECT run_id,case_id,status,ruleset_version,payload_json "
                "FROM runs WHERE run_id=?",
                (result.run_id,),
            ).fetchone()
            if row is None or dict(row) != entity:
                raise StoreIntegrityError(
                    "A08 replay run identity conflicts with stored content"
                )
        self._save_run_validation_link(result.run_id, validation_context)
        self._stage_run_case_source_set(result, context)
        return bool(inserted)

    def _source_run_entity_is_semantically_valid(
        self,
        entity: dict[str, Any],
    ) -> bool:
        try:
            payload = strict_json_loads(entity["payload_json"])
            if type(payload) is not dict:
                return False
            link = self._run_case_source_set_entity(entity["run_id"])
            if link is None:
                return False
            source_payload = strict_json_loads(link["canonical_payload_json"])
            if (
                type(source_payload) is not dict
                or link["canonical_payload_json"] != _json(source_payload)
                or source_payload.get("run_id") != entity["run_id"]
            ):
                return False
            source_tuple = {
                key: payload.get(key)
                for key in (
                    "case_source_assurance_state",
                    "case_source_pack_contract_version",
                    "case_source_set_contract_version",
                    "case_source_set_hash",
                    "case_source_binding_hash",
                    "case_source_lineage_contract_version",
                    "case_source_lineage_hash",
                )
            }
            if source_payload != {"run_id": entity["run_id"], **source_tuple}:
                return False
            source_state = source_tuple["case_source_assurance_state"]
            if source_state not in {CASE_SOURCE_BOUND, CASE_SOURCE_DERIVED}:
                return False
            terminal_hash = link["terminal_lineage_hash"]
            if (
                link["case_source_assurance_state"] != source_state
                or link["source_set_hash"] != source_tuple["case_source_set_hash"]
                or link["root_binding_hash"]
                != source_tuple["case_source_binding_hash"]
                or (
                    source_state == CASE_SOURCE_BOUND
                    and terminal_hash is not None
                )
                or (
                    source_state == CASE_SOURCE_DERIVED
                    and terminal_hash != source_tuple["case_source_lineage_hash"]
                )
            ):
                return False
            context = self._stored_case_source_context_with_lineage(
                link["source_set_hash"],
                terminal_hash,
            )
            if context.assurance().to_dict() != source_tuple:
                return False
            case_row = self.connection.execute(
                "SELECT payload_json FROM cases WHERE case_id=? AND case_hash=?",
                (entity["case_id"], payload.get("case_hash")),
            ).fetchone()
            if case_row is None or strict_json_loads(case_row["payload_json"]) != (
                context.case()
            ):
                return False
            reference_row = self.connection.execute(
                "SELECT reference_set_hash FROM run_reference_sets WHERE run_id=?",
                (entity["run_id"],),
            ).fetchone()
            if reference_row is None:
                source_admission = self.connection.execute(
                    "SELECT 1 FROM replay_admissions WHERE "
                    "json_extract(payload_json,'$.contract_version')=? AND ("
                    "json_extract(payload_json,'$.before_run.run_id')=? OR "
                    "json_extract(payload_json,'$.after_run.run_id')=?) LIMIT 1",
                    (
                        A08_REPLAY_ADMISSION_CONTRACT_VERSION,
                        entity["run_id"],
                        entity["run_id"],
                    ),
                ).fetchone()
                if source_admission is None:
                    return False
            elif reference_row["reference_set_hash"] != (
                context._reference_context.reference_set_hash
            ):
                return False
            validation_row = self.connection.execute(
                "SELECT evidence_set_hash FROM run_validation_sets WHERE run_id=?",
                (entity["run_id"],),
            ).fetchone()
            validation_bundle = (
                None
                if validation_row is None
                else self._load_validation_evidence_bundle(
                    validation_row["evidence_set_hash"]
                )
            )
            validation_phase = "SOURCE"
            if validation_row is not None:
                phase_row = self.connection.execute(
                    "SELECT phase FROM validation_evidence_sets "
                    "WHERE evidence_set_hash=?",
                    (validation_row["evidence_set_hash"],),
                ).fetchone()
                if phase_row is None or phase_row["phase"] not in {
                    "SOURCE",
                    "RESOLVED",
                }:
                    return False
                validation_phase = phase_row["phase"]
            validation_context = (
                None
                if validation_bundle is None
                else _prepare_validation_evidence_context(
                    validation_bundle,
                    context.case(),
                    expected_phase=validation_phase,
                )
            )
            expected = _evaluate_source_rooted_case(
                context.case(),
                context._reference_context,
                validation_context,
                context,
                expected_validation_phase=validation_phase,
            )
            return (
                entity["run_id"] == expected.run_id
                and entity["case_id"] == expected.case_id
                and entity["status"] == str(expected.overall_status)
                and entity["ruleset_version"] == expected.ruleset_version
                and entity["payload_json"] == _json(expected.to_dict())
                and (
                    self._derived_reference_snapshot_matches_context(context)
                    or (
                        bool(context.lineages)
                        and any(
                            lineage.operation_kind == "NATIVE_REPLAY"
                            and lineage.operation_material().get(
                                "controlled_reference_set_hash"
                            )
                            == context._reference_context.reference_set_hash
                            for lineage in reversed(context.lineages)
                        )
                    )
                )
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _run_case_source_set_entity_is_semantically_valid(
        self,
        entity: dict[str, Any],
    ) -> bool:
        try:
            if self._run_case_source_set_entity(entity["run_id"]) != entity:
                return False
            run = self.connection.execute(
                "SELECT run_id,case_id,status,ruleset_version,payload_json "
                "FROM runs WHERE run_id=?",
                (entity["run_id"],),
            ).fetchone()
            if run is None:
                return False
            if entity["case_source_assurance_state"] == CASE_SOURCE_UNBOUND:
                payload = strict_json_loads(run["payload_json"])
                return (
                    type(payload) is dict
                    and _stored_run_payload_profile(payload)
                    == _RUN_PROFILE_CURRENT_V4
                    and entity
                    == self._unbound_run_case_source_entity(entity["run_id"])
                    and {
                        key: payload.get(key)
                        for key in _CASE_SOURCE_ASSURANCE_KEYS
                    }
                    == {
                        key: value
                        for key, value in self._unbound_run_case_source_payload(
                            entity["run_id"]
                        ).items()
                        if key != "run_id"
                    }
                    and self._run_entity_is_semantically_valid(dict(run))
                )
            return self._source_run_entity_is_semantically_valid(dict(run))
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _case_source_coverage_is_complete(self) -> bool:
        if self.feature_profile() != STORE_FEATURE_A08_0_1:
            return True
        try:
            all_sources = {
                row["source_set_hash"]
                for row in self.connection.execute(
                    "SELECT source_set_hash FROM case_source_sets"
                )
            }
            all_lineages = {
                row["lineage_hash"]
                for row in self.connection.execute(
                    "SELECT lineage_hash FROM case_lineage_bindings"
                )
            }
            linked_sources: set[str] = set()
            reachable_lineages: set[str] = set()
            linked_unbound_runs: set[str] = set()
            links = self.connection.execute(
                "SELECT * FROM run_case_source_sets ORDER BY run_id"
            ).fetchall()
            for link in links:
                state = link["case_source_assurance_state"]
                if state == CASE_SOURCE_UNBOUND:
                    entity = dict(link)
                    if (
                        not self._run_case_source_set_entity_is_semantically_valid(
                            entity
                        )
                        or link["source_set_hash"] is not None
                        or link["root_binding_hash"] is not None
                        or link["terminal_lineage_hash"] is not None
                    ):
                        return False
                    linked_unbound_runs.add(link["run_id"])
                    continue
                if state not in {CASE_SOURCE_BOUND, CASE_SOURCE_DERIVED}:
                    return False
                source_set_hash = link["source_set_hash"]
                if source_set_hash not in all_sources:
                    return False
                linked_sources.add(source_set_hash)
                terminal = link["terminal_lineage_hash"]
                if state == CASE_SOURCE_BOUND:
                    if terminal is not None:
                        return False
                    continue
                if terminal is None:
                    return False
                context = self._stored_case_source_context_with_lineage(
                    source_set_hash,
                    terminal,
                )
                reachable_lineages.update(
                    lineage.lineage_hash for lineage in context.lineages
                )

            expected_unbound_runs: set[str] = set()
            for run in self.connection.execute(
                "SELECT run_id,payload_json FROM runs"
            ):
                payload = strict_json_loads(run["payload_json"])
                if (
                    type(payload) is dict
                    and _stored_run_payload_profile(payload)
                    == _RUN_PROFILE_CURRENT_V4
                    and payload.get("case_source_assurance_state")
                    == CASE_SOURCE_UNBOUND
                    and not self._run_is_linked_to_replay_admission(
                        run["run_id"]
                    )
                ):
                    expected_unbound_runs.add(run["run_id"])
            return (
                linked_sources == all_sources
                and reachable_lineages == all_lineages
                and linked_unbound_runs == expected_unbound_runs
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    @staticmethod
    def _a08_reference_bundle_for_context(
        context: _CaseSourceContext,
        root_source_bundle: CaseSourceBundle,
        derivations: tuple[Any, ...],
    ) -> ControlledReferenceBundle:
        """Recover one effective reference pack only from closure-owned bytes."""

        if (
            not _is_sealed_case_source_context(context)
            or type(root_source_bundle) is not CaseSourceBundle
            or type(derivations) is not tuple
        ):
            raise StoreIntegrityError(
                "A08 effective references require an exact raw closure"
            )
        allowed_keys = {
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
        }
        candidates: list[tuple[dict[str, Any], bytes]] = []

        def add_candidates(
            manifest_bytes: bytes,
            raw_members: dict[str, tuple[str, str, bytes]],
        ) -> None:
            try:
                manifest = strict_json_loads(manifest_bytes.decode("utf-8"))
            except (UnicodeError, ValueError) as error:
                raise StoreIntegrityError(
                    "A08 reference source manifest is invalid"
                ) from error
            if type(manifest) is not dict or type(manifest.get("documents")) is not list:
                raise StoreIntegrityError(
                    "A08 reference source manifest documents are missing"
                )
            for raw_spec in manifest["documents"]:
                if (
                    type(raw_spec) is not dict
                    or raw_spec.get("document_type")
                    not in {"SOP", "CONTROL_PLAN", "INSPECTION_RECORD"}
                ):
                    continue
                document_id = raw_spec.get("document_id")
                member = raw_members.get(str(document_id))
                if member is None:
                    continue
                source_id, filename, raw_bytes = member
                spec = {
                    key: value
                    for key, value in raw_spec.items()
                    if key in allowed_keys
                }
                if spec.get("table_selector") is None:
                    spec.pop("table_selector", None)
                if (
                    spec.get("source_id") != source_id
                    or spec.get("source_path") != filename
                ):
                    raise StoreIntegrityError(
                        "A08 reference member differs from its raw manifest"
                    )
                candidates.append((spec, raw_bytes))

        try:
            root_manifest = strict_json_loads(
                root_source_bundle.manifest_bytes.decode("utf-8")
            )
        except (UnicodeError, ValueError) as error:
            raise StoreIntegrityError(
                "A08 root reference manifest is invalid"
            ) from error
        if type(root_manifest) is not dict or type(
            root_manifest.get("documents")
        ) is not list:
            raise StoreIntegrityError(
                "A08 root reference manifest documents are missing"
            )
        root_members = {
            member.document_type: member
            for member in root_source_bundle.members
        }
        root_raw_members: dict[str, tuple[str, str, bytes]] = {}
        for spec in root_manifest["documents"]:
            if type(spec) is not dict:
                continue
            member = root_members.get(spec.get("document_type"))
            if member is None:
                continue
            root_raw_members[str(spec.get("document_id"))] = (
                member.source_id,
                member.source_path,
                member.raw_bytes,
            )
        add_candidates(
            root_source_bundle.manifest_bytes,
            root_raw_members,
        )
        for derivation in derivations:
            if type(derivation) is CaseMutationDerivationBundle:
                continue
            if type(derivation) is not NativeReplayDerivationBundle:
                raise StoreIntegrityError(
                    "A08 reference rebuild rejects unknown derivation carriers"
                )
            add_candidates(
                derivation.artifact_bundle.canonical_manifest_bytes,
                {
                    member.document_id: (
                        member.source_id,
                        member.filename,
                        member.raw_bytes,
                    )
                    for member in derivation.artifact_bundle.members
                },
            )

        reference_context = context._reference_context
        documents = {
            item["document_type"]: item
            for item in reference_context.documents()
        }
        witnesses = reference_context.witness_by_type()
        if set(documents) != {"SOP", "CONTROL_PLAN", "INSPECTION_RECORD"}:
            raise StoreIntegrityError(
                "A08 effective reference documents are incomplete"
            )
        selected: list[tuple[dict[str, Any], bytes]] = []
        for document_type in sorted(documents):
            document = documents[document_type]
            witness = witnesses.get(document_type)
            if witness is None:
                raise StoreIntegrityError(
                    "A08 effective reference witness is missing"
                )
            matches: dict[tuple[str, bytes], tuple[dict[str, Any], bytes]] = {}
            for spec, raw_bytes in candidates:
                if (
                    spec.get("document_type") != document_type
                    or spec.get("document_id") != witness.document_id
                    or spec.get("source_id") != witness.source_id
                    or spec.get("source_path") != witness.relative_path
                    or spec.get("revision") != witness.revision
                    or spec.get("revision") != document.get("revision")
                    or spec.get("status") != document.get("status")
                    or spec.get("owner") != document.get("owner")
                    or spec.get("revision_date")
                    != document.get("revision_date")
                    or hashlib.sha256(raw_bytes).hexdigest()
                    != witness.source_hash
                    or raw_bytes != witness.raw_bytes
                ):
                    continue
                matches[(_json(spec), raw_bytes)] = (spec, raw_bytes)
            if len(matches) != 1:
                raise StoreIntegrityError(
                    "A08 effective reference bytes are missing or ambiguous"
                )
            selected.append(next(iter(matches.values())))

        selected.sort(
            key=lambda item: (
                normalized_identity(str(item[0]["document_id"])),
                str(item[0]["document_id"]),
            )
        )
        bundle = ControlledReferenceBundle(
            canonical_manifest_bytes=_json(
                {
                    "contract_version": CONTROLLED_REFERENCE_PACK_VERSION,
                    "documents": [spec for spec, _raw in selected],
                }
            ).encode("utf-8"),
            members=tuple(
                ControlledReferenceMember(
                    source_id=str(spec["source_id"]),
                    document_id=str(spec["document_id"]),
                    filename=str(spec["source_path"]),
                    raw_bytes=raw_bytes,
                )
                for spec, raw_bytes in selected
            ),
        )
        rebuilt = _prepare_controlled_reference_context(bundle)
        if rebuilt != reference_context:
            raise StoreIntegrityError(
                "A08 effective reference pack differs from the rebuilt context"
            )
        return bundle

    def _a08_reference_bundles_for_closure(
        self,
        root_source_bundle: CaseSourceBundle,
        derivations: tuple[Any, ...],
        root_context: _CaseSourceContext,
        native_steps: tuple[_A08NativeStepPersistence, ...],
    ) -> tuple[ControlledReferenceBundle, ...]:
        contexts = (root_context,) + tuple(
            step.after_context for step in native_steps
        )
        bundles: list[ControlledReferenceBundle] = []
        seen: set[str] = set()
        for context in contexts:
            reference_hash = context._reference_context.reference_set_hash
            if reference_hash in seen:
                continue
            bundle = self._a08_reference_bundle_for_context(
                context,
                root_source_bundle,
                derivations,
            )
            seen.add(reference_hash)
            bundles.append(bundle)
        return tuple(bundles)

    def _rebuild_a08_derivation_closure(
        self,
        root_source_bundle: CaseSourceBundle,
        prior_derivations: tuple[Any, ...],
        current_mutation: CaseMutationBundle | None = None,
    ) -> _A08DerivationPersistence:
        """Rebuild root -> exact ordered derivations without accepting state."""

        if type(root_source_bundle) is not CaseSourceBundle:
            raise StoreIntegrityError(
                "A08 derivation closure requires an exact root source bundle"
            )
        if type(prior_derivations) is not tuple:
            raise StoreIntegrityError(
                "A08 derivation closure requires an exact ordered tuple"
            )
        if current_mutation is not None and type(current_mutation) is not (
            CaseMutationBundle
        ):
            raise StoreIntegrityError(
                "A08 derivation closure requires exact current mutation bytes"
            )
        root_context = _prepare_case_source_context(root_source_bundle)
        context = root_context
        native_steps: list[_A08NativeStepPersistence] = []
        effective_derivations = list(prior_derivations)
        for derivation in prior_derivations:
            if type(derivation) is CaseMutationDerivationBundle:
                context = _derive_case_source_mutation(
                    context,
                    derivation.mutation_bundle,
                )
            elif type(derivation) is NativeReplayDerivationBundle:
                before_context = context
                context, replay = _replay_one_source_derivation(
                    context,
                    derivation,
                )
                native_steps.append(
                    _A08NativeStepPersistence(
                        before_context,
                        context,
                        derivation,
                        replay,
                    )
                )
            else:
                raise StoreIntegrityError(
                    "A08 derivation closure rejects unknown carriers"
                )
        if current_mutation is not None:
            current = CaseMutationDerivationBundle(current_mutation)
            effective_derivations.append(current)
            context = _derive_case_source_mutation(context, current_mutation)
        derivations = tuple(effective_derivations)
        native_tuple = tuple(native_steps)
        return _A08DerivationPersistence(
            root_bundle=root_source_bundle,
            derivations=derivations,
            root_context=root_context,
            terminal_context=context,
            native_steps=native_tuple,
            reference_bundles=self._a08_reference_bundles_for_closure(
                root_source_bundle,
                derivations,
                root_context,
                native_tuple,
            ),
        )

    def _stage_a08_reference_bundle(
        self,
        bundle: ControlledReferenceBundle,
    ) -> bool:
        context = _prepare_controlled_reference_context(bundle)
        created = self._stage_controlled_reference_bundle(
            context.reference_set_hash,
            bundle,
        )
        if not created:
            return False
        entity = self._controlled_reference_set_entity(
            context.reference_set_hash
        )
        if entity is None:
            raise StoreIntegrityError(
                "A08 effective reference set disappeared"
            )
        self._append_audit(
            "controlled_reference_set",
            context.reference_set_hash,
            "CONTROLLED_REFERENCE_SET_RECORDED",
            {
                "primary_key": {
                    "reference_set_hash": context.reference_set_hash
                },
                "entity_fingerprint": _fingerprint(entity),
            },
        )
        return True

    def save_source_run_from_bundles(
        self,
        root_source_bundle: CaseSourceBundle,
        prior_derivations: tuple[Any, ...] = (),
        current_mutation: CaseMutationBundle | None = None,
        validation_bundle: ValidationEvidenceBundle | None = None,
    ) -> RunResult:
        self.require_a08_schema()
        if type(root_source_bundle) is not CaseSourceBundle:
            raise StoreIntegrityError(
                "trusted source run requires exact root Case source bytes"
            )
        if type(prior_derivations) is not tuple:
            raise StoreIntegrityError(
                "trusted source run requires an exact ordered derivation tuple"
            )
        if current_mutation is not None and type(current_mutation) is not (
            CaseMutationBundle
        ):
            raise StoreIntegrityError(
                "trusted source run requires exact mutation raw bytes"
            )
        if validation_bundle is not None and type(validation_bundle) is not (
            ValidationEvidenceBundle
        ):
            raise StoreIntegrityError(
                "trusted source run requires exact validation bytes"
            )
        try:
            closure = self._rebuild_a08_derivation_closure(
                root_source_bundle,
                prior_derivations,
                current_mutation,
            )
            context = closure.terminal_context
            case = context.case()
            validation_context = (
                None
                if validation_bundle is None
                else _prepare_validation_evidence_context(
                    validation_bundle,
                    case,
                    expected_phase="SOURCE",
                )
            )
            result = _evaluate_source_rooted_case(
                case,
                context._reference_context,
                validation_context,
                context,
                expected_validation_phase="SOURCE",
            )
            expected_case_hash = (
                context.root_case_hash
                if not context.lineages
                else context.lineages[-1].output_case_hash
            )
            if result.case_hash != expected_case_hash:
                raise StoreIntegrityError(
                    "trusted source run differs from the rebuilt terminal Case"
                )
        except StoreIntegrityError:
            raise
        except (
            ApprovalGateError,
            AuthorizationAuthenticityError,
            CaseSourceError,
            RevisionArtifactError,
            UnicodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise StoreIntegrityError(
                "trusted source run raw material cannot be rebuilt"
            ) from error

        with self.connection:
            self._stage_case_source_context(closure.root_context)
            for reference_bundle in closure.reference_bundles:
                self._stage_a08_reference_bundle(reference_bundle)
            for native_step in closure.native_steps:
                self._stage_a08_native_step_raw(native_step)
            self._stage_case_source_lineages(context)
            created_validation_set = False
            if validation_context is not None and validation_bundle is not None:
                created_validation_set = self._stage_validation_evidence_bundle(
                    validation_context,
                    validation_bundle,
                )
            self._save_case(case)
            payload_json = _json(result.to_dict())
            run_entity = self._run_entity(
                result.run_id,
                result.case_id,
                str(result.overall_status),
                result.ruleset_version,
                payload_json,
            )
            inserted_run = self.connection.execute(
                "INSERT OR IGNORE INTO runs("
                "run_id,case_id,status,ruleset_version,payload_json) "
                "VALUES (?,?,?,?,?)",
                tuple(run_entity.values()),
            ).rowcount
            if inserted_run:
                self._append_audit(
                    "run",
                    result.run_id,
                    "CHECK_RUN_RECORDED",
                    {
                        "primary_key": {"run_id": result.run_id},
                        "entity_fingerprint": _fingerprint(run_entity),
                    },
                )
            else:
                stored_run = self.connection.execute(
                    "SELECT run_id,case_id,status,ruleset_version,payload_json "
                    "FROM runs WHERE run_id=?",
                    (result.run_id,),
                ).fetchone()
                if stored_run is None or dict(stored_run) != run_entity:
                    raise StoreIntegrityError(
                        "source run identity conflicts with stored content"
                    )
            linked = self.connection.execute(
                "INSERT OR IGNORE INTO run_reference_sets("
                "run_id,reference_set_hash) VALUES (?,?)",
                (result.run_id, context._reference_context.reference_set_hash),
            ).rowcount
            if linked:
                reference_entity = {
                    "run_id": result.run_id,
                    "reference_set_hash": (
                        context._reference_context.reference_set_hash
                    ),
                }
                self._append_audit(
                    "run_reference_set",
                    result.run_id,
                    "RUN_REFERENCE_SET_RECORDED",
                    {
                        "primary_key": {"run_id": result.run_id},
                        "entity_fingerprint": _fingerprint(reference_entity),
                    },
                )
            else:
                reference_row = self.connection.execute(
                    "SELECT reference_set_hash FROM run_reference_sets "
                    "WHERE run_id=?",
                    (result.run_id,),
                ).fetchone()
                if reference_row is None or reference_row[
                    "reference_set_hash"
                ] != context._reference_context.reference_set_hash:
                    raise StoreIntegrityError(
                        "source run reference identity conflicts with stored content"
                    )
            if validation_context is not None:
                self._save_run_validation_link(result.run_id, validation_context)
            self._stage_run_case_source_set(result, context)
            if created_validation_set and validation_context is not None:
                validation_entity = self._validation_evidence_set_entity(
                    validation_context.evidence_set_hash
                )
                if validation_entity is None:
                    raise StoreIntegrityError(
                        "source run validation set disappeared"
                    )
                self._append_audit(
                    "validation_evidence_set",
                    validation_context.evidence_set_hash,
                    "VALIDATION_EVIDENCE_SET_RECORDED",
                    {
                        "primary_key": {
                            "evidence_set_hash": (
                                validation_context.evidence_set_hash
                            )
                        },
                        "entity_fingerprint": _fingerprint(validation_entity),
                    },
                )
            self._fault_point("a08_source_run_before_final_preflight")
            stored_run = self.connection.execute(
                "SELECT run_id,case_id,status,ruleset_version,payload_json "
                "FROM runs WHERE run_id=?",
                (result.run_id,),
            ).fetchone()
            if (
                stored_run is None
                or not self._source_run_entity_is_semantically_valid(
                    dict(stored_run)
                )
                or not self.verify_audit_chain()
            ):
                raise StoreIntegrityError(
                    "trusted source run final semantic preflight failed"
                )
        return result

    def replay_from_verified_prior_run(
        self,
        prior_run_id: str,
        current_replay: NativeReplayDerivationBundle,
    ) -> StatelessApprovalReplayResult:
        """Use a stored run ID only to locate and rebuild its complete raw closure."""

        self.require_a08_schema()
        if type(prior_run_id) is not str or not _is_lower_hex(
            prior_run_id, 16
        ):
            raise StoreIntegrityError(
                "verified prior replay requires one exact v4 run locator"
            )
        if type(current_replay) is not NativeReplayDerivationBundle:
            raise StoreIntegrityError(
                "verified prior replay requires exact current native raw material"
            )
        if not self.verify_audit_chain():
            raise StoreIntegrityError(
                "verified prior replay requires an intact semantic and audit store"
            )
        stored_run = self.connection.execute(
            "SELECT run_id,case_id,status,ruleset_version,payload_json "
            "FROM runs WHERE run_id=?",
            (prior_run_id,),
        ).fetchone()
        source_link = self.connection.execute(
            "SELECT * FROM run_case_source_sets WHERE run_id=?",
            (prior_run_id,),
        ).fetchone()
        if stored_run is None or source_link is None:
            raise StoreIntegrityError(
                "verified prior run locator is unknown or unbound"
            )
        if source_link["case_source_assurance_state"] not in {
            CASE_SOURCE_BOUND,
            CASE_SOURCE_DERIVED,
        }:
            raise StoreIntegrityError(
                "verified prior run locator is unknown or unbound"
            )
        terminal_hash = source_link["terminal_lineage_hash"]
        if source_link["case_source_assurance_state"] == CASE_SOURCE_BOUND:
            if terminal_hash is not None:
                raise StoreIntegrityError(
                    "verified bound prior run has an unexpected lineage"
                )
            child = self.connection.execute(
                "SELECT 1 FROM case_lineage_bindings "
                "WHERE root_binding_hash=? AND parent_lineage_hash IS NULL "
                "LIMIT 1",
                (source_link["root_binding_hash"],),
            ).fetchone()
        else:
            if not _is_lower_hex(terminal_hash, 64):
                raise StoreIntegrityError(
                    "verified derived prior run has no exact terminal lineage"
                )
            child = self.connection.execute(
                "SELECT 1 FROM case_lineage_bindings "
                "WHERE parent_lineage_hash=? LIMIT 1",
                (terminal_hash,),
            ).fetchone()
        if child is not None:
            raise StoreIntegrityError(
                "verified prior run is not the current terminal lineage"
            )

        closure = self._stored_a08_derivation_closure(
            source_link["source_set_hash"],
            terminal_hash,
        )
        context = closure.terminal_context
        assurance = context.assurance().to_dict()
        expected_link = {
            "run_id": prior_run_id,
            "case_source_assurance_state": assurance[
                "case_source_assurance_state"
            ],
            "source_set_hash": assurance["case_source_set_hash"],
            "root_binding_hash": assurance["case_source_binding_hash"],
            "terminal_lineage_hash": assurance[
                "case_source_lineage_hash"
            ],
            "canonical_payload_json": _json(
                {"run_id": prior_run_id, **assurance}
            ),
        }
        if dict(source_link) != expected_link:
            raise StoreIntegrityError(
                "verified prior run link differs from rebuilt raw lineage"
            )

        validation_link = self.connection.execute(
            "SELECT evidence_set_hash FROM run_validation_sets WHERE run_id=?",
            (prior_run_id,),
        ).fetchone()
        validation_context: _ValidationEvidenceContext | None = None
        validation_phase = "SOURCE"
        if validation_link is not None:
            validation_set = self.connection.execute(
                "SELECT phase FROM validation_evidence_sets "
                "WHERE evidence_set_hash=?",
                (validation_link["evidence_set_hash"],),
            ).fetchone()
            if validation_set is None or validation_set["phase"] not in {
                "SOURCE",
                "RESOLVED",
            }:
                raise StoreIntegrityError(
                    "verified prior run validation phase is invalid"
                )
            validation_phase = validation_set["phase"]
            validation_context = _prepare_validation_evidence_context(
                self._load_validation_evidence_bundle(
                    validation_link["evidence_set_hash"]
                ),
                context.case(),
                expected_phase=validation_phase,
            )
        rebuilt_run = _evaluate_source_rooted_case(
            context.case(),
            context._reference_context,
            validation_context,
            context,
            expected_validation_phase=validation_phase,
        )
        expected_run = self._run_entity(
            rebuilt_run.run_id,
            rebuilt_run.case_id,
            str(rebuilt_run.overall_status),
            rebuilt_run.ruleset_version,
            _json(rebuilt_run.to_dict()),
        )
        if (
            rebuilt_run.run_id != prior_run_id
            or dict(stored_run) != expected_run
            or not self._source_run_entity_is_semantically_valid(
                dict(stored_run)
            )
        ):
            raise StoreIntegrityError(
                "verified prior run differs from full raw re-evaluation"
            )
        return self.save_native_replay_from_bundles(
            closure.root_bundle,
            closure.derivations,
            current_replay,
        )

    @staticmethod
    def _derived_reference_bundle_from_case_source(
        context: _CaseSourceContext,
    ) -> ControlledReferenceBundle:
        if not _is_sealed_case_source_context(context):
            raise StoreIntegrityError(
                "derived reference persistence requires sealed Case source bytes"
            )
        try:
            manifest = strict_json_loads(context.bundle.manifest_bytes.decode("utf-8"))
        except (UnicodeError, ValueError) as error:
            raise StoreIntegrityError("case source manifest cannot be decoded") from error
        if type(manifest) is not dict or type(manifest.get("documents")) is not list:
            raise StoreIntegrityError("case source manifest documents are missing")
        allowed_keys = {
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
        }
        specs = [
            {key: value for key, value in item.items() if key in allowed_keys}
            for item in manifest["documents"]
            if type(item) is dict
            and item.get("document_type")
            in {"SOP", "CONTROL_PLAN", "INSPECTION_RECORD"}
        ]
        if len(specs) != 3 or {
            item.get("document_type") for item in specs
        } != {"SOP", "CONTROL_PLAN", "INSPECTION_RECORD"}:
            raise StoreIntegrityError(
                "case source manifest cannot derive the exact reference set"
            )
        specs.sort(
            key=lambda item: (
                normalized_identity(str(item["document_id"])),
                str(item["document_id"]),
            )
        )
        source_members = {
            member.document_type: member for member in context.bundle.members
        }
        controlled_members = tuple(
            ControlledReferenceMember(
                source_id=str(spec["source_id"]),
                document_id=str(spec["document_id"]),
                filename=str(spec["source_path"]),
                raw_bytes=source_members[str(spec["document_type"])].raw_bytes,
            )
            for spec in specs
        )
        return ControlledReferenceBundle(
            canonical_manifest_bytes=_json(
                {
                    "contract_version": CONTROLLED_REFERENCE_PACK_VERSION,
                    "documents": specs,
                }
            ).encode("utf-8"),
            members=controlled_members,
        )

    def _derived_reference_snapshot_matches_context(
        self,
        context: _CaseSourceContext,
    ) -> bool:
        try:
            reference_context = context._reference_context
            bundle = self._derived_reference_bundle_from_case_source(context)
            set_row = self.connection.execute(
                "SELECT contract_version,manifest_bytes "
                "FROM controlled_reference_sets WHERE reference_set_hash=?",
                (reference_context.reference_set_hash,),
            ).fetchone()
            if set_row is None or (
                set_row["contract_version"] != reference_context.contract_version
                or bytes(set_row["manifest_bytes"])
                != bundle.canonical_manifest_bytes
            ):
                return False
            expected = {
                witness.document_id: witness
                for witness in reference_context.witnesses
            }
            rows = self.connection.execute(
                """SELECT m.*,b.size_bytes,b.raw_bytes
                   FROM controlled_reference_members m
                   JOIN artifact_blobs b ON b.source_hash=m.source_hash
                   WHERE m.reference_set_hash=? ORDER BY m.document_id""",
                (reference_context.reference_set_hash,),
            ).fetchall()
            if len(rows) != len(expected) or {
                row["document_id"] for row in rows
            } != set(expected):
                return False
            return all(
                (
                    row["document_type"],
                    row["revision"],
                    row["source_id"],
                    row["filename"],
                    row["source_hash"],
                    row["size_bytes"],
                    bytes(row["raw_bytes"]),
                )
                == (
                    expected[row["document_id"]].document_type,
                    expected[row["document_id"]].revision,
                    expected[row["document_id"]].source_id,
                    expected[row["document_id"]].relative_path,
                    expected[row["document_id"]].source_hash,
                    len(expected[row["document_id"]].raw_bytes),
                    expected[row["document_id"]].raw_bytes,
                )
                for row in rows
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _stage_derived_reference_context(
        self,
        context: _CaseSourceContext,
    ) -> bool:
        reference_context = context._reference_context
        bundle = self._derived_reference_bundle_from_case_source(context)
        existing = self.connection.execute(
            "SELECT 1 FROM controlled_reference_sets WHERE reference_set_hash=?",
            (reference_context.reference_set_hash,),
        ).fetchone()
        if existing is not None:
            if not self._derived_reference_snapshot_matches_context(context):
                raise StoreIntegrityError(
                    "existing controlled reference set differs from Case source bytes"
                )
            return False
        witnesses = {
            witness.document_id: witness
            for witness in reference_context.witnesses
        }
        for member in bundle.members:
            witness = witnesses.get(member.document_id)
            if witness is None or (
                member.source_id != witness.source_id
                or member.filename != witness.relative_path
                or member.raw_bytes != witness.raw_bytes
            ):
                raise StoreIntegrityError(
                    "derived controlled reference member differs from source context"
                )
            if self._stage_a08_blob(member.raw_bytes) != witness.source_hash:
                raise StoreIntegrityError(
                    "derived controlled reference hash differs from source context"
                )
        self.connection.execute(
            "INSERT INTO controlled_reference_sets("
            "reference_set_hash,contract_version,manifest_bytes) VALUES (?,?,?)",
            (
                reference_context.reference_set_hash,
                reference_context.contract_version,
                bundle.canonical_manifest_bytes,
            ),
        )
        for member in bundle.members:
            witness = witnesses[member.document_id]
            self.connection.execute(
                """INSERT INTO controlled_reference_members(
                   reference_set_hash,document_id,document_type,revision,
                   source_id,filename,source_hash) VALUES (?,?,?,?,?,?,?)""",
                (
                    reference_context.reference_set_hash,
                    witness.document_id,
                    witness.document_type,
                    witness.revision,
                    witness.source_id,
                    witness.relative_path,
                    witness.source_hash,
                ),
            )
        entity = self._controlled_reference_set_entity(
            reference_context.reference_set_hash
        )
        if entity is None:
            raise StoreIntegrityError(
                "derived controlled reference set disappeared during persistence"
            )
        self._append_audit(
            "controlled_reference_set",
            reference_context.reference_set_hash,
            "CONTROLLED_REFERENCE_SET_RECORDED",
            {
                "primary_key": {
                    "reference_set_hash": reference_context.reference_set_hash
                },
                "entity_fingerprint": _fingerprint(entity),
            },
        )
        self._fault_point("a08_after_derived_reference_set")
        if not self._derived_reference_snapshot_matches_context(context):
            raise StoreIntegrityError(
                "derived controlled reference final preflight failed"
            )
        return True

    def _case_source_context_for_reference_set(
        self,
        reference_set_hash: str,
    ) -> _CaseSourceContext | None:
        if self.feature_profile() != STORE_FEATURE_A08_0_1:
            return None
        candidates = self.connection.execute(
            "SELECT source_set_hash FROM case_source_sets ORDER BY source_set_hash"
        ).fetchall()
        for row in candidates:
            try:
                context = self._stored_case_source_context(row["source_set_hash"])
            except (TypeError, ValueError, sqlite3.Error):
                continue
            if (
                context._reference_context.reference_set_hash
                == reference_set_hash
                and self._derived_reference_snapshot_matches_context(context)
            ):
                return context
        return None

    def _artifact_set_entity(self, artifact_set_hash: str) -> dict[str, Any] | None:
        artifact_set = self.connection.execute(
            "SELECT * FROM artifact_sets WHERE artifact_set_hash=?",
            (artifact_set_hash,),
        ).fetchone()
        if artifact_set is None:
            return None
        members = self.connection.execute(
            """SELECT m.*, b.size_bytes, b.raw_bytes
               FROM artifact_set_members m
               JOIN artifact_blobs b ON b.source_hash=m.source_hash
               WHERE m.artifact_set_hash=? ORDER BY m.document_id""",
            (artifact_set_hash,),
        ).fetchall()
        return {
            **{key: artifact_set[key] for key in artifact_set.keys() if key != "manifest_bytes"},
            "manifest_bytes_hash": hashlib.sha256(artifact_set["manifest_bytes"]).hexdigest(),
            "members": [
                {
                    **{key: row[key] for key in row.keys() if key != "raw_bytes"},
                    "actual_raw_hash": hashlib.sha256(row["raw_bytes"]).hexdigest(),
                }
                for row in members
            ],
        }

    def _artifact_subject_from_stored_index(
        self, artifact_set_hash: str
    ) -> dict[str, Any] | None:
        """Return the exact stored subject projection without reparsing artifacts."""

        entity = self._artifact_set_entity(artifact_set_hash)
        if entity is None or entity.get("artifact_set_hash") != artifact_set_hash:
            return None
        touched: list[dict[str, Any]] = []
        try:
            for member in entity["members"]:
                if (
                    member["actual_raw_hash"] != member["source_hash"]
                    or not _is_lower_hex(member["source_hash"], 64)
                    or member["size_bytes"] < 0
                ):
                    return None
                supersedes = strict_json_loads(member["supersedes_json"])
                if not isinstance(supersedes, dict):
                    return None
                touched.append(
                    {
                        "document_id": member["document_id"],
                        "source_id": member["source_id"],
                        "source_path": member["filename"],
                        "source_hash": member["source_hash"],
                        "size_bytes": member["size_bytes"],
                        "declared_format": member["declared_format"],
                        "detected_format": member["detected_format"],
                        "supersedes": supersedes,
                    }
                )
            return {
                "replacement_set_id": entity["replacement_set_id"],
                "artifact_set_hash": artifact_set_hash,
                "reference_contract_version": entity[
                    "reference_contract_version"
                ],
                "controlled_reference_set_hash": entity[
                    "resolved_reference_set_hash"
                ],
                "controlled_reference_source_set_hash": entity[
                    "controlled_reference_set_hash"
                ],
                "artifact_contract_version": entity[
                    "artifact_contract_version"
                ],
                "case_schema_version": entity["case_schema_version"],
                "parser_contract_version": entity["parser_contract_version"],
                "mapping_contract_version": entity["mapping_contract_version"],
                "security_root_policy_version": entity[
                    "security_root_policy_version"
                ],
                "touched_document_artifacts": touched,
            }
        except (KeyError, TypeError, ValueError):
            return None

    def _load_artifact_bundle(self, artifact_set_hash: str) -> RevisionArtifactBundle:
        artifact_set = self.connection.execute(
            "SELECT * FROM artifact_sets WHERE artifact_set_hash=?",
            (artifact_set_hash,),
        ).fetchone()
        if artifact_set is None:
            raise StoreIntegrityError("artifact set is missing")
        try:
            manifest = strict_json_loads(
                bytes(artifact_set["manifest_bytes"]).decode("utf-8")
            )
            manifest, canonical_manifest_bytes = canonicalize_artifact_manifest(
                manifest
            )
        except (UnicodeError, ValueError) as error:
            raise StoreIntegrityError("stored artifact manifest is invalid") from error
        if bytes(artifact_set["manifest_bytes"]) != canonical_manifest_bytes:
            raise StoreIntegrityError("stored artifact manifest is not canonical")
        expected_set_fields = {
            "replacement_set_id": manifest.get("replacement_set_id"),
            "artifact_contract_version": ARTIFACT_CONTRACT_VERSION,
            "case_schema_version": manifest.get("case_schema_version"),
            "parser_contract_version": manifest.get("parser_contract_version"),
            "mapping_contract_version": manifest.get("mapping_contract_version"),
            "security_root_policy_version": manifest.get(
                "security_root_policy_version"
            ),
        }
        if any(
            artifact_set[field] != expected
            for field, expected in expected_set_fields.items()
        ):
            raise StoreIntegrityError(
                "stored artifact set metadata differs from its manifest"
            )
        specs: dict[str, dict[str, Any]] = {}
        for item in manifest["documents"]:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("document_id"), str)
                or item["document_id"] in specs
            ):
                raise StoreIntegrityError(
                    "stored artifact manifest document identities are invalid"
                )
            specs[item["document_id"]] = item
        rows = self.connection.execute(
            """SELECT m.source_id, m.document_id, m.filename, m.source_hash,
                      m.declared_format, m.detected_format, m.supersedes_json,
                      b.size_bytes, b.raw_bytes
               FROM artifact_set_members m
               JOIN artifact_blobs b ON b.source_hash=m.source_hash
               WHERE m.artifact_set_hash=? ORDER BY m.document_id""",
            (artifact_set_hash,),
        ).fetchall()
        if len(rows) != len(specs) or {row["document_id"] for row in rows} != set(specs):
            raise StoreIntegrityError(
                "stored artifact members differ from the manifest exact document set"
            )
        members: list[ArtifactMemberBytes] = []
        for row in rows:
            spec = specs[row["document_id"]]
            raw = bytes(row["raw_bytes"])
            if len(raw) != row["size_bytes"] or hashlib.sha256(raw).hexdigest() != row["source_hash"]:
                raise StoreIntegrityError("stored artifact blob hash/size mismatch")
            try:
                supersedes = strict_json_loads(row["supersedes_json"])
            except (TypeError, ValueError) as error:
                raise StoreIntegrityError(
                    "stored artifact member supersedes metadata is invalid"
                ) from error
            declared_format = Path(row["filename"]).suffix[1:].upper()
            if (
                row["source_id"] != spec.get("source_id")
                or row["filename"] != Path(str(spec.get("source_path", ""))).name
                or row["declared_format"] != declared_format
                or row["detected_format"] != declared_format
                or supersedes != spec.get("supersedes")
            ):
                raise StoreIntegrityError(
                    "stored artifact member metadata differs from its manifest"
                )
            members.append(
                ArtifactMemberBytes(
                    source_id=row["source_id"],
                    document_id=row["document_id"],
                    filename=row["filename"],
                    raw_bytes=raw,
                )
            )
        return RevisionArtifactBundle(
            canonical_manifest_bytes=canonical_manifest_bytes,
            members=tuple(members),
        )

    def _stage_artifact_bundle(
        self,
        artifact_set_hash: str,
        bundle: RevisionArtifactBundle,
        reference_context: Any,
        resolved_reference_set_hash: str,
    ) -> bool:
        """Stage exact captured bytes; semantic trust is granted only after rebuild."""

        try:
            manifest, canonical_manifest_bytes = canonicalize_artifact_manifest(
                strict_json_loads(bundle.canonical_manifest_bytes.decode("utf-8"))
            )
        except (UnicodeError, ValueError) as error:
            raise StoreIntegrityError("replacement bundle manifest is invalid") from error
        specs = {item["document_id"]: item for item in manifest["documents"]}
        members = {item.document_id: item for item in bundle.members}
        if len(members) != len(bundle.members) or set(members) != set(specs):
            raise StoreIntegrityError(
                "replacement bundle members differ from its exact manifest documents"
            )
        existing = self.connection.execute(
            "SELECT 1 FROM artifact_sets WHERE artifact_set_hash=?",
            (artifact_set_hash,),
        ).fetchone()
        if existing is not None:
            row = self.connection.execute(
                "SELECT controlled_reference_set_hash,resolved_reference_set_hash,reference_contract_version FROM artifact_sets WHERE artifact_set_hash=?",
                (artifact_set_hash,),
            ).fetchone()
            if row is None or (
                row["controlled_reference_set_hash"]
                != reference_context.reference_set_hash
                or row["resolved_reference_set_hash"]
                != resolved_reference_set_hash
                or row["reference_contract_version"]
                != reference_context.contract_version
            ):
                raise StoreIntegrityError(
                    "existing artifact set differs from controlled reference identity"
                )
            stored = self._load_artifact_bundle(artifact_set_hash)
            expected_members = {
                item.document_id: item for item in bundle.members
            }
            stored_members = {
                item.document_id: item for item in stored.members
            }
            if (
                stored.canonical_manifest_bytes != canonical_manifest_bytes
                or stored_members != expected_members
            ):
                raise StoreIntegrityError(
                    "existing artifact set differs from supplied captured bytes"
                )
            return False
        for document_id, spec in specs.items():
            member = members[document_id]
            if (
                member.source_id != spec["source_id"]
                or member.filename != Path(spec["source_path"]).name
            ):
                raise StoreIntegrityError(
                    "replacement bundle member identity differs from its manifest"
                )
            source_hash = hashlib.sha256(member.raw_bytes).hexdigest()
            inserted = self.connection.execute(
                "INSERT OR IGNORE INTO artifact_blobs(source_hash,size_bytes,raw_bytes) VALUES (?,?,?)",
                (source_hash, len(member.raw_bytes), member.raw_bytes),
            ).rowcount
            if not inserted:
                row = self.connection.execute(
                    "SELECT size_bytes,raw_bytes FROM artifact_blobs WHERE source_hash=?",
                    (source_hash,),
                ).fetchone()
                if (
                    row is None
                    or row["size_bytes"] != len(member.raw_bytes)
                    or bytes(row["raw_bytes"]) != member.raw_bytes
                ):
                    raise StoreIntegrityError(
                        "source_hash conflicts with different stored bytes"
                    )
        self._fault_point("after_blob")
        self.connection.execute(
            """INSERT INTO artifact_sets
               (artifact_set_hash,replacement_set_id,manifest_bytes,
                controlled_reference_set_hash,resolved_reference_set_hash,
                reference_contract_version,
                artifact_contract_version,case_schema_version,parser_contract_version,
                mapping_contract_version,security_root_policy_version)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                artifact_set_hash,
                manifest["replacement_set_id"],
                canonical_manifest_bytes,
                reference_context.reference_set_hash,
                resolved_reference_set_hash,
                reference_context.contract_version,
                ARTIFACT_CONTRACT_VERSION,
                manifest["case_schema_version"],
                manifest["parser_contract_version"],
                manifest["mapping_contract_version"],
                manifest["security_root_policy_version"],
            ),
        )
        for document_id, spec in specs.items():
            member = members[document_id]
            source_hash = hashlib.sha256(member.raw_bytes).hexdigest()
            declared_format = Path(member.filename).suffix[1:].upper()
            self.connection.execute(
                """INSERT INTO artifact_set_members
                   (artifact_set_hash,document_id,source_id,filename,source_hash,
                    declared_format,detected_format,supersedes_json)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    artifact_set_hash,
                    document_id,
                    member.source_id,
                    member.filename,
                    source_hash,
                    declared_format,
                    declared_format,
                    _json(spec["supersedes"]),
                ),
            )
        self._fault_point("after_artifact_set_members")
        return True

    def _controlled_reference_set_entity(
        self, reference_set_hash: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM controlled_reference_sets WHERE reference_set_hash=?",
            (reference_set_hash,),
        ).fetchone()
        if row is None:
            return None
        members = self.connection.execute(
            """SELECT m.*,b.size_bytes,b.raw_bytes
               FROM controlled_reference_members m
               JOIN artifact_blobs b ON b.source_hash=m.source_hash
               WHERE m.reference_set_hash=? ORDER BY m.document_id""",
            (reference_set_hash,),
        ).fetchall()
        return {
            "reference_set_hash": row["reference_set_hash"],
            "contract_version": row["contract_version"],
            "manifest_bytes_hash": hashlib.sha256(row["manifest_bytes"]).hexdigest(),
            "members": [
                {
                    **{key: member[key] for key in member.keys() if key != "raw_bytes"},
                    "actual_raw_hash": hashlib.sha256(member["raw_bytes"]).hexdigest(),
                }
                for member in members
            ],
        }

    def _controlled_reference_snapshot_matches_context(
        self,
        context: _ControlledReferenceContext,
        bundle: ControlledReferenceBundle,
    ) -> bool:
        """Compare the transaction's stored raw snapshot without reparsing artifacts."""

        try:
            set_row = self.connection.execute(
                "SELECT contract_version,manifest_bytes FROM controlled_reference_sets "
                "WHERE reference_set_hash=?",
                (context.reference_set_hash,),
            ).fetchone()
            if set_row is None or (
                set_row["contract_version"] != context.contract_version
                or bytes(set_row["manifest_bytes"])
                != bundle.canonical_manifest_bytes
            ):
                return False
            expected = {
                witness.document_id: witness for witness in context.witnesses
            }
            rows = self.connection.execute(
                """SELECT m.document_id,m.document_type,m.revision,m.source_id,
                          m.filename,m.source_hash,b.size_bytes,b.raw_bytes
                   FROM controlled_reference_members m
                   JOIN artifact_blobs b ON b.source_hash=m.source_hash
                   WHERE m.reference_set_hash=? ORDER BY m.document_id""",
                (context.reference_set_hash,),
            ).fetchall()
            if len(rows) != len(expected) or {
                row["document_id"] for row in rows
            } != set(expected):
                return False
            return all(
                (
                    row["document_type"],
                    row["revision"],
                    row["source_id"],
                    row["filename"],
                    row["source_hash"],
                    row["size_bytes"],
                    bytes(row["raw_bytes"]),
                )
                == (
                    expected[row["document_id"]].document_type,
                    expected[row["document_id"]].revision,
                    expected[row["document_id"]].source_id,
                    expected[row["document_id"]].filename,
                    expected[row["document_id"]].source_hash,
                    len(expected[row["document_id"]].raw_bytes),
                    expected[row["document_id"]].raw_bytes,
                )
                for row in rows
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _validation_evidence_snapshot_matches_context(
        self,
        context: _ValidationEvidenceContext,
        bundle: ValidationEvidenceBundle,
    ) -> bool:
        """Compare stored evidence bytes/metadata with one sealed parser context."""

        try:
            if (
                type(context) is not _ValidationEvidenceContext
                or not context.is_sealed()
                or type(bundle) is not ValidationEvidenceBundle
            ):
                return False
            set_row = self.connection.execute(
                """SELECT phase,contract_version,parser_contract_version,
                          manifest_bytes,case_subject_hash,scope_digest
                   FROM validation_evidence_sets WHERE evidence_set_hash=?""",
                (context.evidence_set_hash,),
            ).fetchone()
            if set_row is None or (
                set_row["phase"],
                set_row["contract_version"],
                set_row["parser_contract_version"],
                bytes(set_row["manifest_bytes"]),
                set_row["case_subject_hash"],
                set_row["scope_digest"],
            ) != (
                context.phase,
                context.contract_version,
                VALIDATION_PARSER_CONTRACT_VERSION,
                bundle.canonical_manifest_bytes,
                context.case_subject_hash,
                context.scope_digest,
            ):
                return False

            witnesses = {
                witness.evidence_id: witness for witness in context.witnesses
            }
            members = {
                member.evidence_id: member for member in bundle.members
            }
            if (
                len(witnesses) != len(context.witnesses)
                or len(members) != len(bundle.members)
                or set(witnesses) != set(members)
            ):
                return False
            for evidence_id, witness in witnesses.items():
                member = members[evidence_id]
                if (
                    member.source_id,
                    member.filename,
                    hashlib.sha256(member.raw_bytes).hexdigest(),
                    len(member.raw_bytes),
                    member.raw_bytes,
                ) != (
                    witness.source_id,
                    witness.filename,
                    witness.source_hash,
                    len(witness.raw_bytes),
                    witness.raw_bytes,
                ):
                    return False

            rows = self.connection.execute(
                """SELECT m.evidence_id,m.source_id,m.filename,m.source_hash,
                          b.size_bytes,b.raw_bytes
                   FROM validation_evidence_members m
                   JOIN artifact_blobs b ON b.source_hash=m.source_hash
                   WHERE m.evidence_set_hash=? ORDER BY m.evidence_id""",
                (context.evidence_set_hash,),
            ).fetchall()
            if len(rows) != len(witnesses) or {
                row["evidence_id"] for row in rows
            } != set(witnesses):
                return False
            return all(
                (
                    row["source_id"],
                    row["filename"],
                    row["source_hash"],
                    row["size_bytes"],
                    bytes(row["raw_bytes"]),
                )
                == (
                    witnesses[row["evidence_id"]].source_id,
                    witnesses[row["evidence_id"]].filename,
                    witnesses[row["evidence_id"]].source_hash,
                    len(witnesses[row["evidence_id"]].raw_bytes),
                    witnesses[row["evidence_id"]].raw_bytes,
                )
                for row in rows
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _artifact_snapshot_matches_context(
        self,
        context: ArtifactContext,
        bundle: RevisionArtifactBundle,
    ) -> bool:
        """Re-read stored bytes/metadata, while reusing the verified parser context."""

        try:
            current = self._load_artifact_bundle(context.artifact_set_hash)
            current_members = {
                member.document_id: member for member in current.members
            }
            expected_members = {
                member.document_id: member for member in bundle.members
            }
            return (
                current.canonical_manifest_bytes == bundle.canonical_manifest_bytes
                and current_members == expected_members
                and self._artifact_subject_from_stored_index(
                    context.artifact_set_hash
                )
                == context.subject_fields()
            )
        except (KeyError, TypeError, ValueError, StoreIntegrityError, sqlite3.Error):
            return False

    def _load_controlled_reference_bundle(
        self, reference_set_hash: str
    ) -> ControlledReferenceBundle:
        set_row = self.connection.execute(
            "SELECT * FROM controlled_reference_sets WHERE reference_set_hash=?",
            (reference_set_hash,),
        ).fetchone()
        if set_row is None:
            raise StoreIntegrityError("controlled reference set is missing")
        manifest_bytes = bytes(set_row["manifest_bytes"])
        try:
            manifest = strict_json_loads(manifest_bytes.decode("utf-8"))
        except (UnicodeError, ValueError) as error:
            raise StoreIntegrityError(
                "stored controlled reference manifest is invalid"
            ) from error
        if not isinstance(manifest, dict) or _json(manifest).encode("utf-8") != manifest_bytes:
            raise StoreIntegrityError(
                "stored controlled reference manifest is not canonical"
            )
        documents = manifest.get("documents")
        if not isinstance(documents, list):
            raise StoreIntegrityError(
                "stored controlled reference manifest documents are invalid"
            )
        specs = {
            item.get("document_id"): item
            for item in documents
            if isinstance(item, dict) and isinstance(item.get("document_id"), str)
        }
        if len(specs) != len(documents):
            raise StoreIntegrityError(
                "stored controlled reference manifest identities are ambiguous"
            )
        rows = self.connection.execute(
            """SELECT m.*,b.size_bytes,b.raw_bytes
               FROM controlled_reference_members m
               JOIN artifact_blobs b ON b.source_hash=m.source_hash
               WHERE m.reference_set_hash=? ORDER BY m.document_id""",
            (reference_set_hash,),
        ).fetchall()
        if len(rows) != len(specs) or {row["document_id"] for row in rows} != set(specs):
            raise StoreIntegrityError(
                "stored controlled reference members differ from manifest"
            )
        members: list[ControlledReferenceMember] = []
        for row in rows:
            spec = specs[row["document_id"]]
            raw = bytes(row["raw_bytes"])
            if (
                len(raw) != row["size_bytes"]
                or hashlib.sha256(raw).hexdigest() != row["source_hash"]
                or row["source_id"] != spec.get("source_id")
                or row["filename"] != spec.get("source_path")
                or row["document_type"] != spec.get("document_type")
                or row["revision"] != spec.get("revision")
            ):
                raise StoreIntegrityError(
                    "stored controlled reference member differs from manifest or bytes"
                )
            members.append(
                ControlledReferenceMember(
                    row["source_id"],
                    row["document_id"],
                    row["filename"],
                    raw,
                )
            )
        bundle = ControlledReferenceBundle(manifest_bytes, tuple(members))
        try:
            context = _prepare_controlled_reference_context(bundle)
        except (TypeError, ValueError) as error:
            raise StoreIntegrityError(
                "stored controlled reference bytes cannot be rebuilt"
            ) from error
        if (
            context.reference_set_hash != reference_set_hash
            or context.contract_version != set_row["contract_version"]
        ):
            raise StoreIntegrityError(
                "stored controlled reference set identity differs from rebuilt bytes"
            )
        return bundle

    def _stage_controlled_reference_bundle(
        self,
        reference_set_hash: str,
        bundle: ControlledReferenceBundle,
    ) -> bool:
        if type(bundle) is not ControlledReferenceBundle:
            raise StoreIntegrityError(
                "controlled reference persistence requires exact captured bundle type"
            )
        try:
            context = _prepare_controlled_reference_context(bundle)
            manifest = strict_json_loads(bundle.canonical_manifest_bytes.decode("utf-8"))
        except (TypeError, UnicodeError, ValueError) as error:
            raise StoreIntegrityError("controlled reference bundle is invalid") from error
        if context.reference_set_hash != reference_set_hash:
            raise StoreIntegrityError(
                "controlled reference bundle differs from approved reference identity"
            )
        existing = self.connection.execute(
            "SELECT 1 FROM controlled_reference_sets WHERE reference_set_hash=?",
            (reference_set_hash,),
        ).fetchone()
        if existing is not None:
            stored = self._load_controlled_reference_bundle(reference_set_hash)
            supplied = {item.document_id: item for item in bundle.members}
            persisted = {item.document_id: item for item in stored.members}
            if (
                stored.canonical_manifest_bytes != bundle.canonical_manifest_bytes
                or persisted != supplied
            ):
                raise StoreIntegrityError(
                    "existing controlled reference set differs from supplied bytes"
                )
            return False
        specs = {item["document_id"]: item for item in manifest["documents"]}
        members = {item.document_id: item for item in bundle.members}
        if len(members) != len(bundle.members) or set(members) != set(specs):
            raise StoreIntegrityError(
                "controlled reference bundle exact member set differs from manifest"
            )
        for document_id, member in members.items():
            spec = specs[document_id]
            if (
                member.source_id != spec.get("source_id")
                or member.filename != spec.get("source_path")
            ):
                raise StoreIntegrityError(
                    "controlled reference member identity differs from manifest"
                )
            source_hash = hashlib.sha256(member.raw_bytes).hexdigest()
            inserted = self.connection.execute(
                "INSERT OR IGNORE INTO artifact_blobs(source_hash,size_bytes,raw_bytes) VALUES (?,?,?)",
                (source_hash, len(member.raw_bytes), member.raw_bytes),
            ).rowcount
            if not inserted:
                blob = self.connection.execute(
                    "SELECT size_bytes,raw_bytes FROM artifact_blobs WHERE source_hash=?",
                    (source_hash,),
                ).fetchone()
                if (
                    blob is None
                    or blob["size_bytes"] != len(member.raw_bytes)
                    or bytes(blob["raw_bytes"]) != member.raw_bytes
                ):
                    raise StoreIntegrityError(
                        "controlled reference source hash conflicts with stored bytes"
                    )
        self.connection.execute(
            "INSERT INTO controlled_reference_sets(reference_set_hash,contract_version,manifest_bytes) VALUES (?,?,?)",
            (
                reference_set_hash,
                context.contract_version,
                bundle.canonical_manifest_bytes,
            ),
        )
        for document_id, member in members.items():
            spec = specs[document_id]
            self.connection.execute(
                """INSERT INTO controlled_reference_members
                   (reference_set_hash,document_id,document_type,revision,
                    source_id,filename,source_hash) VALUES (?,?,?,?,?,?,?)""",
                (
                    reference_set_hash,
                    document_id,
                    spec["document_type"],
                    spec["revision"],
                    member.source_id,
                    member.filename,
                    hashlib.sha256(member.raw_bytes).hexdigest(),
                ),
            )
        self._fault_point("after_controlled_reference_members")
        return True

    def _validation_evidence_set_entity(
        self, evidence_set_hash: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM validation_evidence_sets WHERE evidence_set_hash=?",
            (evidence_set_hash,),
        ).fetchone()
        if row is None:
            return None
        members = self.connection.execute(
            """SELECT m.*,b.size_bytes,b.raw_bytes
               FROM validation_evidence_members m
               JOIN artifact_blobs b ON b.source_hash=m.source_hash
               WHERE m.evidence_set_hash=? ORDER BY m.evidence_id""",
            (evidence_set_hash,),
        ).fetchall()
        return {
            "evidence_set_hash": row["evidence_set_hash"],
            "phase": row["phase"],
            "contract_version": row["contract_version"],
            "parser_contract_version": row["parser_contract_version"],
            "manifest_bytes_hash": hashlib.sha256(
                bytes(row["manifest_bytes"])
            ).hexdigest(),
            "case_subject_hash": row["case_subject_hash"],
            "scope_digest": row["scope_digest"],
            "members": [
                {
                    **{
                        key: member[key]
                        for key in member.keys()
                        if key != "raw_bytes"
                    },
                    "actual_raw_hash": hashlib.sha256(
                        bytes(member["raw_bytes"])
                    ).hexdigest(),
                }
                for member in members
            ],
        }

    def _verification_semantic_cache_key(
        self, value: Any
    ) -> tuple[Any, ...]:
        """Bind a cached result to the exact entity and current SQLite snapshot."""

        data_version = self.connection.execute("PRAGMA data_version").fetchone()
        if data_version is None:
            raise sqlite3.DatabaseError("SQLite data_version is unavailable")
        return (
            self.connection.total_changes,
            int(data_version[0]),
            _exact_cache_value(value),
        )

    def _validation_evidence_cache_snapshot(
        self, evidence_set_hash: str
    ) -> dict[str, Any] | None:
        """Capture every stored set/member/blob byte used by evidence validation."""

        row = self.connection.execute(
            "SELECT * FROM validation_evidence_sets WHERE evidence_set_hash=?",
            (evidence_set_hash,),
        ).fetchone()
        if row is None:
            return None
        members = self.connection.execute(
            """SELECT m.evidence_set_hash,m.evidence_id,m.source_id,m.filename,
                      m.source_hash,b.size_bytes,b.raw_bytes
               FROM validation_evidence_members m
               JOIN artifact_blobs b ON b.source_hash=m.source_hash
               WHERE m.evidence_set_hash=? ORDER BY m.evidence_id""",
            (evidence_set_hash,),
        ).fetchall()
        return {
            "set": {key: row[key] for key in row.keys()},
            "members": [
                {key: member[key] for key in member.keys()}
                for member in members
            ],
        }

    def _load_validation_evidence_bundle(
        self, evidence_set_hash: str
    ) -> ValidationEvidenceBundle:
        set_row = self.connection.execute(
            "SELECT * FROM validation_evidence_sets WHERE evidence_set_hash=?",
            (evidence_set_hash,),
        ).fetchone()
        if set_row is None:
            raise StoreIntegrityError("validation evidence set is missing")
        rows = self.connection.execute(
            """SELECT m.*,b.size_bytes,b.raw_bytes
               FROM validation_evidence_members m
               JOIN artifact_blobs b ON b.source_hash=m.source_hash
               WHERE m.evidence_set_hash=? ORDER BY m.evidence_id""",
            (evidence_set_hash,),
        ).fetchall()
        members: list[ValidationEvidenceMember] = []
        for row in rows:
            raw = bytes(row["raw_bytes"])
            if (
                len(raw) != row["size_bytes"]
                or hashlib.sha256(raw).hexdigest() != row["source_hash"]
            ):
                raise StoreIntegrityError(
                    "stored validation report bytes differ from their identity"
                )
            members.append(
                ValidationEvidenceMember(
                    row["source_id"],
                    row["evidence_id"],
                    row["filename"],
                    raw,
                )
            )
        try:
            return ValidationEvidenceBundle(
                bytes(set_row["manifest_bytes"]), tuple(members)
            )
        except (TypeError, ValueError) as error:
            raise StoreIntegrityError(
                "stored validation evidence bundle cannot be rebuilt"
            ) from error

    def _stage_validation_evidence_bundle(
        self,
        context: _ValidationEvidenceContext,
        bundle: ValidationEvidenceBundle,
    ) -> bool:
        if type(bundle) is not ValidationEvidenceBundle:
            raise StoreIntegrityError(
                "validation persistence requires exact captured bundle type"
            )
        existing = self.connection.execute(
            "SELECT 1 FROM validation_evidence_sets WHERE evidence_set_hash=?",
            (context.evidence_set_hash,),
        ).fetchone()
        if existing is not None:
            stored = self._load_validation_evidence_bundle(
                context.evidence_set_hash
            )
            if stored != bundle:
                raise StoreIntegrityError(
                    "existing validation evidence set differs from supplied bytes"
                )
            return False
        members = {member.evidence_id: member for member in bundle.members}
        witnesses = {witness.evidence_id: witness for witness in context.witnesses}
        if len(members) != len(bundle.members) or set(members) != set(witnesses):
            raise StoreIntegrityError(
                "validation evidence member set differs from sealed context"
            )
        for evidence_id, member in members.items():
            witness = witnesses[evidence_id]
            if (
                member.source_id != witness.source_id
                or member.filename != witness.filename
                or member.raw_bytes != witness.raw_bytes
            ):
                raise StoreIntegrityError(
                    "validation evidence member differs from sealed context"
                )
            inserted = self.connection.execute(
                "INSERT OR IGNORE INTO artifact_blobs(source_hash,size_bytes,raw_bytes) "
                "VALUES (?,?,?)",
                (witness.source_hash, len(witness.raw_bytes), witness.raw_bytes),
            ).rowcount
            if not inserted:
                row = self.connection.execute(
                    "SELECT size_bytes,raw_bytes FROM artifact_blobs WHERE source_hash=?",
                    (witness.source_hash,),
                ).fetchone()
                if (
                    row is None
                    or row["size_bytes"] != len(witness.raw_bytes)
                    or bytes(row["raw_bytes"]) != witness.raw_bytes
                ):
                    raise StoreIntegrityError(
                        "validation source hash conflicts with stored bytes"
                    )
        self.connection.execute(
            """INSERT INTO validation_evidence_sets
               (evidence_set_hash,phase,contract_version,parser_contract_version,
                manifest_bytes,case_subject_hash,scope_digest)
               VALUES (?,?,?,?,?,?,?)""",
            (
                context.evidence_set_hash,
                context.phase,
                context.contract_version,
                VALIDATION_PARSER_CONTRACT_VERSION,
                bundle.canonical_manifest_bytes,
                context.case_subject_hash,
                context.scope_digest,
            ),
        )
        for evidence_id, witness in witnesses.items():
            self.connection.execute(
                """INSERT INTO validation_evidence_members
                   (evidence_set_hash,evidence_id,source_id,filename,source_hash)
                   VALUES (?,?,?,?,?)""",
                (
                    context.evidence_set_hash,
                    evidence_id,
                    witness.source_id,
                    witness.filename,
                    witness.source_hash,
                ),
            )
        self._fault_point("after_validation_evidence_members")
        return True

    def _validation_evidence_set_is_semantically_valid(
        self, evidence_set_hash: str
    ) -> bool:
        cache = getattr(self, "_verify_validation_evidence_semantic_cache", None)
        if not isinstance(cache, dict):
            return self._validation_evidence_set_is_semantically_valid_uncached(
                evidence_set_hash
            )
        try:
            snapshot = self._validation_evidence_cache_snapshot(evidence_set_hash)
            key = self._verification_semantic_cache_key(snapshot)
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False
        if key not in cache:
            cache[key] = (
                self._validation_evidence_set_is_semantically_valid_uncached(
                    evidence_set_hash
                )
            )
        return bool(cache[key])

    def _validation_evidence_set_is_semantically_valid_uncached(
        self, evidence_set_hash: str
    ) -> bool:
        try:
            row = self.connection.execute(
                "SELECT * FROM validation_evidence_sets WHERE evidence_set_hash=?",
                (evidence_set_hash,),
            ).fetchone()
            lineage_case: dict[str, Any] | None = None
            if row is None:
                return False
            case_row = self.connection.execute(
                "SELECT case_hash,payload_json FROM cases WHERE case_hash IN "
                "(SELECT json_extract(payload_json,'$.case_hash') FROM runs "
                " WHERE json_extract(payload_json,'$.validation_evidence_set_hash')=?) "
                "LIMIT 1",
                (evidence_set_hash,),
            ).fetchone()
            # Replay evidence is bound through replay_validation_bindings; a
            # standalone run has a direct run_validation_sets link.
            if case_row is None:
                binding = self.connection.execute(
                    """SELECT source_case_hash,after_case_hash FROM replay_validation_bindings
                       WHERE source_evidence_set_hash=? OR resolved_evidence_set_hash=?
                       LIMIT 1""",
                    (evidence_set_hash, evidence_set_hash),
                ).fetchone()
                if binding is None:
                    for lineage in self.connection.execute(
                        "SELECT l.*,b.raw_bytes FROM case_lineage_bindings l "
                        "JOIN artifact_blobs b ON "
                        "b.source_hash=l.operation_material_source_hash "
                        "WHERE l.operation_kind='NATIVE_REPLAY'"
                    ):
                        material = strict_json_loads(
                            bytes(lineage["raw_bytes"]).decode("utf-8")
                        )
                        material_key = (
                            "source_validation_evidence_set_hash"
                            if row["phase"] == "SOURCE"
                            else "resolved_validation_evidence_set_hash"
                        )
                        if (
                            type(material) is not dict
                            or material.get(material_key) != evidence_set_hash
                        ):
                            continue
                        source = self.connection.execute(
                            "SELECT source_set_hash FROM case_source_sets "
                            "WHERE root_binding_hash=?",
                            (lineage["root_binding_hash"],),
                        ).fetchone()
                        if source is None:
                            return False
                        terminal = (
                            lineage["parent_lineage_hash"]
                            if row["phase"] == "SOURCE"
                            else lineage["lineage_hash"]
                        )
                        lineage_case = self._stored_case_source_context_with_lineage(
                            source["source_set_hash"],
                            terminal,
                        ).case()
                        break
                    if lineage_case is None:
                        return False
                else:
                    bound_case_hash = (
                        binding["source_case_hash"]
                        if row["phase"] == "SOURCE"
                        else binding["after_case_hash"]
                    )
                    case_row = self.connection.execute(
                        "SELECT case_hash,payload_json FROM cases WHERE case_hash=? LIMIT 1",
                        (bound_case_hash,),
                    ).fetchone()
            if case_row is None and lineage_case is None:
                return False
            case = (
                lineage_case
                if lineage_case is not None
                else self._verify_stored_case_payload(case_row["payload_json"])
            )
            case_hash = canonical_hash(case)
            context = self._stored_validation_context(
                evidence_set_hash,
                case,
                row["phase"],
                case_hash=case_hash,
            )
            return (
                context.evidence_set_hash == evidence_set_hash
                and context.contract_version == row["contract_version"]
                and row["parser_contract_version"]
                == VALIDATION_PARSER_CONTRACT_VERSION
                and context.case_subject_hash == row["case_subject_hash"]
                and context.scope_digest == row["scope_digest"]
            )
        except (KeyError, TypeError, ValueError, StoreIntegrityError, sqlite3.Error):
            return False

    def _stored_validation_context(
        self,
        evidence_set_hash: str,
        case: dict[str, Any],
        phase: str,
        *,
        case_hash: str | None = None,
        _case_identity: _ValidationCaseIdentity | None = None,
    ) -> _ValidationEvidenceContext:
        key = (
            evidence_set_hash,
            case_hash if case_hash is not None else canonical_hash(case),
            phase,
        )
        cache = getattr(self, "_verify_validation_context_cache", None)
        if cache is not None and key in cache:
            return cache[key]
        identity_key = key[1]
        identity_cache = getattr(self, "_verify_validation_identity_cache", None)
        case_identity = _case_identity
        if not (
            type(case_identity) is _ValidationCaseIdentity
            and case_identity.is_sealed()
        ):
            case_identity = (
                identity_cache.get(identity_key)
                if isinstance(identity_cache, dict)
                else None
            )
        if not (
            type(case_identity) is _ValidationCaseIdentity
            and case_identity.is_sealed()
        ):
            case_identity = _prepare_validation_case_identity(case)
        if isinstance(identity_cache, dict):
            identity_cache[identity_key] = case_identity
        bundle = self._load_validation_evidence_bundle(evidence_set_hash)
        context = _prepare_validation_evidence_context(
            bundle,
            case,
            expected_phase=phase,
            _case_identity=case_identity,
        )
        if cache is not None:
            cache[key] = context
        return context

    def _authorization_record_set_entity(
        self, record_set_hash: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT record_set_hash,contract_version,bundle_id,"
            "normalized_bundle_id,manifest_bytes "
            "FROM authorization_record_sets WHERE record_set_hash=?",
            (record_set_hash,),
        ).fetchone()
        return dict(row) if row is not None else None

    def _load_authorization_record_bundle(
        self, record_set_hash: str
    ) -> AuthorizationRecordBundle:
        row = self.connection.execute(
            "SELECT manifest_bytes FROM authorization_record_sets "
            "WHERE record_set_hash=?",
            (record_set_hash,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("authorization record set is missing")
        members = self.connection.execute(
            "SELECT record_id,source_path,content_hash,size_bytes,raw_bytes "
            "FROM authorization_record_members WHERE record_set_hash=? "
            "ORDER BY record_id",
            (record_set_hash,),
        ).fetchall()
        try:
            return AuthorizationRecordBundle(
                bytes(row["manifest_bytes"]),
                tuple(
                    AuthorizationRecordMember(
                        record_id=str(member["record_id"]),
                        filename=str(member["source_path"]),
                        content_hash=str(member["content_hash"]),
                        size_bytes=int(member["size_bytes"]),
                        raw_bytes=bytes(member["raw_bytes"]),
                    )
                    for member in members
                ),
            )
        except (TypeError, ValueError) as error:
            raise StoreIntegrityError(
                "stored authorization record bytes cannot be rebuilt"
            ) from error

    def _stage_authorization_record_bundle(
        self,
        context: AuthorizationRecordContext,
        bundle: AuthorizationRecordBundle,
    ) -> bool:
        if (
            type(context) is not AuthorizationRecordContext
            or not context.is_sealed()
            or type(bundle) is not AuthorizationRecordBundle
        ):
            raise StoreIntegrityError(
                "authorization persistence requires exact sealed raw bytes"
            )
        rebuilt = prepare_authorization_record_context(bundle)
        if (
            rebuilt.record_set_hash != context.record_set_hash
            or rebuilt.bundle_id != context.bundle_id
            or rebuilt.contract_version != context.contract_version
            or rebuilt.records() != context.records()
        ):
            raise StoreIntegrityError(
                "authorization raw bytes differ from the supplied sealed context"
            )
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO authorization_record_sets "
            "(record_set_hash,contract_version,bundle_id,normalized_bundle_id,manifest_bytes) "
            "VALUES (?,?,?,?,?)",
            (
                context.record_set_hash,
                context.contract_version,
                context.bundle_id,
                normalized_identity(context.bundle_id),
                bundle.canonical_manifest_bytes,
            ),
        ).rowcount
        expected_set = {
            "record_set_hash": context.record_set_hash,
            "contract_version": context.contract_version,
            "bundle_id": context.bundle_id,
            "normalized_bundle_id": normalized_identity(context.bundle_id),
            "manifest_bytes": bundle.canonical_manifest_bytes,
        }
        stored_set = self._authorization_record_set_entity(context.record_set_hash)
        if stored_set != expected_set:
            raise StoreIntegrityError(
                "authorization record set hash conflicts with stored content"
            )
        expected_ids: set[str] = set()
        for member in bundle.members:
            expected_ids.add(member.record_id)
            expected = {
                "record_set_hash": context.record_set_hash,
                "record_id": member.record_id,
                "normalized_record_id": normalized_identity(member.record_id),
                "source_path": member.filename,
                "normalized_source_path": normalized_identity(member.filename),
                "content_hash": member.content_hash,
                "size_bytes": member.size_bytes,
                "raw_bytes": member.raw_bytes,
            }
            self.connection.execute(
                "INSERT OR IGNORE INTO authorization_record_members "
                "(record_set_hash,record_id,normalized_record_id,source_path,"
                "normalized_source_path,content_hash,size_bytes,raw_bytes) "
                "VALUES (?,?,?,?,?,?,?,?)",
                tuple(expected.values()),
            )
            row = self.connection.execute(
                "SELECT record_set_hash,record_id,normalized_record_id,source_path,"
                "normalized_source_path,content_hash,size_bytes,raw_bytes "
                "FROM authorization_record_members WHERE record_set_hash=? AND record_id=?",
                (context.record_set_hash, member.record_id),
            ).fetchone()
            if row is None or dict(row) != expected:
                raise StoreIntegrityError(
                    "authorization record identity conflicts with stored bytes"
                )
        actual_ids = {
            str(row["record_id"])
            for row in self.connection.execute(
                "SELECT record_id FROM authorization_record_members "
                "WHERE record_set_hash=?",
                (context.record_set_hash,),
            )
        }
        if actual_ids != expected_ids:
            raise StoreIntegrityError(
                "authorization record set contains unexpected members"
            )
        if inserted:
            self._append_audit(
                "authorization_record_set",
                context.record_set_hash,
                "AUTHORIZATION_RECORD_SET_RECORDED",
                {
                    "primary_key": {"record_set_hash": context.record_set_hash},
                    "entity_fingerprint": _fingerprint(expected_set),
                },
            )
        return bool(inserted)

    def _authorization_trust_snapshot_entity(
        self, trust_snapshot_hash: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT trust_snapshot_hash,contract_version,trust_policy_hash,"
            "trust_policy_version,snapshot_bytes "
            "FROM authorization_trust_snapshots WHERE trust_snapshot_hash=?",
            (trust_snapshot_hash,),
        ).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def _authorization_trust_snapshot_entity_from_context(
        context: AuthorizationAuthenticityContext,
        bundle: AuthorizationTrustSnapshotBundle,
    ) -> dict[str, Any]:
        if (
            type(context) is not AuthorizationAuthenticityContext
            or not context.is_sealed()
            or type(bundle) is not AuthorizationTrustSnapshotBundle
            or type(bundle.canonical_snapshot_bytes) is not bytes
        ):
            raise StoreIntegrityError(
                "authorization trust persistence requires exact sealed raw inputs"
            )
        return {
            "trust_snapshot_hash": context.trust_snapshot_hash,
            "contract_version": context.trust_snapshot_contract_version,
            "trust_policy_hash": context.trust_policy_hash,
            "trust_policy_version": context.trust_policy_version,
            "snapshot_bytes": bundle.canonical_snapshot_bytes,
        }

    def _load_authorization_trust_snapshot_bundle(
        self, trust_snapshot_hash: str
    ) -> AuthorizationTrustSnapshotBundle:
        entity = self._authorization_trust_snapshot_entity(trust_snapshot_hash)
        if entity is None:
            raise StoreIntegrityError(
                "authorization trust snapshot is missing from stored bytes"
            )
        try:
            return AuthorizationTrustSnapshotBundle(entity["snapshot_bytes"])
        except (KeyError, TypeError, ValueError) as error:
            raise StoreIntegrityError(
                "stored authorization trust snapshot is invalid"
            ) from error

    def _stored_authorization_authenticity_context(
        self,
        authorization_record_set_hash: str,
        trust_snapshot_hash: str,
    ) -> AuthorizationAuthenticityContext:
        cache = getattr(self, "_verify_authorization_context_cache", None)
        cache_key = (authorization_record_set_hash, trust_snapshot_hash)
        if isinstance(cache, dict) and cache_key in cache:
            context = cache[cache_key]
            if type(context) is not AuthorizationAuthenticityContext:
                raise StoreIntegrityError(
                    "stored authorization authenticity cache is invalid"
                )
            return context
        context = prepare_authorization_authenticity_context(
            self._load_authorization_record_bundle(
                authorization_record_set_hash
            ),
            self._load_authorization_trust_snapshot_bundle(
                trust_snapshot_hash
            ),
        )
        if isinstance(cache, dict):
            cache[cache_key] = context
        return context

    def _stage_authorization_trust_snapshot_bundle(
        self,
        context: AuthorizationAuthenticityContext,
        bundle: AuthorizationTrustSnapshotBundle,
    ) -> bool:
        return self._save_authorization_trust_snapshot_entity(
            self._authorization_trust_snapshot_entity_from_context(
                context, bundle
            )
        )

    def _save_authorization_trust_snapshot_entity(
        self, entity: dict[str, Any]
    ) -> bool:
        fields = (
            "trust_snapshot_hash",
            "contract_version",
            "trust_policy_hash",
            "trust_policy_version",
            "snapshot_bytes",
        )
        if set(entity) != set(fields):
            raise StoreIntegrityError(
                "authorization trust snapshot requires exact stored fields"
            )
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO authorization_trust_snapshots "
            "(trust_snapshot_hash,contract_version,trust_policy_hash,"
            "trust_policy_version,snapshot_bytes) VALUES (?,?,?,?,?)",
            tuple(entity[field] for field in fields),
        ).rowcount
        stored = self._authorization_trust_snapshot_entity(
            entity["trust_snapshot_hash"]
        )
        if stored != entity:
            raise StoreIntegrityError(
                "authorization trust snapshot hash conflicts with stored bytes"
            )
        if inserted:
            self._append_audit(
                "authorization_trust_snapshot",
                entity["trust_snapshot_hash"],
                "AUTHORIZATION_TRUST_SNAPSHOT_RECORDED",
                {
                    "primary_key": {
                        "trust_snapshot_hash": entity["trust_snapshot_hash"]
                    },
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        return bool(inserted)

    @staticmethod
    def _approval_subject_entity(subject: dict[str, Any]) -> dict[str, Any]:
        value = validate_approval_subject(subject)
        return {
            "approval_subject_hash": approval_subject_hash(value),
            "contract_version": value["contract_version"],
            "resolution_id": value["resolution_id"],
            "execution_nonce": value["execution_nonce"],
            "payload_json": _json(value),
        }

    @staticmethod
    def _approval_assertion_entities(
        assertions: list[dict[str, Any]] | tuple[dict[str, Any], ...],
        *,
        approval_subject_hash_value: str,
        authorization_record_set_hash: str,
    ) -> tuple[dict[str, Any], ...]:
        entities: list[dict[str, Any]] = []
        for raw in assertions:
            value = validate_approval_assertion_shape(raw)
            if value["approval_subject_hash"] != approval_subject_hash_value:
                raise StoreIntegrityError(
                    "approval assertion is bound to a different subject"
                )
            entities.append(
                {
                    "assertion_hash": approval_assertion_hash(value),
                    "approval_subject_hash": approval_subject_hash_value,
                    "approval_id": value["approval_id"],
                    "normalized_approval_id": normalized_identity(
                        value["approval_id"]
                    ),
                    "role_claim": value["role_claim"],
                    "authorization_record_set_hash": authorization_record_set_hash,
                    "authorization_record_id": value["authorization_record_id"],
                    "authorization_record_hash": value["authorization_record_hash"],
                    "payload_json": _json(value),
                }
            )
        entities.sort(key=lambda item: item["assertion_hash"])
        return tuple(entities)

    @staticmethod
    def _assertion_set_hash(assertion_hashes: tuple[str, ...]) -> str:
        canonical = tuple(sorted(assertion_hashes))
        return _domain_hash(
            _APPROVAL_ASSERTION_SET_DOMAIN,
            _json(canonical).encode("utf-8"),
        )

    @staticmethod
    def _approval_consumption_entity(
        *,
        subject: dict[str, Any],
        assertion_set_hash: str,
        authorization_record_set_hash: str,
        replay_admission_hash: str,
        after_case_hash: str,
        after_run_id: str,
        a06_refs: dict[str, str] | None = None,
        replay_authorization_authenticity_binding_hash: str | None = None,
    ) -> dict[str, Any]:
        subject_value = validate_approval_subject(subject)
        effective_a06_refs = a06_refs or {}
        if effective_a06_refs and set(effective_a06_refs) != set(
            _A06_AUTHENTICITY_REF_KEYS
        ):
            raise StoreIntegrityError(
                "approval consumption requires exact A06 authenticity refs"
            )
        payload = {
            "contract_version": (
                A06_APPROVAL_CONSUMPTION_CONTRACT_VERSION
                if effective_a06_refs
                else APPROVAL_CONSUMPTION_CONTRACT_VERSION
            ),
            "approval_subject_hash": approval_subject_hash(subject_value),
            "assertion_set_hash": assertion_set_hash,
            "authorization_record_set_hash": authorization_record_set_hash,
            "execution_nonce": subject_value["execution_nonce"],
            "use_policy": subject_value["use_policy"],
            "replay_admission_hash": replay_admission_hash,
            "after_case_hash": after_case_hash,
            "after_run_id": after_run_id,
        }
        if effective_a06_refs:
            if not _is_lower_hex(
                replay_authorization_authenticity_binding_hash, 64
            ):
                raise StoreIntegrityError(
                    "A06 approval consumption requires persistent authenticity binding"
                )
            payload.update(effective_a06_refs)
            payload[
                "replay_authorization_authenticity_binding_hash"
            ] = replay_authorization_authenticity_binding_hash
        payload_json = _json(payload)
        return {
            "consumption_hash": _domain_hash(
                (
                    _A06_APPROVAL_CONSUMPTION_DOMAIN
                    if effective_a06_refs
                    else _APPROVAL_CONSUMPTION_DOMAIN
                ),
                payload_json.encode("utf-8"),
            ),
            "approval_subject_hash": payload["approval_subject_hash"],
            "assertion_set_hash": assertion_set_hash,
            "authorization_record_set_hash": authorization_record_set_hash,
            "execution_nonce": payload["execution_nonce"],
            "replay_admission_hash": replay_admission_hash,
            "after_run_id": after_run_id,
            "payload_json": payload_json,
        }

    @staticmethod
    def _baseline_approval_binding_entity(
        *,
        replay: ReplayResult,
        subject_hash: str,
        assertion_hashes: tuple[str, ...],
        authorization_record_set_hash: str,
        a06_refs: dict[str, str] | None = None,
        replay_authorization_authenticity_binding_hash: str | None = None,
    ) -> dict[str, Any] | None:
        if replay.baseline is None:
            return None
        assertion_set_hash = QualityCIStore._assertion_set_hash(assertion_hashes)
        effective_a06_refs = a06_refs or {}
        if effective_a06_refs and set(effective_a06_refs) != set(
            _A06_AUTHENTICITY_REF_KEYS
        ):
            raise StoreIntegrityError(
                "baseline approval binding requires exact A06 authenticity refs"
            )
        payload = {
            "contract_version": (
                A06_BASELINE_APPROVAL_BINDING_CONTRACT_VERSION
                if effective_a06_refs
                else BASELINE_APPROVAL_BINDING_CONTRACT_VERSION
            ),
            "baseline_id": replay.baseline.baseline_id,
            "baseline_hash": canonical_hash(replay.baseline.to_dict()),
            "after_case_hash": replay.after.case_hash,
            "after_run_id": replay.after.run_id,
            "resolution_id": replay.resolution_id,
            "artifact_set_hash": replay.artifact_set_hash,
            "approval_subject_hash": subject_hash,
            "assertion_hashes": list(sorted(assertion_hashes)),
            "assertion_set_hash": assertion_set_hash,
            "authorization_record_set_hash": authorization_record_set_hash,
        }
        if effective_a06_refs:
            if not _is_lower_hex(
                replay_authorization_authenticity_binding_hash, 64
            ):
                raise StoreIntegrityError(
                    "A06 baseline binding requires persistent authenticity binding"
                )
            payload.update(effective_a06_refs)
            payload[
                "replay_authorization_authenticity_binding_hash"
            ] = replay_authorization_authenticity_binding_hash
        payload_json = _json(payload)
        return {
            "baseline_binding_hash": _domain_hash(
                (
                    _A06_BASELINE_APPROVAL_BINDING_DOMAIN
                    if effective_a06_refs
                    else _BASELINE_APPROVAL_BINDING_DOMAIN
                ),
                payload_json.encode("utf-8"),
            ),
            "baseline_id": replay.baseline.baseline_id,
            "after_case_hash": replay.after.case_hash,
            "after_run_id": replay.after.run_id,
            "resolution_id": replay.resolution_id,
            "artifact_set_hash": replay.artifact_set_hash,
            "approval_subject_hash": subject_hash,
            "assertion_set_hash": assertion_set_hash,
            "authorization_record_set_hash": authorization_record_set_hash,
            "payload_json": payload_json,
        }

    @staticmethod
    def _replay_approval_expectation_entity(
        *,
        replay: ReplayResult,
        subject_hash: str,
        assertion_hashes: tuple[str, ...],
        authorization_record_set_hash: str,
        consumption_hash: str,
        replay_admission_hash: str,
        baseline_binding_hash: str | None,
        a06_refs: dict[str, str] | None = None,
        replay_authorization_authenticity_binding_hash: str | None = None,
    ) -> dict[str, Any]:
        assertion_set_hash = QualityCIStore._assertion_set_hash(assertion_hashes)
        effective_a06_refs = a06_refs or {}
        if effective_a06_refs and set(effective_a06_refs) != set(
            _A06_AUTHENTICITY_REF_KEYS
        ):
            raise StoreIntegrityError(
                "replay approval expectation requires exact A06 authenticity refs"
            )
        baseline = (
            {
                "baseline_id": replay.baseline.baseline_id,
                "baseline_hash": canonical_hash(replay.baseline.to_dict()),
            }
            if replay.baseline is not None
            else None
        )
        payload = {
            "contract_version": (
                A06_REPLAY_APPROVAL_EXPECTATION_CONTRACT_VERSION
                if effective_a06_refs
                else REPLAY_APPROVAL_EXPECTATION_CONTRACT_VERSION
            ),
            "resolution_id": replay.resolution_id,
            "after_case_hash": replay.after.case_hash,
            "after_run_id": replay.after.run_id,
            "artifact_set_hash": replay.artifact_set_hash,
            "approval_subject_hash": subject_hash,
            "assertion_hashes": list(sorted(assertion_hashes)),
            "assertion_set_hash": assertion_set_hash,
            "authorization_record_set_hash": authorization_record_set_hash,
            "consumption_hash": consumption_hash,
            "replay_admission_hash": replay_admission_hash,
            "baseline": baseline,
            "baseline_binding_hash": baseline_binding_hash,
        }
        if effective_a06_refs:
            if not _is_lower_hex(
                replay_authorization_authenticity_binding_hash, 64
            ):
                raise StoreIntegrityError(
                    "A06 replay expectation requires persistent authenticity binding"
                )
            payload.update(effective_a06_refs)
            payload[
                "replay_authorization_authenticity_binding_hash"
            ] = replay_authorization_authenticity_binding_hash
        payload_json = _json(payload)
        return {
            "expectation_hash": _domain_hash(
                (
                    _A06_REPLAY_APPROVAL_EXPECTATION_DOMAIN
                    if effective_a06_refs
                    else _REPLAY_APPROVAL_EXPECTATION_DOMAIN
                ),
                payload_json.encode("utf-8"),
            ),
            "resolution_id": replay.resolution_id,
            "after_case_hash": replay.after.case_hash,
            "after_run_id": replay.after.run_id,
            "artifact_set_hash": replay.artifact_set_hash,
            "approval_subject_hash": subject_hash,
            "assertion_set_hash": assertion_set_hash,
            "authorization_record_set_hash": authorization_record_set_hash,
            "consumption_hash": consumption_hash,
            "replay_admission_hash": replay_admission_hash,
            "baseline_id": replay.baseline.baseline_id if replay.baseline else None,
            "baseline_binding_hash": baseline_binding_hash,
            "payload_json": payload_json,
        }

    @staticmethod
    def _canonical_resolution_value(resolution: Any) -> dict[str, Any]:
        required = {
            "resolution_id",
            "replacement_set_id",
            "description",
            "operations",
            "approvals",
        }
        if not isinstance(resolution, dict) or set(resolution) != required:
            raise StoreIntegrityError(
                "stored replay resolution must contain the exact versioned fields"
            )
        for field in ("resolution_id", "replacement_set_id", "description"):
            if not _is_nonempty_string(resolution.get(field)):
                raise StoreIntegrityError(f"resolution {field} must be non-empty")
        if not _resolution_operations_are_valid(resolution.get("operations")):
            raise StoreIntegrityError("resolution operations are invalid")
        approvals = resolution.get("approvals")
        if not isinstance(approvals, list) or not approvals:
            raise StoreIntegrityError("resolution approvals must be a non-empty list")
        allowed_approval_fields = {
            "role",
            "decision",
            "case_id",
            "event_id",
            "event_revision",
            "approved_case_hash",
            "approved_patch_hash",
            "comment",
            "resolution_id",
            "operations",
        }
        canonical_approvals: list[dict[str, Any]] = []
        for approval in approvals:
            if (
                not isinstance(approval, dict)
                or set(approval) - allowed_approval_fields
            ):
                raise StoreIntegrityError(
                    "approval payload contains unsupported fields"
                )
            canonical_approvals.append(
                strict_json_loads(_json(approval))
            )
        canonical_approvals.sort(key=_json)
        canonical = {
            "resolution_id": resolution["resolution_id"],
            "replacement_set_id": resolution["replacement_set_id"],
            "description": resolution["description"],
            "operations": strict_json_loads(_json(resolution["operations"])),
            "approvals": canonical_approvals,
        }
        return canonical

    @classmethod
    def _canonical_resolution_bytes(cls, resolution: Any) -> bytes:
        return _json(cls._canonical_resolution_value(resolution)).encode("utf-8")

    @staticmethod
    def _approval_payload_for_store(
        resolution: dict[str, Any],
        approval: dict[str, Any],
        artifact_subject: dict[str, Any],
        validation_policy: dict[str, Any],
    ) -> dict[str, Any]:
        approval_core_fields = {
            "role",
            "decision",
            "case_id",
            "event_id",
            "event_revision",
            "approved_case_hash",
            "approved_patch_hash",
        }
        allowed_approval_fields = approval_core_fields | {
            "comment",
            "resolution_id",
            "operations",
        }
        if not isinstance(approval, dict) or set(approval) - allowed_approval_fields:
            raise StoreIntegrityError("approval payload contains unsupported fields")
        if not approval_core_fields.issubset(approval):
            raise StoreIntegrityError("approval payload is missing identity fields")
        if (
            "resolution_id" in approval
            and approval["resolution_id"] != resolution["resolution_id"]
        ):
            raise StoreIntegrityError(
                "approval payload resolution_id conflicts with its resolution"
            )
        if (
            "operations" in approval
            and approval["operations"] != resolution["operations"]
        ):
            raise StoreIntegrityError(
                "approval payload operations conflict with its approved patch"
            )
        payload = {
            **{field: approval[field] for field in approval_core_fields},
            "resolution_id": resolution["resolution_id"],
            "operations": resolution["operations"],
            "artifact_subject": artifact_subject,
            "validation_policy": validation_policy,
        }
        if "comment" in approval:
            payload["comment"] = approval["comment"]
        return payload

    @classmethod
    def _build_replay_admission(
        cls,
        replay: ReplayResult,
        resolution: dict[str, Any],
        approved_case: dict[str, Any],
        resolved_case: dict[str, Any],
        subject: dict[str, Any],
        context: ArtifactContext,
        native_approval: _NativeApprovalPersistence | None = None,
        source_contexts: tuple[_CaseSourceContext, _CaseSourceContext] | None = None,
    ) -> tuple[ReplayAdmission, str]:
        if source_contexts is not None:
            if (
                type(source_contexts) is not tuple
                or len(source_contexts) != 2
                or any(
                    not _is_sealed_case_source_context(item)
                    for item in source_contexts
                )
            ):
                raise StoreIntegrityError(
                    "A08 admission requires exact sealed before/after source contexts"
                )
            before_source_context, after_source_context = source_contexts
            before_source = before_source_context.assurance().to_dict()
            after_source = after_source_context.assurance().to_dict()
            if (
                before_source_context.case() != approved_case
                or after_source_context.case() != resolved_case
                or any(
                    getattr(replay.before, key) != value
                    for key, value in before_source.items()
                )
                or any(
                    getattr(replay.after, key) != value
                    for key, value in after_source.items()
                )
                or after_source["case_source_assurance_state"]
                != CASE_SOURCE_DERIVED
                or before_source["case_source_set_hash"]
                != after_source["case_source_set_hash"]
                or before_source["case_source_binding_hash"]
                != after_source["case_source_binding_hash"]
            ):
                raise StoreIntegrityError(
                    "A08 admission source contexts differ from the replay"
                )
        else:
            before_source = None
            after_source = None
        canonical_resolution_bytes = cls._canonical_resolution_bytes(resolution)
        canonical_resolution = strict_json_loads(
            canonical_resolution_bytes.decode("utf-8")
        )
        if native_approval is None:
            approval_payloads = [
                cls._approval_payload_for_store(
                    canonical_resolution,
                    approval,
                    context.subject_fields(),
                    subject["validation_policy"],
                )
                for approval in canonical_resolution["approvals"]
            ]
            approval_refs = [
                {
                    **{
                        field: payload[field]
                        for field in (
                            "resolution_id",
                            "case_id",
                            "event_id",
                            "event_revision",
                            "approved_case_hash",
                            "approved_patch_hash",
                            "role",
                            "decision",
                        )
                    },
                    "payload_hash": canonical_hash(payload),
                }
                for payload in approval_payloads
            ]
            admission_subject = subject
            admission_subject_hash = canonical_hash(subject)
            contract_version = REPLAY_ADMISSION_CONTRACT_VERSION
            admission_domain = _REPLAY_ADMISSION_DOMAIN
            native_fields: dict[str, Any] = {}
        else:
            admission_subject = validate_approval_subject(native_approval.subject)
            admission_subject_hash = approval_subject_hash(admission_subject)
            assertion_entities = cls._approval_assertion_entities(
                native_approval.assertions,
                approval_subject_hash_value=admission_subject_hash,
                authorization_record_set_hash=(
                    native_approval.authorization_context.record_set_hash
                ),
            )
            approval_refs = [
                {
                    "assertion_hash": entity["assertion_hash"],
                    "approval_id": strict_json_loads(entity["payload_json"])[
                        "approval_id"
                    ],
                    "role_claim": entity["role_claim"],
                    "authorization_record_id": entity[
                        "authorization_record_id"
                    ],
                    "authorization_record_hash": entity[
                        "authorization_record_hash"
                    ],
                }
                for entity in assertion_entities
            ]
            assertion_set_hash = cls._assertion_set_hash(
                tuple(entity["assertion_hash"] for entity in assertion_entities)
            )
            a06_refs = (
                _native_a06_refs(native_approval)
                if native_approval.a06_refs
                else {}
            )
            if a06_refs and a06_refs["authorization_record_set_hash"] != (
                native_approval.authorization_context.record_set_hash
            ):
                raise StoreIntegrityError(
                    "A06 authenticity refs differ from authorization raw bytes"
                )
            if source_contexts is not None:
                if not a06_refs:
                    raise StoreIntegrityError(
                        "A08 admission requires rebuilt A06 authenticity facts"
                    )
                contract_version = A08_REPLAY_ADMISSION_CONTRACT_VERSION
                admission_domain = _A08_REPLAY_ADMISSION_DOMAIN
            else:
                contract_version = (
                    A06_REPLAY_ADMISSION_CONTRACT_VERSION
                    if a06_refs
                    else A05_REPLAY_ADMISSION_CONTRACT_VERSION
                )
                admission_domain = (
                    _A06_REPLAY_ADMISSION_DOMAIN
                    if a06_refs
                    else _A05_REPLAY_ADMISSION_DOMAIN
                )
            native_fields = {
                "authorization_record_set_hash": (
                    native_approval.authorization_context.record_set_hash
                ),
                "approval_assertion_set_hash": assertion_set_hash,
                "execution_nonce": admission_subject["execution_nonce"],
                "use_policy": admission_subject["use_policy"],
                **a06_refs,
            }
        approval_refs.sort(key=_json)
        baseline = (
            {
                "baseline_id": replay.baseline.baseline_id,
                "baseline_hash": canonical_hash(replay.baseline.to_dict()),
            }
            if replay.baseline is not None
            else None
        )
        core = {
            "contract_version": contract_version,
            "resolution_id": replay.resolution_id,
            "resolution_hash": _domain_hash(
                _RESOLUTION_RECORD_DOMAIN, canonical_resolution_bytes
            ),
            "assurance_state": replay.assurance_state,
            "artifact_set_hash": replay.artifact_set_hash,
            "controlled_reference_set_hash": replay.controlled_reference_set_hash,
            "controlled_reference_source_set_hash": context.source_reference_set_hash,
            "source_validation_evidence_set_hash": replay.source_validation_evidence_set_hash,
            "resolved_validation_evidence_set_hash": replay.resolved_validation_evidence_set_hash,
            "validation_evidence_pair_hash": replay.validation_evidence_pair_hash,
            "validation_evidence_contract_version": VALIDATION_EVIDENCE_CONTRACT_VERSION,
            "pre_case": {
                "case_id": approved_case["case_id"],
                "case_hash": canonical_hash(approved_case),
            },
            "before_case": {
                "case_id": replay.before.case_id,
                "case_hash": replay.before.case_hash,
            },
            "before_run": {
                "run_id": replay.before.run_id,
                "case_id": replay.before.case_id,
                "case_hash": replay.before.case_hash,
                "status": str(replay.before.overall_status),
                "reference_assurance_state": replay.before.reference_assurance_state,
                "reference_set_hash": replay.before.reference_set_hash,
                "reference_contract_version": replay.before.reference_contract_version,
                "validation_assurance_state": replay.before.validation_assurance_state,
                "validation_evidence_set_hash": replay.before.validation_evidence_set_hash,
                "validation_evidence_contract_version": replay.before.validation_evidence_contract_version,
                "run_hash": canonical_hash(replay.before.to_dict()),
            },
            "after_case": {
                "case_id": resolved_case["case_id"],
                "case_hash": canonical_hash(resolved_case),
            },
            "after_run": {
                "run_id": replay.after.run_id,
                "case_id": replay.after.case_id,
                "case_hash": replay.after.case_hash,
                "status": str(replay.after.overall_status),
                "reference_assurance_state": replay.after.reference_assurance_state,
                "reference_set_hash": replay.after.reference_set_hash,
                "reference_contract_version": replay.after.reference_contract_version,
                "validation_assurance_state": replay.after.validation_assurance_state,
                "validation_evidence_set_hash": replay.after.validation_evidence_set_hash,
                "validation_evidence_contract_version": replay.after.validation_evidence_contract_version,
                "run_hash": canonical_hash(replay.after.to_dict()),
            },
            "approval_subject": admission_subject,
            "approval_subject_hash": admission_subject_hash,
            "approved_patch_hash": admission_subject_hash,
            "approval_refs": approval_refs,
            "baseline": baseline,
            "ruleset_versions": {
                "before": replay.before.ruleset_version,
                "after": replay.after.ruleset_version,
            },
            "artifact_contract_version": context.artifact_contract_version,
            "reference_contract_version": context.reference_context.contract_version,
            "validation_contract_version": VALIDATION_EVIDENCE_CONTRACT_VERSION,
            "case_schema_version": context.case_schema_version,
            "parser_contract_version": context.parser_contract_version,
            "mapping_contract_version": context.mapping_contract_version,
            "security_root_policy_version": context.security_root_policy_version,
            **native_fields,
        }
        if source_contexts is not None:
            core["before_case_source"] = before_source
            core["after_case_source"] = after_source
        core_bytes = _json(core).encode("utf-8")
        replay_admission_hash = _domain_hash(admission_domain, core_bytes)
        payload = {"replay_admission_hash": replay_admission_hash, **core}
        payload_bytes = _json(payload).encode("utf-8")
        return (
            ReplayAdmission(replay_admission_hash, payload_bytes),
            canonical_resolution_bytes.decode("utf-8"),
        )

    @staticmethod
    def _replay_admission_entity(
        admission: ReplayAdmission,
        resolution_json: str,
    ) -> dict[str, Any]:
        payload = admission.to_dict()
        return {
            "replay_admission_hash": admission.replay_admission_hash,
            "resolution_id": payload["resolution_id"],
            "artifact_set_hash": payload["artifact_set_hash"],
            "approved_case_hash": payload["pre_case"]["case_hash"],
            "resolution_json": resolution_json,
            "payload_json": admission.canonical_payload_bytes.decode("utf-8"),
        }

    @staticmethod
    def _replay_ledger_entity(
        admission: ReplayAdmission,
        *,
        consumption_hash: str | None = None,
        replay_authorization_authenticity_binding_hash: str | None = None,
    ) -> dict[str, Any]:
        payload = admission.to_dict()
        admission_version = payload.get("contract_version")
        a08 = admission_version == A08_REPLAY_ADMISSION_CONTRACT_VERSION
        a06 = admission_version in {
            A06_REPLAY_ADMISSION_CONTRACT_VERSION,
            A08_REPLAY_ADMISSION_CONTRACT_VERSION,
        }
        native = admission_version in {
            A05_REPLAY_ADMISSION_CONTRACT_VERSION,
            A06_REPLAY_ADMISSION_CONTRACT_VERSION,
            A08_REPLAY_ADMISSION_CONTRACT_VERSION,
        }
        ledger_payload = {
            "contract_version": (
                A08_REPLAY_LEDGER_CONTRACT_VERSION
                if a08
                else (
                    A06_REPLAY_LEDGER_CONTRACT_VERSION
                    if a06
                    else (
                        A05_REPLAY_LEDGER_CONTRACT_VERSION
                        if native
                        else REPLAY_LEDGER_CONTRACT_VERSION
                    )
                )
            ),
            "replay_admission_hash": admission.replay_admission_hash,
            "assurance_state": payload["assurance_state"],
            "resolution_id": payload["resolution_id"],
            "artifact_set_hash": payload["artifact_set_hash"],
            "controlled_reference_set_hash": payload[
                "controlled_reference_set_hash"
            ],
            "controlled_reference_source_set_hash": payload[
                "controlled_reference_source_set_hash"
            ],
            "source_validation_evidence_set_hash": payload[
                "source_validation_evidence_set_hash"
            ],
            "resolved_validation_evidence_set_hash": payload[
                "resolved_validation_evidence_set_hash"
            ],
            "validation_evidence_pair_hash": payload[
                "validation_evidence_pair_hash"
            ],
            "approved_case_hash": payload["pre_case"]["case_hash"],
            "before_run": payload["before_run"],
            "after_case": payload["after_case"],
            "after_run": payload["after_run"],
            "baseline": payload["baseline"],
        }
        if a08:
            ledger_payload.update(
                {
                    "before_case_source": payload["before_case_source"],
                    "after_case_source": payload["after_case_source"],
                }
            )
        if native:
            if not _is_lower_hex(consumption_hash, 64):
                raise StoreIntegrityError(
                    "native replay ledger requires exact approval consumption"
                )
            ledger_payload.update(
                {
                    "approval_subject_hash": payload[
                        "approval_subject_hash"
                    ],
                    "approval_assertion_set_hash": payload[
                        "approval_assertion_set_hash"
                    ],
                    "authorization_record_set_hash": payload[
                        "authorization_record_set_hash"
                    ],
                    "execution_nonce": payload["execution_nonce"],
                    "use_policy": payload["use_policy"],
                    "consumption_hash": consumption_hash,
                }
            )
        if a06:
            if not _is_lower_hex(
                replay_authorization_authenticity_binding_hash, 64
            ):
                raise StoreIntegrityError(
                    "A06 replay ledger requires its persistent authenticity binding"
                )
            ledger_payload.update(
                {
                    key: payload[key]
                    for key in _A06_AUTHENTICITY_REF_KEYS
                }
            )
            ledger_payload[
                "replay_authorization_authenticity_binding_hash"
            ] = replay_authorization_authenticity_binding_hash
        payload_json = _json(ledger_payload)
        return {
            "replay_ledger_hash": _domain_hash(
                (
                    _A08_REPLAY_LEDGER_DOMAIN
                    if a08
                    else (
                        _A06_REPLAY_LEDGER_DOMAIN
                        if a06
                        else (
                            _A05_REPLAY_LEDGER_DOMAIN
                            if native
                            else _REPLAY_LEDGER_DOMAIN
                        )
                    )
                ),
                payload_json.encode("utf-8"),
            ),
            "replay_admission_hash": admission.replay_admission_hash,
            "consumption_hash": consumption_hash,
            "resolution_id": payload["resolution_id"],
            "artifact_set_hash": payload["artifact_set_hash"],
            "approved_case_hash": payload["pre_case"]["case_hash"],
            "after_run_id": payload["after_run"]["run_id"],
            "payload_json": payload_json,
        }

    @staticmethod
    def _replay_validation_binding_entity(
        replay: ReplayResult,
        admission: ReplayAdmission,
        source_context: _ValidationEvidenceContext,
        resolved_context: _ValidationEvidenceContext,
    ) -> dict[str, Any]:
        payload = {
            "contract_version": REPLAY_VALIDATION_BINDING_CONTRACT_VERSION,
            "resolution_id": replay.resolution_id,
            "source_case_hash": replay.before.case_hash,
            "after_case_hash": replay.after.case_hash,
            "after_run_id": replay.after.run_id,
            "source_evidence_set_hash": source_context.evidence_set_hash,
            "source_case_subject_hash": source_context.case_subject_hash,
            "source_scope_digest": source_context.scope_digest,
            "resolved_evidence_set_hash": resolved_context.evidence_set_hash,
            "resolved_case_subject_hash": resolved_context.case_subject_hash,
            "resolved_scope_digest": resolved_context.scope_digest,
            "evidence_pair_hash": replay.validation_evidence_pair_hash,
            "replay_admission_hash": admission.replay_admission_hash,
            "ruleset_version": replay.after.ruleset_version,
            "validation_contract_version": VALIDATION_EVIDENCE_CONTRACT_VERSION,
        }
        payload_json = _json(payload)
        return {
            "validation_binding_hash": _domain_hash(
                _REPLAY_VALIDATION_BINDING_DOMAIN, payload_json.encode("utf-8")
            ),
            "resolution_id": replay.resolution_id,
            "source_case_hash": replay.before.case_hash,
            "after_case_hash": replay.after.case_hash,
            "after_run_id": replay.after.run_id,
            "source_evidence_set_hash": source_context.evidence_set_hash,
            "resolved_evidence_set_hash": resolved_context.evidence_set_hash,
            "evidence_pair_hash": replay.validation_evidence_pair_hash,
            "replay_admission_hash": admission.replay_admission_hash,
            "payload_json": payload_json,
        }

    def _save_replay_validation_binding_entity(
        self, entity: dict[str, Any]
    ) -> bool:
        inserted = self.connection.execute(
            """INSERT OR IGNORE INTO replay_validation_bindings
               (validation_binding_hash,resolution_id,source_case_hash,
                after_case_hash,after_run_id,source_evidence_set_hash,
                resolved_evidence_set_hash,evidence_pair_hash,
                replay_admission_hash,payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            tuple(
                entity[key]
                for key in (
                    "validation_binding_hash",
                    "resolution_id",
                    "source_case_hash",
                    "after_case_hash",
                    "after_run_id",
                    "source_evidence_set_hash",
                    "resolved_evidence_set_hash",
                    "evidence_pair_hash",
                    "replay_admission_hash",
                    "payload_json",
                )
            ),
        ).rowcount
        if inserted:
            self._append_audit(
                "replay_validation_binding",
                entity["validation_binding_hash"],
                "REPLAY_VALIDATION_BINDING_RECORDED",
                {
                    "primary_key": {
                        "validation_binding_hash": entity[
                            "validation_binding_hash"
                        ]
                    },
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        else:
            row = self.connection.execute(
                "SELECT * FROM replay_validation_bindings "
                "WHERE validation_binding_hash=?",
                (entity["validation_binding_hash"],),
            ).fetchone()
            if row is None or dict(row) != entity:
                raise StoreIntegrityError(
                    "validation binding identity conflicts with stored content"
                )
        return bool(inserted)

    @staticmethod
    def _replay_authorization_authenticity_binding_entity(
        replay: ReplayResult,
        admission: ReplayAdmission,
        *,
        approval_subject_hash_value: str,
        approval_assertion_set_hash: str,
        a06_refs: dict[str, str],
    ) -> dict[str, Any]:
        if set(a06_refs) != set(_A06_AUTHENTICITY_REF_KEYS):
            raise StoreIntegrityError(
                "authorization authenticity refs require the exact A06 field set"
            )
        payload = {
            "contract_version": (
                REPLAY_AUTHORIZATION_AUTHENTICITY_BINDING_CONTRACT_VERSION
            ),
            "resolution_id": replay.resolution_id,
            "replay_admission_hash": admission.replay_admission_hash,
            "approval_subject_hash": approval_subject_hash_value,
            "approval_assertion_set_hash": approval_assertion_set_hash,
            **a06_refs,
            "after_case_hash": replay.after.case_hash,
            "after_run_id": replay.after.run_id,
        }
        payload_json = _json(payload)
        persistent_hash = _domain_hash(
            _REPLAY_AUTHORIZATION_AUTHENTICITY_BINDING_DOMAIN,
            payload_json.encode("utf-8"),
        )
        return {
            "replay_authorization_authenticity_binding_hash": persistent_hash,
            "replay_admission_hash": admission.replay_admission_hash,
            "approval_subject_hash": approval_subject_hash_value,
            "approval_assertion_set_hash": approval_assertion_set_hash,
            "authorization_record_set_hash": a06_refs[
                "authorization_record_set_hash"
            ],
            "trust_snapshot_hash": a06_refs[
                "authorization_trust_snapshot_hash"
            ],
            "authorization_authenticity_context_hash": a06_refs[
                "authorization_authenticity_context_hash"
            ],
            "stateless_authenticity_binding_hash": a06_refs[
                "authorization_authenticity_binding_hash"
            ],
            "after_case_hash": replay.after.case_hash,
            "after_run_id": replay.after.run_id,
            "payload_json": payload_json,
        }

    def _save_replay_authorization_authenticity_binding_entity(
        self, entity: dict[str, Any]
    ) -> bool:
        fields = (
            "replay_authorization_authenticity_binding_hash",
            "replay_admission_hash",
            "approval_subject_hash",
            "approval_assertion_set_hash",
            "authorization_record_set_hash",
            "trust_snapshot_hash",
            "authorization_authenticity_context_hash",
            "stateless_authenticity_binding_hash",
            "after_case_hash",
            "after_run_id",
            "payload_json",
        )
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO replay_authorization_authenticity_bindings "
            "(" + ",".join(fields) + ") VALUES (" + ",".join("?" for _ in fields) + ")",
            tuple(entity[field] for field in fields),
        ).rowcount
        row = self.connection.execute(
            "SELECT * FROM replay_authorization_authenticity_bindings "
            "WHERE replay_authorization_authenticity_binding_hash=?",
            (entity["replay_authorization_authenticity_binding_hash"],),
        ).fetchone()
        if row is None or dict(row) != entity:
            raise StoreIntegrityError(
                "replay authorization authenticity binding conflicts with stored content"
            )
        if inserted:
            self._append_audit(
                "replay_authorization_authenticity_binding",
                entity["replay_authorization_authenticity_binding_hash"],
                "REPLAY_AUTHORIZATION_AUTHENTICITY_BINDING_RECORDED",
                {
                    "primary_key": {
                        "replay_authorization_authenticity_binding_hash": entity[
                            "replay_authorization_authenticity_binding_hash"
                        ]
                    },
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        return bool(inserted)

    def _replay_authorization_authenticity_binding_entity_for_hash(
        self, persistent_binding_hash: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM replay_authorization_authenticity_bindings "
            "WHERE replay_authorization_authenticity_binding_hash=?",
            (persistent_binding_hash,),
        ).fetchone()
        return dict(row) if row is not None else None

    def _native_a06_rows_match_final_context(
        self,
        native: _NativeApprovalPersistence,
        *,
        subject_entity: dict[str, Any],
        assertion_entities: tuple[dict[str, Any], ...],
        consumption_entity: dict[str, Any],
        expectation_entity: dict[str, Any],
        baseline_binding_entity: dict[str, Any] | None,
        authenticity_binding_entity: dict[str, Any],
        ledger_entity: dict[str, Any],
    ) -> bool:
        """One stored-byte A06 semantic preflight with verify-call-local caches."""

        previous_context_cache = getattr(
            self, "_verify_authorization_context_cache", None
        )
        previous_snapshot_cache = getattr(
            self, "_verify_authorization_snapshot_cache", None
        )
        previous_binding_cache = getattr(
            self, "_verify_authorization_binding_cache", None
        )
        self._verify_authorization_context_cache = {}
        self._verify_authorization_snapshot_cache = {}
        self._verify_authorization_binding_cache = {}
        try:
            stored_context = self._stored_authorization_authenticity_context(
                native.authorization_context.record_set_hash,
                native.authenticity_context.trust_snapshot_hash,
            )
            if (
                stored_context.state != AUTHORIZATION_AUTHENTICITY_PASS
                or stored_context != native.authenticity_context
            ):
                return False
            expected_snapshot = (
                self._authorization_trust_snapshot_entity_from_context(
                    stored_context,
                    native.authorization_trust_bundle,
                )
            )
            stored_snapshot = self._authorization_trust_snapshot_entity(
                stored_context.trust_snapshot_hash
            )
            stored_binding = (
                self._replay_authorization_authenticity_binding_entity_for_hash(
                    authenticity_binding_entity[
                        "replay_authorization_authenticity_binding_hash"
                    ]
                )
            )
            stored_subject = self.connection.execute(
                "SELECT * FROM approval_subjects WHERE approval_subject_hash=?",
                (subject_entity["approval_subject_hash"],),
            ).fetchone()
            stored_assertions = [
                self.connection.execute(
                    "SELECT * FROM approval_assertions WHERE assertion_hash=?",
                    (item["assertion_hash"],),
                ).fetchone()
                for item in assertion_entities
            ]
            stored_consumption = self.connection.execute(
                "SELECT * FROM approval_consumptions WHERE consumption_hash=?",
                (consumption_entity["consumption_hash"],),
            ).fetchone()
            stored_expectation = self.connection.execute(
                "SELECT * FROM replay_approval_expectations WHERE expectation_hash=?",
                (expectation_entity["expectation_hash"],),
            ).fetchone()
            stored_baseline_binding = (
                self.connection.execute(
                    "SELECT * FROM baseline_approval_bindings "
                    "WHERE baseline_binding_hash=?",
                    (baseline_binding_entity["baseline_binding_hash"],),
                ).fetchone()
                if baseline_binding_entity is not None
                else None
            )
            return (
                stored_snapshot == expected_snapshot
                and stored_binding == authenticity_binding_entity
                and stored_subject is not None
                and dict(stored_subject) == subject_entity
                and all(
                    row is not None and dict(row) == expected
                    for row, expected in zip(
                        stored_assertions,
                        assertion_entities,
                        strict=True,
                    )
                )
                and stored_consumption is not None
                and dict(stored_consumption) == consumption_entity
                and stored_expectation is not None
                and dict(stored_expectation) == expectation_entity
                and (
                    (
                        baseline_binding_entity is None
                        and stored_baseline_binding is None
                    )
                    or (
                        stored_baseline_binding is not None
                        and dict(stored_baseline_binding)
                        == baseline_binding_entity
                    )
                )
                and self._authorization_record_set_entity_is_semantically_valid(
                    self._authorization_record_set_entity(
                        expectation_entity["authorization_record_set_hash"]
                    )
                    or {}
                )
                and self._authorization_trust_snapshot_entity_is_semantically_valid(
                    expected_snapshot
                )
                and self._replay_authorization_authenticity_binding_entity_is_semantically_valid(
                    authenticity_binding_entity
                )
                and self._approval_subject_entity_is_semantically_valid(
                    subject_entity
                )
                and all(
                    self._approval_assertion_entity_is_semantically_valid(item)
                    for item in assertion_entities
                )
                and self._approval_consumption_entity_is_semantically_valid(
                    consumption_entity
                )
                and self._replay_approval_expectation_entity_is_semantically_valid(
                    expectation_entity
                )
                and (
                    baseline_binding_entity is None
                    or self._baseline_approval_binding_entity_is_semantically_valid(
                        baseline_binding_entity
                    )
                )
                and self._replay_ledger_entity_is_semantically_valid(
                    ledger_entity
                )
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            StoreIntegrityError,
            sqlite3.Error,
        ):
            return False
        finally:
            if previous_context_cache is None:
                del self._verify_authorization_context_cache
            else:
                self._verify_authorization_context_cache = previous_context_cache
            if previous_snapshot_cache is None:
                del self._verify_authorization_snapshot_cache
            else:
                self._verify_authorization_snapshot_cache = previous_snapshot_cache
            if previous_binding_cache is None:
                del self._verify_authorization_binding_cache
            else:
                self._verify_authorization_binding_cache = previous_binding_cache

    def _save_approval_subject_entity(self, entity: dict[str, Any]) -> bool:
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO approval_subjects "
            "(approval_subject_hash,contract_version,resolution_id,execution_nonce,payload_json) "
            "VALUES (?,?,?,?,?)",
            tuple(
                entity[field]
                for field in (
                    "approval_subject_hash",
                    "contract_version",
                    "resolution_id",
                    "execution_nonce",
                    "payload_json",
                )
            ),
        ).rowcount
        row = self.connection.execute(
            "SELECT * FROM approval_subjects WHERE approval_subject_hash=?",
            (entity["approval_subject_hash"],),
        ).fetchone()
        if row is None or dict(row) != entity:
            raise StoreIntegrityError(
                "approval subject identity or execution nonce is already bound"
            )
        if inserted:
            self._append_audit(
                "approval_subject",
                entity["approval_subject_hash"],
                "APPROVAL_SUBJECT_RECORDED",
                {
                    "primary_key": {
                        "approval_subject_hash": entity["approval_subject_hash"]
                    },
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        return bool(inserted)

    def _save_approval_assertion_entity(self, entity: dict[str, Any]) -> bool:
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO approval_assertions "
            "(assertion_hash,approval_subject_hash,approval_id,normalized_approval_id,role_claim,"
            "authorization_record_set_hash,authorization_record_id,"
            "authorization_record_hash,payload_json) VALUES (?,?,?,?,?,?,?,?,?)",
            tuple(
                entity[field]
                for field in (
                    "assertion_hash",
                    "approval_subject_hash",
                    "approval_id",
                    "normalized_approval_id",
                    "role_claim",
                    "authorization_record_set_hash",
                    "authorization_record_id",
                    "authorization_record_hash",
                    "payload_json",
                )
            ),
        ).rowcount
        row = self.connection.execute(
            "SELECT * FROM approval_assertions WHERE assertion_hash=?",
            (entity["assertion_hash"],),
        ).fetchone()
        if row is None or dict(row) != entity:
            raise StoreIntegrityError(
                "approval assertion identity conflicts with stored content"
            )
        if inserted:
            self._append_audit(
                "approval_assertion",
                entity["assertion_hash"],
                "APPROVAL_ASSERTION_RECORDED",
                {
                    "primary_key": {"assertion_hash": entity["assertion_hash"]},
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        return bool(inserted)

    def _save_approval_consumption_entity(self, entity: dict[str, Any]) -> bool:
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO approval_consumptions "
            "(consumption_hash,approval_subject_hash,assertion_set_hash,"
            "authorization_record_set_hash,execution_nonce,replay_admission_hash,"
            "after_run_id,payload_json) VALUES (?,?,?,?,?,?,?,?)",
            tuple(
                entity[field]
                for field in (
                    "consumption_hash",
                    "approval_subject_hash",
                    "assertion_set_hash",
                    "authorization_record_set_hash",
                    "execution_nonce",
                    "replay_admission_hash",
                    "after_run_id",
                    "payload_json",
                )
            ),
        ).rowcount
        row = self.connection.execute(
            "SELECT * FROM approval_consumptions WHERE consumption_hash=?",
            (entity["consumption_hash"],),
        ).fetchone()
        if row is None or dict(row) != entity:
            raise StoreIntegrityError(
                "SINGLE_REPLAY approval is already consumed by another admission"
            )
        if inserted:
            self._append_audit(
                "approval_consumption",
                entity["consumption_hash"],
                "APPROVAL_CONSUMPTION_RECORDED",
                {
                    "primary_key": {"consumption_hash": entity["consumption_hash"]},
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        return bool(inserted)

    def _save_replay_approval_expectation_entity(
        self, entity: dict[str, Any]
    ) -> bool:
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO replay_approval_expectations "
            "(expectation_hash,resolution_id,after_case_hash,after_run_id,"
            "artifact_set_hash,approval_subject_hash,assertion_set_hash,"
            "authorization_record_set_hash,consumption_hash,replay_admission_hash,"
            "baseline_id,baseline_binding_hash,payload_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(
                entity[field]
                for field in (
                    "expectation_hash",
                    "resolution_id",
                    "after_case_hash",
                    "after_run_id",
                    "artifact_set_hash",
                    "approval_subject_hash",
                    "assertion_set_hash",
                    "authorization_record_set_hash",
                    "consumption_hash",
                    "replay_admission_hash",
                    "baseline_id",
                    "baseline_binding_hash",
                    "payload_json",
                )
            ),
        ).rowcount
        row = self.connection.execute(
            "SELECT * FROM replay_approval_expectations WHERE expectation_hash=?",
            (entity["expectation_hash"],),
        ).fetchone()
        if row is None or dict(row) != entity:
            raise StoreIntegrityError(
                "replay approval expectation conflicts with stored cohort"
            )
        if inserted:
            self._append_audit(
                "replay_approval_expectation",
                entity["expectation_hash"],
                "REPLAY_APPROVAL_EXPECTATION_RECORDED",
                {
                    "primary_key": {"expectation_hash": entity["expectation_hash"]},
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        return bool(inserted)

    def _save_baseline_approval_binding_entity(
        self, entity: dict[str, Any]
    ) -> bool:
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO baseline_approval_bindings "
            "(baseline_binding_hash,baseline_id,after_case_hash,after_run_id,"
            "resolution_id,artifact_set_hash,approval_subject_hash,"
            "assertion_set_hash,authorization_record_set_hash,payload_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            tuple(
                entity[field]
                for field in (
                    "baseline_binding_hash",
                    "baseline_id",
                    "after_case_hash",
                    "after_run_id",
                    "resolution_id",
                    "artifact_set_hash",
                    "approval_subject_hash",
                    "assertion_set_hash",
                    "authorization_record_set_hash",
                    "payload_json",
                )
            ),
        ).rowcount
        row = self.connection.execute(
            "SELECT * FROM baseline_approval_bindings "
            "WHERE baseline_binding_hash=?",
            (entity["baseline_binding_hash"],),
        ).fetchone()
        if row is None or dict(row) != entity:
            raise StoreIntegrityError(
                "baseline approval binding conflicts with stored cohort"
            )
        if inserted:
            self._append_audit(
                "baseline_approval_binding",
                entity["baseline_binding_hash"],
                "BASELINE_APPROVAL_BINDING_RECORDED",
                {
                    "primary_key": {
                        "baseline_binding_hash": entity["baseline_binding_hash"]
                    },
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        return bool(inserted)

    def _replay_admission_links_match(
        self,
        entity: dict[str, Any],
        replay: ReplayResult,
        resolution: dict[str, Any],
        approved_case: dict[str, Any],
        resolved_case: dict[str, Any],
        subject: dict[str, Any],
    ) -> bool:
        try:
            case_expectations = (
                (
                    approved_case,
                    entity["approved_case_hash"],
                ),
                (
                    resolved_case,
                    replay.after.case_hash,
                ),
            )
            for case, case_hash in case_expectations:
                expected = self._case_entity(
                    str(case["case_id"]),
                    case_hash,
                    int(case.get("synthetic_for_competition") is True),
                    _json(case),
                )
                row = self.connection.execute(
                    "SELECT case_id,case_hash,synthetic,payload_json FROM cases "
                    "WHERE case_id=? AND case_hash=?",
                    (case["case_id"], case_hash),
                ).fetchone()
                if row is None or dict(row) != expected:
                    return False
            for run in (replay.before, replay.after):
                expected = self._run_entity(
                    run.run_id,
                    run.case_id,
                    str(run.overall_status),
                    run.ruleset_version,
                    _json(run.to_dict()),
                )
                row = self.connection.execute(
                    "SELECT run_id,case_id,status,ruleset_version,payload_json "
                    "FROM runs WHERE run_id=?",
                    (run.run_id,),
                ).fetchone()
                if row is None or dict(row) != expected:
                    return False
            expected_approval_entities: dict[tuple[Any, ...], dict[str, Any]] = {}
            admission_payload = strict_json_loads(entity["payload_json"])
            is_native = (
                admission_payload.get("contract_version")
                in {
                    A05_REPLAY_ADMISSION_CONTRACT_VERSION,
                    A06_REPLAY_ADMISSION_CONTRACT_VERSION,
                    A08_REPLAY_ADMISSION_CONTRACT_VERSION,
                }
            )
            if not is_native:
                canonical_resolution = self._canonical_resolution_value(resolution)
                for approval in canonical_resolution["approvals"]:
                    payload = self._approval_payload_for_store(
                        canonical_resolution,
                        approval,
                        {
                            key: subject[key]
                            for key in (
                                "replacement_set_id",
                                "artifact_set_hash",
                                "reference_contract_version",
                                "controlled_reference_set_hash",
                                "controlled_reference_source_set_hash",
                                "artifact_contract_version",
                                "case_schema_version",
                                "parser_contract_version",
                                "mapping_contract_version",
                                "security_root_policy_version",
                                "touched_document_artifacts",
                            )
                        },
                        subject["validation_policy"],
                    )
                    key = tuple(
                        payload[field]
                        for field in (
                            "resolution_id",
                            "case_id",
                            "event_id",
                            "event_revision",
                            "approved_case_hash",
                            "role",
                        )
                    )
                    expected_approval_entities[key] = self._approval_entity(
                        payload["resolution_id"],
                        payload["case_id"],
                        payload["event_id"],
                        payload["event_revision"],
                        payload["approved_case_hash"],
                        payload["approved_patch_hash"],
                        payload["role"],
                        payload["decision"],
                        _json(payload),
                    )
            rows = self.connection.execute(
                """SELECT resolution_id,case_id,event_id,event_revision,
                          approved_case_hash,approved_patch_hash,role,decision,payload_json
                   FROM approvals WHERE resolution_id=? AND case_id=?
                     AND approved_case_hash=?""",
                (
                    replay.resolution_id,
                    replay.before.case_id,
                    replay.before.case_hash,
                ),
            ).fetchall()
            actual_approval_entities = {
                (
                    row["resolution_id"],
                    row["case_id"],
                    row["event_id"],
                    row["event_revision"],
                    row["approved_case_hash"],
                    row["role"],
                ): dict(row)
                for row in rows
            }
            if actual_approval_entities != expected_approval_entities:
                return False
            matching_baselines: list[dict[str, Any]] = []
            for row in self.connection.execute(
                "SELECT baseline_id,case_id,source_run_id,payload_json FROM baselines"
            ):
                payload = strict_json_loads(row["payload_json"])
                if (
                    isinstance(payload, dict)
                    and payload.get("resolution_id") == replay.resolution_id
                    and payload.get("artifact_set_hash") == replay.artifact_set_hash
                    and payload.get("approved_case_hash") == replay.before.case_hash
                ):
                    matching_baselines.append(dict(row))
            if replay.baseline is None:
                return not matching_baselines
            expected_baseline = self._baseline_entity(
                replay.baseline.baseline_id,
                replay.baseline.case_id,
                replay.baseline.source_run_id,
                _json(replay.baseline.to_dict()),
            )
            return matching_baselines == [expected_baseline]
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _replay_validation_run_links_match(
        self,
        replay: ReplayResult,
        source_context: _ValidationEvidenceContext,
        resolved_context: _ValidationEvidenceContext,
    ) -> bool:
        expected = {
            replay.before.run_id: source_context.evidence_set_hash,
            replay.after.run_id: resolved_context.evidence_set_hash,
        }
        rows = self.connection.execute(
            "SELECT run_id,evidence_set_hash FROM run_validation_sets "
            "WHERE run_id IN (?,?)",
            (replay.before.run_id, replay.after.run_id),
        ).fetchall()
        return (
            len(rows) == len(expected)
            and {row["run_id"]: row["evidence_set_hash"] for row in rows}
            == expected
        )

    def _save_replay_admission_entity(
        self, admission_entity: dict[str, Any]
    ) -> bool:
        replay_admission_hash = admission_entity["replay_admission_hash"]
        inserted = self.connection.execute(
            """INSERT OR IGNORE INTO replay_admissions
               (replay_admission_hash,resolution_id,artifact_set_hash,
                approved_case_hash,resolution_json,payload_json)
               VALUES (?,?,?,?,?,?)""",
            tuple(
                admission_entity[field]
                for field in (
                    "replay_admission_hash",
                    "resolution_id",
                    "artifact_set_hash",
                    "approved_case_hash",
                    "resolution_json",
                    "payload_json",
                )
            ),
        ).rowcount
        if inserted:
            self._append_audit(
                "replay_admission",
                replay_admission_hash,
                "REPLAY_ADMISSION_RECORDED",
                {
                    "primary_key": {
                        "replay_admission_hash": replay_admission_hash
                    },
                    "entity_fingerprint": _fingerprint(admission_entity),
                },
            )
        else:
            row = self.connection.execute(
                """SELECT replay_admission_hash,resolution_id,artifact_set_hash,
                          approved_case_hash,resolution_json,payload_json
                   FROM replay_admissions WHERE replay_admission_hash=?""",
                (replay_admission_hash,),
            ).fetchone()
            if row is None or dict(row) != admission_entity:
                raise StoreIntegrityError(
                    "replay admission hash conflicts with different stored content"
                )
        return bool(inserted)

    def _save_replay_ledger_entity(self, entity: dict[str, Any]) -> bool:
        inserted = self.connection.execute(
            """INSERT OR IGNORE INTO replay_ledger
               (replay_ledger_hash,replay_admission_hash,consumption_hash,resolution_id,
                artifact_set_hash,approved_case_hash,after_run_id,payload_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            tuple(
                entity[field]
                for field in (
                    "replay_ledger_hash",
                    "replay_admission_hash",
                    "consumption_hash",
                    "resolution_id",
                    "artifact_set_hash",
                    "approved_case_hash",
                    "after_run_id",
                    "payload_json",
                )
            ),
        ).rowcount
        if inserted:
            self._append_audit(
                "replay_ledger",
                entity["replay_ledger_hash"],
                "REPLAY_LEDGER_RECORDED",
                {
                    "primary_key": {
                        "replay_ledger_hash": entity["replay_ledger_hash"]
                    },
                    "entity_fingerprint": _fingerprint(entity),
                },
            )
        else:
            row = self.connection.execute(
                "SELECT * FROM replay_ledger WHERE replay_ledger_hash=?",
                (entity["replay_ledger_hash"],),
            ).fetchone()
            if row is None or dict(row) != entity:
                raise StoreIntegrityError(
                    "replay ledger hash conflicts with different stored content"
                )
        return bool(inserted)

    def save_native_replay(
        self,
        result: StatelessApprovalReplayResult,
        resolution: dict[str, Any],
        *,
        approval_subject: dict[str, Any],
        approval_assertions: list[dict[str, Any]] | tuple[dict[str, Any], ...],
        authorization_bundle: AuthorizationRecordBundle,
        authorization_trust_bundle: AuthorizationTrustSnapshotBundle,
        artifact_bundle: RevisionArtifactBundle,
        reference_bundle: ControlledReferenceBundle,
        source_validation_bundle: ValidationEvidenceBundle,
        resolved_validation_bundle: ValidationEvidenceBundle,
    ) -> None:
        """Persist one A06 replay without weakening the A02--A05 trust stage.

        The approval and issuance-trust inputs are rebuilt from raw bytes here.  A
        private legacy projection is used only to reproduce the locked A04
        ReplayResult; the A05 subject/assertions and their consumption are
        persisted separately and atomically by :meth:`save_replay`.
        """

        if type(result) is not StatelessApprovalReplayResult:
            raise StoreIntegrityError(
                "native replay persistence requires StatelessApprovalReplayResult"
            )
        if type(authorization_bundle) is not AuthorizationRecordBundle:
            raise StoreIntegrityError(
                "native replay persistence requires exact authorization raw bytes"
            )
        if type(authorization_trust_bundle) is not AuthorizationTrustSnapshotBundle:
            raise StoreIntegrityError(
                "native replay persistence requires exact authorization trust bytes"
            )
        replay = result.replay
        row = self.connection.execute(
            "SELECT payload_json FROM cases WHERE case_id=? AND case_hash=?",
            (replay.before.case_id, replay.before.case_hash),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError(
                "exact pre-resolution case must be registered before saving its replay"
            )
        try:
            approved_case = strict_json_loads(row["payload_json"])
            native_resolution = validate_native_resolution(resolution)
            subject = validate_approval_subject(approval_subject)
            artifact_context = prepare_artifact_context(
                artifact_bundle,
                approved_case,
                native_resolution["operations"],
                reference_bundle=reference_bundle,
            )
            resolved_case = _resolved_case_from_context(
                approved_case,
                native_resolution,
                native_resolution["operations"],
                artifact_context,
            )
            source_validation_identity = _prepare_validation_case_identity(
                approved_case
            )
            resolved_validation_identity = _prepare_validation_case_identity(
                resolved_case
            )
            legacy_subject = _subject_from_context(
                native_resolution,
                approved_case,
                resolved_case,
                artifact_context,
                source_validation_identity,
                resolved_validation_identity,
            )
            expected_subject = _native_subject_from_legacy_projection(
                native_resolution,
                legacy_subject,
                execution_nonce=subject["execution_nonce"],
            )
            validate_approval_subject(subject, expected=expected_subject)
            authenticity_context = prepare_authorization_authenticity_context(
                authorization_bundle,
                authorization_trust_bundle,
            )
            if authenticity_context.state != AUTHORIZATION_AUTHENTICITY_PASS:
                raise AuthorizationAuthenticityError(
                    "authorization authenticity is not PASS: "
                    f"{authenticity_context.state}"
                )
            authorization_context = authenticity_context.record_context
            validation = validate_approval_assertions(
                subject, approval_assertions, authorization_context
            )
            require_authenticated_assertion_records(
                approval_assertions,
                authenticity_context,
            )
        except (
            ApprovalGateError,
            RevisionArtifactError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise StoreIntegrityError(
                f"native approval cannot be rebuilt from raw bytes: {error}"
            ) from error
        assertion_set_hash = self._assertion_set_hash(
            validation.assertion_hashes
        )
        expected_authenticity_binding_hash = (
            authorization_authenticity_binding_hash(
                approval_subject_hash=validation.approval_subject_hash,
                approval_assertion_set_hash=assertion_set_hash,
                authorization_authenticity_context_hash=(
                    authenticity_context.authorization_authenticity_context_hash
                ),
                after_case_hash=replay.after.case_hash,
                after_run_hash=canonical_hash(replay.after.to_dict()),
            )
        )
        sidecar = result.replay_approval
        if (
            sidecar.approval_subject_hash != validation.approval_subject_hash
            or sidecar.assertion_hashes != validation.assertion_hashes
            or sidecar.approved_roles != validation.approved_roles
            or sidecar.authorization_record_set_hash
            != validation.authorization_record_set_hash
            or sidecar.authorization_record_set_contract_version
            != validation.authorization_record_set_contract_version
            or sidecar.authorization_authenticity_state
            != AUTHORIZATION_AUTHENTICITY_PASS
            or sidecar.authorization_authenticity_context_hash
            != authenticity_context.authorization_authenticity_context_hash
            or sidecar.authorization_authenticity_binding_hash
            != expected_authenticity_binding_hash
            or sidecar.authorization_trust_snapshot_hash
            != authenticity_context.trust_snapshot_hash
            or sidecar.authorization_trust_snapshot_contract_version
            != authenticity_context.trust_snapshot_contract_version
            or sidecar.authorization_trust_policy_hash
            != authenticity_context.trust_policy_hash
            or sidecar.authorization_trust_policy_version
            != authenticity_context.trust_policy_version
            or sidecar.execution_nonce != subject["execution_nonce"]
            or sidecar.use_policy != subject["use_policy"]
        ):
            raise StoreIntegrityError(
                "native replay sidecar differs from the rebuilt approval claims"
            )
        consumed = self.connection.execute(
            "SELECT c.replay_admission_hash,a.payload_json "
            "FROM approval_consumptions c JOIN replay_admissions a "
            "ON a.replay_admission_hash=c.replay_admission_hash "
            "WHERE c.approval_subject_hash=?",
            (validation.approval_subject_hash,),
        ).fetchone()
        if consumed is not None:
            admitted = strict_json_loads(consumed["payload_json"])
            if (
                admitted.get("before_run", {}).get("run_id")
                != replay.before.run_id
                or admitted.get("after_run", {}).get("run_id")
                != replay.after.run_id
                or admitted.get("artifact_set_hash")
                != replay.artifact_set_hash
                or admitted.get("validation_evidence_pair_hash")
                != replay.validation_evidence_pair_hash
            ):
                raise StoreIntegrityError(
                    "SINGLE_REPLAY approval subject is already consumed by a "
                    "different replay admission"
                )

        legacy_patch_hash = canonical_hash(legacy_subject)
        adapted_resolution = strict_json_loads(_json(native_resolution))
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
        native = _NativeApprovalPersistence(
            subject=subject,
            assertions=tuple(
                validate_approval_assertion_shape(item)
                for item in approval_assertions
            ),
            authorization_bundle=authorization_bundle,
            authorization_context=authorization_context,
            authorization_trust_bundle=authorization_trust_bundle,
            authenticity_context=authenticity_context,
            a06_refs=tuple(
                sorted(
                    {
                        "authorization_record_set_hash": (
                            authorization_context.record_set_hash
                        ),
                        "authorization_record_set_contract_version": (
                            authorization_context.contract_version
                        ),
                        "authorization_authenticity_state": (
                            authenticity_context.state
                        ),
                        "authorization_authenticity_context_hash": (
                            authenticity_context.authorization_authenticity_context_hash
                        ),
                        "authorization_authenticity_binding_hash": (
                            expected_authenticity_binding_hash
                        ),
                        "authorization_trust_snapshot_hash": (
                            authenticity_context.trust_snapshot_hash
                        ),
                        "authorization_trust_snapshot_contract_version": (
                            authenticity_context.trust_snapshot_contract_version
                        ),
                        "authorization_trust_policy_hash": (
                            authenticity_context.trust_policy_hash
                        ),
                        "authorization_trust_policy_version": (
                            authenticity_context.trust_policy_version
                        ),
                    }.items()
                )
            ),
        )
        self._save_native_replay_transaction(
            replay,
            adapted_resolution,
            artifact_bundle=artifact_bundle,
            reference_bundle=reference_bundle,
            source_validation_bundle=source_validation_bundle,
            resolved_validation_bundle=resolved_validation_bundle,
            _native_approval=native,
            _artifact_context=artifact_context,
            _source_validation_identity=source_validation_identity,
            _resolved_validation_identity=resolved_validation_identity,
            _store_seal=_NATIVE_STORE_SEAL,
        )

    def save_native_replay_from_bundles(
        self,
        root_source_bundle: CaseSourceBundle,
        prior_derivations: tuple[Any, ...],
        current_replay: NativeReplayDerivationBundle,
    ) -> StatelessApprovalReplayResult:
        """Rebuild and atomically persist one A08 replay from raw inputs only."""

        self.require_a08_schema()
        if type(root_source_bundle) is not CaseSourceBundle:
            raise StoreIntegrityError(
                "A08 replay requires an exact root CaseSourceBundle"
            )
        if type(prior_derivations) is not tuple:
            raise StoreIntegrityError(
                "A08 replay requires an exact ordered derivation tuple"
            )
        if type(current_replay) is not NativeReplayDerivationBundle:
            raise StoreIntegrityError(
                "A08 replay requires exact current native raw material"
            )
        try:
            public_result = replay_with_source_assurance(
                root_source_bundle,
                prior_derivations,
                current_replay,
            )
            prior_closure = self._rebuild_a08_derivation_closure(
                root_source_bundle,
                prior_derivations,
            )
            before_context = prior_closure.terminal_context
            after_context, rebuilt_result = _replay_one_source_derivation(
                before_context,
                current_replay,
            )
            current_step = _A08NativeStepPersistence(
                before_context,
                after_context,
                current_replay,
                rebuilt_result,
            )
            if rebuilt_result.to_dict() != public_result.to_dict():
                raise StoreIntegrityError(
                    "A08 public replay differs from the independent raw rebuild"
                )
            full_derivations = (*prior_derivations, current_replay)
            native_steps = (*prior_closure.native_steps, current_step)
            closure = _A08SourceReplayPersistence(
                root_bundle=root_source_bundle,
                prior_derivations=prior_derivations,
                current_replay=current_replay,
                before_context=before_context,
                after_context=after_context,
                native_steps=native_steps,
                reference_bundles=self._a08_reference_bundles_for_closure(
                    root_source_bundle,
                    full_derivations,
                    prior_closure.root_context,
                    native_steps,
                ),
            )

            resolution = _native_resolution_from_bytes(
                current_replay.native_resolution_bytes
            )
            subject_value = strict_json_loads(
                current_replay.approval_subject_bytes.decode("utf-8")
            )
            if type(subject_value) is not dict:
                raise TypeError("A08 approval subject must be an exact object")
            subject = validate_approval_subject(subject_value)
            assertions = _approval_assertions_from_bytes(
                current_replay.approval_assertions_bytes
            )
            authenticity_context = prepare_authorization_authenticity_context(
                current_replay.authorization_bundle,
                current_replay.authorization_trust_bundle,
            )
            if authenticity_context.state != AUTHORIZATION_AUTHENTICITY_PASS:
                raise AuthorizationAuthenticityError(
                    "A08 authorization authenticity is not PASS"
                )
            validation = validate_approval_assertions(
                subject,
                assertions,
                authenticity_context.record_context,
            )
            require_authenticated_assertion_records(
                assertions,
                authenticity_context,
            )
            artifact_context = prepare_artifact_context(
                current_replay.artifact_bundle,
                before_context.case(),
                resolution["operations"],
                _baseline_reference_context=before_context._reference_context,
            )
            expected_subject, legacy_subject = _source_subject_from_context(
                resolution,
                before_context,
                artifact_context,
                execution_nonce=subject["execution_nonce"],
            )
            validate_approval_subject(subject, expected=expected_subject)
            if after_context.case() != _resolved_case_from_context(
                before_context.case(),
                resolution,
                resolution["operations"],
                artifact_context,
            ):
                raise StoreIntegrityError(
                    "A08 after source context differs from replacement artifacts"
                )
            assertion_set_hash = self._assertion_set_hash(
                validation.assertion_hashes
            )
            replay = public_result.replay
            stateless_binding_hash = authorization_authenticity_binding_hash(
                approval_subject_hash=validation.approval_subject_hash,
                approval_assertion_set_hash=assertion_set_hash,
                authorization_authenticity_context_hash=(
                    authenticity_context.authorization_authenticity_context_hash
                ),
                after_case_hash=replay.after.case_hash,
                after_run_hash=canonical_hash(replay.after.to_dict()),
            )
            sidecar = public_result.replay_approval
            if (
                sidecar.approval_subject_hash
                != validation.approval_subject_hash
                or sidecar.assertion_hashes != validation.assertion_hashes
                or sidecar.approved_roles != validation.approved_roles
                or sidecar.authorization_record_set_hash
                != authenticity_context.authorization_record_set_hash
                or sidecar.authorization_authenticity_state
                != AUTHORIZATION_AUTHENTICITY_PASS
                or sidecar.authorization_authenticity_context_hash
                != authenticity_context.authorization_authenticity_context_hash
                or sidecar.authorization_authenticity_binding_hash
                != stateless_binding_hash
                or sidecar.authorization_trust_snapshot_hash
                != authenticity_context.trust_snapshot_hash
            ):
                raise StoreIntegrityError(
                    "A08 replay sidecar differs from rebuilt raw authorization facts"
                )
            a06_refs = {
                "authorization_record_set_hash": (
                    authenticity_context.authorization_record_set_hash
                ),
                "authorization_record_set_contract_version": (
                    authenticity_context.authorization_record_set_contract_version
                ),
                "authorization_authenticity_state": authenticity_context.state,
                "authorization_authenticity_context_hash": (
                    authenticity_context.authorization_authenticity_context_hash
                ),
                "authorization_authenticity_binding_hash": stateless_binding_hash,
                "authorization_trust_snapshot_hash": (
                    authenticity_context.trust_snapshot_hash
                ),
                "authorization_trust_snapshot_contract_version": (
                    authenticity_context.trust_snapshot_contract_version
                ),
                "authorization_trust_policy_hash": (
                    authenticity_context.trust_policy_hash
                ),
                "authorization_trust_policy_version": (
                    authenticity_context.trust_policy_version
                ),
            }
            native = _NativeApprovalPersistence(
                subject=subject,
                assertions=tuple(
                    validate_approval_assertion_shape(item)
                    for item in assertions
                ),
                authorization_bundle=current_replay.authorization_bundle,
                authorization_context=authenticity_context.record_context,
                authorization_trust_bundle=(
                    current_replay.authorization_trust_bundle
                ),
                authenticity_context=authenticity_context,
                a06_refs=tuple(sorted(a06_refs.items())),
            )
            legacy_patch_hash = canonical_hash(legacy_subject)
            adapted_resolution = {
                **resolution,
                "approvals": [
                    {
                        "role": role,
                        "decision": "APPROVED",
                        "case_id": legacy_subject["case_id"],
                        "event_id": legacy_subject["event_id"],
                        "event_revision": legacy_subject["event_revision"],
                        "approved_case_hash": legacy_subject[
                            "approved_case_hash"
                        ],
                        "approved_patch_hash": legacy_patch_hash,
                    }
                    for role in validation.approved_roles
                ],
            }
        except StoreIntegrityError:
            raise
        except (
            ApprovalGateError,
            AuthorizationAuthenticityError,
            CaseSourceError,
            RevisionArtifactError,
            UnicodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise StoreIntegrityError(
                f"A08 replay raw closure cannot be rebuilt: {error}"
            ) from error

        self._save_native_replay_transaction(
            replay,
            adapted_resolution,
            artifact_bundle=current_replay.artifact_bundle,
            source_validation_bundle=current_replay.source_validation_bundle,
            resolved_validation_bundle=current_replay.resolved_validation_bundle,
            _native_approval=native,
            _artifact_context=artifact_context,
            _source_validation_identity=_prepare_validation_case_identity(
                before_context.case()
            ),
            _resolved_validation_identity=_prepare_validation_case_identity(
                after_context.case()
            ),
            _a08_source=closure,
            _store_seal=_NATIVE_STORE_SEAL,
        )
        return public_result

    def save_replay(
        self,
        replay: ReplayResult,
        resolution: dict[str, Any],
        *,
        artifact_bundle: RevisionArtifactBundle | None = None,
        reference_bundle: ControlledReferenceBundle | None = None,
        source_validation_bundle: ValidationEvidenceBundle | None = None,
        resolved_validation_bundle: ValidationEvidenceBundle | None = None,
    ) -> None:
        """Reject the retired approval surface before any persistence write."""

        raise StoreIntegrityError(
            "LEGACY_APPROVAL_UNATTESTED: use save_native_replay with exact "
            "ApprovalSubject, ApprovalAssertions, and authorization raw bytes"
        )

    def _stage_a08_native_step_raw(
        self,
        step: _A08NativeStepPersistence,
    ) -> None:
        """Stage all raw facts needed to re-execute one stored native lineage."""

        if (
            type(step) is not _A08NativeStepPersistence
            or not _is_sealed_case_source_context(step.before_context)
            or not _is_sealed_case_source_context(step.after_context)
            or type(step.bundle) is not NativeReplayDerivationBundle
            or type(step.result) is not StatelessApprovalReplayResult
        ):
            raise StoreIntegrityError(
                "A08 native lineage staging requires its private rebuilt step"
            )
        resolution = _native_resolution_from_bytes(
            step.bundle.native_resolution_bytes
        )
        artifact_context = prepare_artifact_context(
            step.bundle.artifact_bundle,
            step.before_context.case(),
            resolution["operations"],
            _baseline_reference_context=step.before_context._reference_context,
        )
        if (
            artifact_context.reference_context is None
            or artifact_context.reference_context.reference_set_hash
            != step.after_context._reference_context.reference_set_hash
            or step.after_context.case()
            != _resolved_case_from_context(
                step.before_context.case(),
                resolution,
                resolution["operations"],
                artifact_context,
            )
        ):
            raise StoreIntegrityError(
                "A08 native lineage artifacts differ from rebuilt source contexts"
            )
        created_artifact = self._stage_artifact_bundle(
            artifact_context.artifact_set_hash,
            step.bundle.artifact_bundle,
            step.before_context._reference_context,
            step.after_context._reference_context.reference_set_hash,
        )
        if created_artifact:
            artifact_entity = self._artifact_set_entity(
                artifact_context.artifact_set_hash
            )
            if artifact_entity is None:
                raise StoreIntegrityError(
                    "A08 native lineage artifact set disappeared"
                )
            self._append_audit(
                "artifact_set",
                artifact_context.artifact_set_hash,
                "ARTIFACT_SET_RECORDED",
                {
                    "primary_key": {
                        "artifact_set_hash": artifact_context.artifact_set_hash
                    },
                    "entity_fingerprint": _fingerprint(artifact_entity),
                },
            )
        source_validation = _prepare_validation_evidence_context(
            step.bundle.source_validation_bundle,
            step.before_context.case(),
            expected_phase="SOURCE",
        )
        resolved_validation = _prepare_validation_evidence_context(
            step.bundle.resolved_validation_bundle,
            step.after_context.case(),
            expected_phase="RESOLVED",
        )
        for context, bundle in (
            (source_validation, step.bundle.source_validation_bundle),
            (resolved_validation, step.bundle.resolved_validation_bundle),
        ):
            if self._stage_validation_evidence_bundle(context, bundle):
                entity = self._validation_evidence_set_entity(
                    context.evidence_set_hash
                )
                if entity is None:
                    raise StoreIntegrityError(
                        "A08 native lineage validation set disappeared"
                    )
                self._append_audit(
                    "validation_evidence_set",
                    context.evidence_set_hash,
                    "VALIDATION_EVIDENCE_SET_RECORDED",
                    {
                        "primary_key": {
                            "evidence_set_hash": context.evidence_set_hash
                        },
                        "entity_fingerprint": _fingerprint(entity),
                    },
                )
        authenticity = prepare_authorization_authenticity_context(
            step.bundle.authorization_bundle,
            step.bundle.authorization_trust_bundle,
        )
        if authenticity.state != AUTHORIZATION_AUTHENTICITY_PASS:
            raise StoreIntegrityError(
                "A08 native lineage authorization is not PASS"
            )
        subject_value = strict_json_loads(
            step.bundle.approval_subject_bytes.decode("utf-8")
        )
        if type(subject_value) is not dict:
            raise StoreIntegrityError(
                "A08 native lineage approval subject is not an object"
            )
        subject = validate_approval_subject(subject_value)
        assertions = _approval_assertions_from_bytes(
            step.bundle.approval_assertions_bytes
        )
        validation = validate_approval_assertions(
            subject,
            assertions,
            authenticity.record_context,
        )
        require_authenticated_assertion_records(assertions, authenticity)
        lineage_material = step.after_context.lineages[-1].operation_material()
        if (
            approval_subject_hash(subject)
            != lineage_material["approval_subject_hash"]
            or self._assertion_set_hash(validation.assertion_hashes)
            != lineage_material["approval_assertion_set_hash"]
            or authenticity.authorization_authenticity_context_hash
            != lineage_material["authorization_authenticity_context_hash"]
        ):
            raise StoreIntegrityError(
                "A08 native lineage raw authorization differs from operation material"
            )
        self._stage_authorization_record_bundle(
            authenticity.record_context,
            step.bundle.authorization_bundle,
        )
        self._stage_authorization_trust_snapshot_bundle(
            authenticity,
            step.bundle.authorization_trust_bundle,
        )
        self._save_approval_subject_entity(
            self._approval_subject_entity(subject)
        )
        for entity in self._approval_assertion_entities(
            tuple(validate_approval_assertion_shape(item) for item in assertions),
            approval_subject_hash_value=approval_subject_hash(subject),
            authorization_record_set_hash=(
                authenticity.authorization_record_set_hash
            ),
        ):
            self._save_approval_assertion_entity(entity)

    def _save_native_replay_transaction(
        self,
        replay: ReplayResult,
        resolution: dict[str, Any],
        *,
        artifact_bundle: RevisionArtifactBundle | None = None,
        reference_bundle: ControlledReferenceBundle | None = None,
        source_validation_bundle: ValidationEvidenceBundle | None = None,
        resolved_validation_bundle: ValidationEvidenceBundle | None = None,
        _native_approval: _NativeApprovalPersistence,
        _artifact_context: ArtifactContext,
        _source_validation_identity: _ValidationCaseIdentity,
        _resolved_validation_identity: _ValidationCaseIdentity,
        _a08_source: _A08SourceReplayPersistence | None = None,
        _store_seal: object,
    ) -> None:
        if (
            _store_seal is not _NATIVE_STORE_SEAL
            or type(_native_approval) is not _NativeApprovalPersistence
        ):
            raise StoreIntegrityError(
                "native replay transaction requires the private Store seal"
            )
        if (
            type(_native_approval.authorization_trust_bundle)
            is not AuthorizationTrustSnapshotBundle
            or type(_native_approval.authenticity_context)
            is not AuthorizationAuthenticityContext
            or not _native_approval.authenticity_context.is_sealed()
            or _native_approval.authenticity_context.state
            != AUTHORIZATION_AUTHENTICITY_PASS
        ):
            raise StoreIntegrityError(
                "native replay transaction requires exact sealed A06 trust inputs"
            )
        if (
            type(_artifact_context) is not ArtifactContext
            or type(_source_validation_identity) is not _ValidationCaseIdentity
            or not _source_validation_identity.is_sealed()
            or type(_resolved_validation_identity) is not _ValidationCaseIdentity
            or not _resolved_validation_identity.is_sealed()
        ):
            raise StoreIntegrityError(
                "native replay transaction requires its exact call-local contexts"
            )
        if type(replay) is not ReplayResult:
            raise StoreIntegrityError("only an actual ReplayResult can be saved")
        if type(artifact_bundle) is not RevisionArtifactBundle:
            raise StoreIntegrityError("actual replay persistence requires captured artifact bytes")
        source_mode = type(_a08_source) is _A08SourceReplayPersistence
        if _a08_source is not None and not source_mode:
            raise StoreIntegrityError(
                "A08 replay transaction requires its private source closure"
            )
        if not source_mode and type(reference_bundle) is not ControlledReferenceBundle:
            raise StoreIntegrityError(
                "actual replay persistence requires controlled-reference raw bytes"
            )
        if (
            type(source_validation_bundle) is not ValidationEvidenceBundle
            or type(resolved_validation_bundle) is not ValidationEvidenceBundle
        ):
            raise StoreIntegrityError(
                "actual replay persistence requires exact SOURCE and RESOLVED "
                "validation raw bundles"
            )
        if source_mode:
            assert _a08_source is not None
            if (
                not _is_sealed_case_source_context(
                    _a08_source.before_context
                )
                or not _is_sealed_case_source_context(
                    _a08_source.after_context
                )
            ):
                raise StoreIntegrityError(
                    "A08 replay transaction source closure is not sealed"
                )
            supplied_reference_context = (
                _a08_source.before_context._reference_context
            )
        else:
            try:
                supplied_reference_context = _prepare_controlled_reference_context(
                    reference_bundle
                )
            except (TypeError, ValueError) as error:
                raise StoreIntegrityError(
                    "controlled-reference bundle cannot be rebuilt"
                ) from error
        resolution = self._canonical_resolution_value(resolution)
        resolution_id = str(resolution.get("resolution_id", ""))
        if not resolution_id or replay.resolution_id != resolution_id:
            raise StoreIntegrityError("replay and resolution_id do not match")
        if replay.baseline and replay.baseline.resolution_id != resolution_id:
            raise StoreIntegrityError("baseline and resolution_id do not match")

        if source_mode:
            assert _a08_source is not None
            approved_case = _a08_source.before_context.case()
            if (
                canonical_hash(approved_case) != replay.before.case_hash
                or _a08_source.after_context.case() != _resolved_case_from_context(
                    approved_case,
                    {key: resolution[key] for key in NATIVE_RESOLUTION_KEYS},
                    resolution["operations"],
                    _artifact_context,
                )
            ):
                raise StoreIntegrityError(
                    "A08 source closure differs from the rebuilt replay cases"
                )
        else:
            case_row = self.connection.execute(
                "SELECT payload_json FROM cases WHERE case_id=? AND case_hash=?",
                (replay.before.case_id, replay.before.case_hash),
            ).fetchone()
            if case_row is None:
                raise StoreIntegrityError(
                    "exact pre-resolution case must be registered before saving its replay"
                )
            try:
                approved_case = json.loads(case_row["payload_json"])
            except json.JSONDecodeError as error:
                raise StoreIntegrityError("registered pre-resolution case payload is invalid") from error
        try:
            source_validation_identity = _prepare_validation_case_identity(
                approved_case
            )
            source_validation_context = _prepare_validation_evidence_context(
                source_validation_bundle,
                approved_case,
                expected_phase="SOURCE",
                _case_identity=source_validation_identity,
            )
        except (TypeError, ValueError) as error:
            raise StoreIntegrityError(
                "source validation bytes cannot be rebuilt"
            ) from error
        has_audit = self.connection.execute(
            "SELECT 1 FROM audit_events LIMIT 1"
        ).fetchone() is not None
        if has_audit and not self.verify_audit_chain():
            raise StoreIntegrityError(
                "replay persistence requires an intact semantic and audit store"
            )
        if not source_mode:
            self._assert_replay_runs_have_no_standalone_reference_links(replay)
        with self._prevalidated_replay_transaction() as prevalidated_transaction_seal:
            if not source_mode:
                self._assert_replay_runs_have_no_standalone_reference_links(replay)
            if source_mode:
                assert _a08_source is not None
                root_context = _prepare_case_source_context(
                    _a08_source.root_bundle
                )
                self._stage_case_source_context(root_context)
                for effective_reference_bundle in (
                    _a08_source.reference_bundles
                ):
                    self._stage_a08_reference_bundle(
                        effective_reference_bundle
                    )
                self._save_case(approved_case)
                for prior_step in _a08_source.native_steps[:-1]:
                    self._stage_a08_native_step_raw(prior_step)
                created_reference_set = False
                stored_reference_bundle = None
            else:
                created_reference_set = self._stage_controlled_reference_bundle(
                    supplied_reference_context.reference_set_hash,
                    reference_bundle,
                )
                stored_reference_bundle = self._load_controlled_reference_bundle(
                    supplied_reference_context.reference_set_hash
                )
            created_artifact_set = self._stage_artifact_bundle(
                replay.artifact_set_hash,
                artifact_bundle,
                supplied_reference_context,
                replay.controlled_reference_set_hash,
            )
            stored_bundle = self._load_artifact_bundle(replay.artifact_set_hash)
            context = _artifact_context
            if not self._artifact_snapshot_matches_context(
                context, stored_bundle
            ):
                raise StoreIntegrityError(
                    "stored artifact bytes differ from the call-local context"
                )
            if context.artifact_set_hash != replay.artifact_set_hash:
                raise StoreIntegrityError(
                    "stored artifact context differs from the replay artifact identity"
                )
            if (
                context.reference_context is None
                or context.reference_context.reference_set_hash
                != replay.controlled_reference_set_hash
            ):
                raise StoreIntegrityError(
                    "stored controlled references differ from replay identity"
                )
            if source_mode:
                assert _a08_source is not None
                resolved_case = _a08_source.after_context.case()
                _expected_source_subject, subject = _source_subject_from_context(
                    {
                        key: resolution[key]
                        for key in NATIVE_RESOLUTION_KEYS
                    },
                    _a08_source.before_context,
                    context,
                    execution_nonce=_native_approval.subject[
                        "execution_nonce"
                    ],
                )
                patch_hash = canonical_hash(subject)
                resolved_identity = _resolved_validation_identity
            else:
                attested = _attest_approved_resolution(
                    approved_case,
                    resolution,
                    artifact_bundle=stored_bundle,
                    reference_bundle=stored_reference_bundle,
                    _artifact_context=context,
                    _source_validation_identity=_source_validation_identity,
                    _resolved_validation_identity=_resolved_validation_identity,
                )
                resolved_case = attested.resolved_case()
                subject = attested.subject()
                patch_hash = attested.patch_hash
                resolved_identity = attested.resolved_validation_identity
            try:
                resolved_validation_context = _prepare_validation_evidence_context(
                    resolved_validation_bundle,
                    resolved_case,
                    expected_phase="RESOLVED",
                    _case_identity=resolved_identity,
                )
            except (TypeError, ValueError) as error:
                raise StoreIntegrityError(
                    "resolved validation bytes cannot be rebuilt"
                ) from error
            created_source_validation_set = self._stage_validation_evidence_bundle(
                source_validation_context,
                source_validation_bundle,
            )
            created_resolved_validation_set = self._stage_validation_evidence_bundle(
                resolved_validation_context,
                resolved_validation_bundle,
            )
            expected_replay = (
                replay
                if source_mode
                else _replay_attested_resolution(
                    approved_case,
                    resolution,
                    attested,
                    source_validation_context=source_validation_context,
                    resolved_validation_context=resolved_validation_context,
                )
            )
            expected_replay_value = expected_replay.to_dict()
            if expected_replay_value != replay.to_dict():
                raise StoreIntegrityError(
                    "replay or baseline metadata does not match the exact recomputed approved workflow"
                )
            save_prevalidated_run = None
            if not source_mode:
                prevalidated_runs = {
                    "before": (
                        expected_replay.before,
                        attested.before_reference_context,
                        source_validation_context,
                        _json(expected_replay_value["before"]),
                    ),
                    "after": (
                        expected_replay.after,
                        context.reference_context,
                        resolved_validation_context,
                        _json(expected_replay_value["after"]),
                    ),
                }
                unconsumed_prevalidated_runs = {"before", "after"}

                def save_prevalidated_run(position: str) -> bool:
                    """Persist one exact run through this transaction's closure only."""

                    if (
                        not self.connection.in_transaction
                        or getattr(
                            self,
                            "_active_prevalidated_transaction_seal",
                            None,
                        )
                        is not prevalidated_transaction_seal
                        or position not in unconsumed_prevalidated_runs
                    ):
                        raise StoreIntegrityError(
                            "prevalidated replay run requires its active private transaction"
                        )
                    (
                        expected_result,
                        reference_context,
                        validation_context,
                        expected_payload_json,
                    ) = prevalidated_runs[position]
                    if (
                        type(expected_result) is not RunResult
                        or type(reference_context) is not _ControlledReferenceContext
                        or not reference_context.is_sealed()
                        or type(validation_context) is not _ValidationEvidenceContext
                        or not validation_context.is_sealed()
                        or expected_result.reference_set_hash
                        != reference_context.reference_set_hash
                        or expected_result.reference_contract_version
                        != reference_context.contract_version
                        or expected_result.validation_evidence_set_hash
                        != validation_context.evidence_set_hash
                        or expected_result.validation_evidence_contract_version
                        != validation_context.contract_version
                    ):
                        raise StoreIntegrityError(
                            "prevalidated replay run differs from its exact sealed context"
                        )
                    payload_json = _json(expected_result.to_dict())
                    if payload_json != expected_payload_json:
                        raise StoreIntegrityError(
                            "prevalidated replay run changed after exact comparison"
                        )
                    unconsumed_prevalidated_runs.remove(position)
                    status = str(expected_result.overall_status)
                    entity = self._run_entity(
                        expected_result.run_id,
                        expected_result.case_id,
                        status,
                        expected_result.ruleset_version,
                        payload_json,
                    )
                    inserted = self.connection.execute(
                        "INSERT OR IGNORE INTO runs(run_id, case_id, status, ruleset_version, payload_json) VALUES (?, ?, ?, ?, ?)",
                        (
                            expected_result.run_id,
                            expected_result.case_id,
                            status,
                            expected_result.ruleset_version,
                            payload_json,
                        ),
                    ).rowcount
                    if inserted:
                        self._append_audit(
                            "run",
                            expected_result.run_id,
                            "CHECK_RUN_RECORDED",
                            {
                                "primary_key": {
                                    "run_id": expected_result.run_id
                                },
                                "entity_fingerprint": _fingerprint(entity),
                            },
                        )
                    else:
                        row = self.connection.execute(
                            "SELECT run_id, case_id, status, ruleset_version, payload_json FROM runs WHERE run_id=?",
                            (expected_result.run_id,),
                        ).fetchone()
                        if row is None or _fingerprint(dict(row)) != _fingerprint(
                            entity
                        ):
                            raise StoreIntegrityError(
                                "run_id conflicts with different output; bump ruleset version or repair the store"
                            )
                    return bool(inserted)
            admission, resolution_json = self._build_replay_admission(
                expected_replay,
                resolution,
                approved_case,
                resolved_case,
                subject,
                context,
                native_approval=_native_approval,
                source_contexts=(
                    (
                        _a08_source.before_context,
                        _a08_source.after_context,
                    )
                    if source_mode and _a08_source is not None
                    else None
                ),
            )
            admission_entity = self._replay_admission_entity(
                admission, resolution_json
            )
            validation_binding_entity = self._replay_validation_binding_entity(
                expected_replay,
                admission,
                source_validation_context,
                resolved_validation_context,
            )
            native_subject_entity: dict[str, Any] | None = None
            native_assertion_entities: tuple[dict[str, Any], ...] = ()
            native_consumption_entity: dict[str, Any] | None = None
            native_baseline_binding_entity: dict[str, Any] | None = None
            native_expectation_entity: dict[str, Any] | None = None
            native_authenticity_binding_entity: dict[str, Any] | None = None
            if _native_approval is not None:
                rebuilt_authenticity = _native_approval.authenticity_context
                rebuilt_authorization = _native_approval.authorization_context
                if (
                    rebuilt_authenticity.record_context != rebuilt_authorization
                    or rebuilt_authorization.record_set_hash
                    != _native_approval.authorization_context.record_set_hash
                    or rebuilt_authenticity.state
                    != AUTHORIZATION_AUTHENTICITY_PASS
                ):
                    raise StoreIntegrityError(
                        "native authorization authenticity changed before persistence"
                    )
                a06_refs = _native_a06_refs(_native_approval)
                expected_a06_refs = {
                    "authorization_record_set_hash": (
                        rebuilt_authenticity.authorization_record_set_hash
                    ),
                    "authorization_record_set_contract_version": (
                        rebuilt_authenticity.authorization_record_set_contract_version
                    ),
                    "authorization_authenticity_state": rebuilt_authenticity.state,
                    "authorization_authenticity_context_hash": (
                        rebuilt_authenticity.authorization_authenticity_context_hash
                    ),
                    "authorization_authenticity_binding_hash": a06_refs[
                        "authorization_authenticity_binding_hash"
                    ],
                    "authorization_trust_snapshot_hash": (
                        rebuilt_authenticity.trust_snapshot_hash
                    ),
                    "authorization_trust_snapshot_contract_version": (
                        rebuilt_authenticity.trust_snapshot_contract_version
                    ),
                    "authorization_trust_policy_hash": (
                        rebuilt_authenticity.trust_policy_hash
                    ),
                    "authorization_trust_policy_version": (
                        rebuilt_authenticity.trust_policy_version
                    ),
                }
                if a06_refs != expected_a06_refs:
                    raise StoreIntegrityError(
                        "native A06 references differ from rebuilt raw trust inputs"
                    )
                self._stage_authorization_record_bundle(
                    rebuilt_authorization,
                    _native_approval.authorization_bundle,
                )
                self._stage_authorization_trust_snapshot_bundle(
                    rebuilt_authenticity,
                    _native_approval.authorization_trust_bundle,
                )
                validate_approval_assertions(
                    _native_approval.subject,
                    _native_approval.assertions,
                    rebuilt_authorization,
                )
                require_authenticated_assertion_records(
                    _native_approval.assertions,
                    rebuilt_authenticity,
                )
                native_subject_entity = self._approval_subject_entity(
                    _native_approval.subject
                )
                native_assertion_entities = self._approval_assertion_entities(
                    _native_approval.assertions,
                    approval_subject_hash_value=native_subject_entity[
                        "approval_subject_hash"
                    ],
                    authorization_record_set_hash=(
                        rebuilt_authorization.record_set_hash
                    ),
                )
                assertion_hashes = tuple(
                    item["assertion_hash"] for item in native_assertion_entities
                )
                assertion_set_hash = self._assertion_set_hash(
                    assertion_hashes
                )
                native_authenticity_binding_entity = (
                    self._replay_authorization_authenticity_binding_entity(
                        expected_replay,
                        admission,
                        approval_subject_hash_value=native_subject_entity[
                            "approval_subject_hash"
                        ],
                        approval_assertion_set_hash=assertion_set_hash,
                        a06_refs=a06_refs,
                    )
                )
                persistent_authenticity_binding_hash = (
                    native_authenticity_binding_entity[
                        "replay_authorization_authenticity_binding_hash"
                    ]
                )
                native_consumption_entity = self._approval_consumption_entity(
                    subject=_native_approval.subject,
                    assertion_set_hash=assertion_set_hash,
                    authorization_record_set_hash=(
                        rebuilt_authorization.record_set_hash
                    ),
                    replay_admission_hash=admission.replay_admission_hash,
                    after_case_hash=expected_replay.after.case_hash,
                    after_run_id=expected_replay.after.run_id,
                    a06_refs=a06_refs,
                    replay_authorization_authenticity_binding_hash=(
                        persistent_authenticity_binding_hash
                    ),
                )
                native_baseline_binding_entity = (
                    self._baseline_approval_binding_entity(
                        replay=expected_replay,
                        subject_hash=native_subject_entity[
                            "approval_subject_hash"
                        ],
                        assertion_hashes=assertion_hashes,
                        authorization_record_set_hash=(
                            rebuilt_authorization.record_set_hash
                        ),
                        a06_refs=a06_refs,
                        replay_authorization_authenticity_binding_hash=(
                            persistent_authenticity_binding_hash
                        ),
                    )
                )
                native_expectation_entity = (
                    self._replay_approval_expectation_entity(
                        replay=expected_replay,
                        subject_hash=native_subject_entity[
                            "approval_subject_hash"
                        ],
                        assertion_hashes=assertion_hashes,
                        authorization_record_set_hash=(
                            rebuilt_authorization.record_set_hash
                        ),
                        consumption_hash=native_consumption_entity[
                            "consumption_hash"
                        ],
                        replay_admission_hash=admission.replay_admission_hash,
                        baseline_binding_hash=(
                            native_baseline_binding_entity[
                                "baseline_binding_hash"
                            ]
                            if native_baseline_binding_entity is not None
                            else None
                        ),
                        a06_refs=a06_refs,
                        replay_authorization_authenticity_binding_hash=(
                            persistent_authenticity_binding_hash
                        ),
                    )
                )
            ledger_entity = self._replay_ledger_entity(
                admission,
                consumption_hash=(
                    native_consumption_entity["consumption_hash"]
                    if native_consumption_entity is not None
                    else None
                ),
                replay_authorization_authenticity_binding_hash=(
                    native_authenticity_binding_entity[
                        "replay_authorization_authenticity_binding_hash"
                    ]
                    if native_authenticity_binding_entity is not None
                    else None
                ),
            )
            existing_admission = self.connection.execute(
                """SELECT replay_admission_hash,resolution_id,artifact_set_hash,
                          approved_case_hash,resolution_json,payload_json
                   FROM replay_admissions
                   WHERE resolution_id=? AND artifact_set_hash=?
                     AND approved_case_hash=?""",
                (resolution_id, context.artifact_set_hash, replay.before.case_hash),
            ).fetchone()
            if existing_admission is not None and (
                dict(existing_admission) != admission_entity
                or not self._replay_admission_links_match(
                    dict(existing_admission),
                    expected_replay,
                    resolution,
                    approved_case,
                    resolved_case,
                    subject,
                )
            ):
                raise StoreIntegrityError(
                    "stored replay admission or one of its semantic references is inconsistent"
                )
            if replay.baseline:
                if (
                    replay.baseline.case_id != replay.before.case_id
                    or replay.baseline.approved_case_hash != replay.before.case_hash
                    or replay.baseline.approved_event_id != subject["event_id"]
                    or replay.baseline.approved_event_revision != subject["event_revision"]
                    or replay.baseline.source_run_id != replay.after.run_id
                    or replay.baseline.case_hash != replay.after.case_hash
                    or replay.baseline.approved_patch_hash != patch_hash
                ):
                    raise StoreIntegrityError(
                        "baseline does not match the exact approved replay context"
                    )
                approved = [
                    item
                    for item in resolution.get("approvals", [])
                    if item.get("decision") == "APPROVED"
                    and item.get("case_id") == subject["case_id"]
                    and item.get("event_id") == subject["event_id"]
                    and item.get("event_revision") == subject["event_revision"]
                    and item.get("approved_case_hash") == subject["approved_case_hash"]
                    and item.get("approved_patch_hash") == patch_hash
                ]
                approved_roles = tuple(
                    sorted({str(item.get("role", "")) for item in approved})
                )
                expected_roles = (
                    expected_replay.baseline.approved_roles
                    if expected_replay.baseline
                    else ()
                )
                if (
                    approved_roles != replay.baseline.approved_roles
                    or approved_roles != expected_roles
                ):
                    raise StoreIntegrityError(
                        "baseline approvals do not match the supplied resolution"
                    )
            if created_artifact_set:
                entity = self._artifact_set_entity(context.artifact_set_hash)
                if entity is None:
                    raise StoreIntegrityError("stored artifact set disappeared")
                self._append_audit(
                    "artifact_set",
                    context.artifact_set_hash,
                    "ARTIFACT_SET_RECORDED",
                    {
                        "primary_key": {
                            "artifact_set_hash": context.artifact_set_hash
                        },
                        "entity_fingerprint": _fingerprint(entity),
                    },
                )
            if created_reference_set:
                entity = self._controlled_reference_set_entity(
                    supplied_reference_context.reference_set_hash
                )
                if entity is None:
                    raise StoreIntegrityError(
                        "stored controlled reference set disappeared"
                    )
                self._append_audit(
                    "controlled_reference_set",
                    supplied_reference_context.reference_set_hash,
                    "CONTROLLED_REFERENCE_SET_RECORDED",
                    {
                        "primary_key": {
                            "reference_set_hash": supplied_reference_context.reference_set_hash
                        },
                        "entity_fingerprint": _fingerprint(entity),
                    },
                )
            for created, validation_context in (
                (created_source_validation_set, source_validation_context),
                (created_resolved_validation_set, resolved_validation_context),
            ):
                if created:
                    entity = self._validation_evidence_set_entity(
                        validation_context.evidence_set_hash
                    )
                    if entity is None:
                        raise StoreIntegrityError(
                            "stored validation evidence set disappeared"
                        )
                    self._append_audit(
                        "validation_evidence_set",
                        validation_context.evidence_set_hash,
                        "VALIDATION_EVIDENCE_SET_RECORDED",
                        {
                            "primary_key": {
                                "evidence_set_hash": validation_context.evidence_set_hash
                            },
                            "entity_fingerprint": _fingerprint(entity),
                        },
                    )
            self._save_case(resolved_case)
            if source_mode:
                assert _a08_source is not None
                if native_subject_entity is None:
                    raise StoreIntegrityError(
                        "A08 replay approval subject was not rebuilt"
                    )
                self._save_approval_subject_entity(native_subject_entity)
                for native_assertion_entity in native_assertion_entities:
                    self._save_approval_assertion_entity(
                        native_assertion_entity
                    )
                self._stage_case_source_lineages(
                    _a08_source.after_context
                )
                self._stage_a08_source_run(
                    replay.before,
                    _a08_source.before_context,
                    source_validation_context,
                )
                self._stage_a08_source_run(
                    replay.after,
                    _a08_source.after_context,
                    resolved_validation_context,
                )
            else:
                assert save_prevalidated_run is not None
                save_prevalidated_run("before")
                save_prevalidated_run("after")
                self._save_run_validation_link(
                    replay.before.run_id, source_validation_context
                )
                self._save_run_validation_link(
                    replay.after.run_id, resolved_validation_context
                )
            self._fault_point("after_runs")
            if native_subject_entity is not None and not source_mode:
                self._save_approval_subject_entity(native_subject_entity)
                for native_assertion_entity in native_assertion_entities:
                    self._save_approval_assertion_entity(
                        native_assertion_entity
                    )
                self._fault_point("after_native_approvals")
            for approval in (
                ()
                if _native_approval is not None
                else resolution.get("approvals", [])
            ):
                approval_payload = self._approval_payload_for_store(
                    resolution,
                    approval,
                    context.subject_fields(),
                    subject["validation_policy"],
                )
                case_id = approval_payload["case_id"]
                event_id = approval_payload["event_id"]
                event_revision = approval_payload["event_revision"]
                approved_case_hash = approval_payload["approved_case_hash"]
                approved_patch_hash = approval_payload["approved_patch_hash"]
                role = approval_payload["role"]
                decision = approval_payload["decision"]
                payload_json = _json(approval_payload)
                entity = self._approval_entity(
                    resolution_id,
                    case_id,
                    event_id,
                    event_revision,
                    approved_case_hash,
                    approved_patch_hash,
                    role,
                    decision,
                    payload_json,
                )
                inserted = self.connection.execute(
                    """INSERT OR IGNORE INTO approvals
                       (resolution_id, case_id, event_id, event_revision,
                        approved_case_hash, approved_patch_hash, role, decision, payload_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        resolution_id,
                        case_id,
                        event_id,
                        event_revision,
                        approved_case_hash,
                        approved_patch_hash,
                        role,
                        decision,
                        payload_json,
                    ),
                ).rowcount
                if inserted:
                    self._append_audit(
                        "approval",
                        f"{resolution_id}@{case_id}@{event_id}@{event_revision}@{approved_case_hash}@{role}",
                        "APPROVAL_RECORDED",
                        {
                            "primary_key": {
                                "resolution_id": resolution_id,
                                "case_id": case_id,
                                "event_id": event_id,
                                "event_revision": event_revision,
                                "approved_case_hash": approved_case_hash,
                                "role": role,
                            },
                            "entity_fingerprint": _fingerprint(entity),
                        },
                    )
                else:
                    row = self.connection.execute(
                        """SELECT resolution_id, case_id, event_id, event_revision,
                                  approved_case_hash, approved_patch_hash, role, decision, payload_json
                           FROM approvals
                           WHERE resolution_id=? AND case_id=? AND event_id=?
                             AND event_revision=? AND approved_case_hash=? AND role=?""",
                        (
                            resolution_id,
                            case_id,
                            event_id,
                            event_revision,
                            approved_case_hash,
                            role,
                        ),
                    ).fetchone()
                    if row is None or _fingerprint(dict(row)) != _fingerprint(entity):
                        raise StoreIntegrityError(
                            "approval identity conflicts with different decision or content"
                        )

            if replay.baseline:
                self._fault_point("before_baseline")
                payload = replay.baseline.to_dict()
                payload_json = _json(payload)
                entity = self._baseline_entity(
                    replay.baseline.baseline_id,
                    replay.baseline.case_id,
                    replay.baseline.source_run_id,
                    payload_json,
                )
                inserted = self.connection.execute(
                    "INSERT OR IGNORE INTO baselines(baseline_id, case_id, source_run_id, payload_json) VALUES (?, ?, ?, ?)",
                    (
                        replay.baseline.baseline_id,
                        replay.baseline.case_id,
                        replay.baseline.source_run_id,
                        payload_json,
                    ),
                ).rowcount
                if inserted:
                    self._append_audit(
                        "baseline",
                        replay.baseline.baseline_id,
                        "BASELINE_CREATED",
                        {
                            "primary_key": {"baseline_id": replay.baseline.baseline_id},
                            "entity_fingerprint": _fingerprint(entity),
                        },
                    )
                else:
                    row = self.connection.execute(
                        "SELECT baseline_id, case_id, source_run_id, payload_json FROM baselines WHERE baseline_id=?",
                        (replay.baseline.baseline_id,),
                    ).fetchone()
                    if row is None or _fingerprint(dict(row)) != _fingerprint(entity):
                        raise StoreIntegrityError(
                            "baseline_id conflicts with different stored content"
                        )
            self._save_replay_admission_entity(admission_entity)
            if self.connection.execute(
                "SELECT 1 FROM replay_admissions WHERE replay_admission_hash=?",
                (admission_entity["replay_admission_hash"],),
            ).fetchone() is None:
                raise StoreIntegrityError(
                    "replay final semantic preflight failed: admission missing"
                )
            if native_authenticity_binding_entity is not None:
                self._save_replay_authorization_authenticity_binding_entity(
                    native_authenticity_binding_entity
                )
                self._fault_point("after_authorization_authenticity_binding")
            self._save_replay_ledger_entity(ledger_entity)
            self._save_replay_validation_binding_entity(
                validation_binding_entity
            )
            if native_consumption_entity is not None:
                self._save_approval_consumption_entity(
                    native_consumption_entity
                )
                if native_baseline_binding_entity is not None:
                    self._save_baseline_approval_binding_entity(
                        native_baseline_binding_entity
                    )
                if native_expectation_entity is None:
                    raise StoreIntegrityError(
                        "native replay approval expectation was not constructed"
                    )
                self._save_replay_approval_expectation_entity(
                    native_expectation_entity
                )
                self._fault_point("after_native_approval_consumption")
            self._fault_point("after_replay_admission")
            stored_admission = self.connection.execute(
                """SELECT replay_admission_hash,resolution_id,artifact_set_hash,
                          approved_case_hash,resolution_json,payload_json
                   FROM replay_admissions WHERE replay_admission_hash=?""",
                (admission_entity["replay_admission_hash"],),
            ).fetchone()
            stored_ledger = self.connection.execute(
                "SELECT * FROM replay_ledger WHERE replay_ledger_hash=?",
                (ledger_entity["replay_ledger_hash"],),
            ).fetchone()
            stored_validation_binding = self.connection.execute(
                "SELECT * FROM replay_validation_bindings "
                "WHERE validation_binding_hash=?",
                (validation_binding_entity["validation_binding_hash"],),
            ).fetchone()
            native_rows_match = (
                native_subject_entity is not None
                and native_consumption_entity is not None
                and native_expectation_entity is not None
                and native_authenticity_binding_entity is not None
                and self._native_a06_rows_match_final_context(
                    _native_approval,
                    subject_entity=native_subject_entity,
                    assertion_entities=native_assertion_entities,
                    consumption_entity=native_consumption_entity,
                    expectation_entity=native_expectation_entity,
                    baseline_binding_entity=native_baseline_binding_entity,
                    authenticity_binding_entity=(
                        native_authenticity_binding_entity
                    ),
                    ledger_entity=ledger_entity,
                )
            )
            if (
                stored_admission is None
                or stored_ledger is None
                or dict(stored_admission) != admission_entity
                or dict(stored_ledger) != ledger_entity
                or stored_validation_binding is None
                or dict(stored_validation_binding) != validation_binding_entity
                or not native_rows_match
                or not self._replay_admission_links_match(
                    dict(stored_admission),
                    expected_replay,
                    resolution,
                    approved_case,
                    resolved_case,
                    subject,
                )
                or (
                    source_mode
                    and (
                        _a08_source is None
                        or not self._a08_replay_run_reference_links_match(
                            expected_replay,
                            _a08_source.before_context,
                        )
                    )
                )
                or (
                    not source_mode
                    and self.connection.execute(
                        "SELECT 1 FROM run_reference_sets "
                        "WHERE run_id IN (?,?) LIMIT 1",
                        (
                            expected_replay.before.run_id,
                            expected_replay.after.run_id,
                        ),
                    ).fetchone()
                    is not None
                )
                or not self._replay_validation_run_links_match(
                    expected_replay,
                    source_validation_context,
                    resolved_validation_context,
                )
                # This is the last boundary before SQLite commits.  Reuse the
                # parser context already rebuilt from the transaction's stored
                # bytes, but compare every persisted byte/metadata projection
                # against it before accepting the raw audit/business-key view.
                or (
                    not source_mode
                    and not self._controlled_reference_snapshot_matches_context(
                        supplied_reference_context, reference_bundle
                    )
                )
                or (
                    source_mode
                    and (
                        _a08_source is None
                        or self._stored_case_source_context_with_lineage(
                            _a08_source.after_context.case_source_set.source_set_hash,
                            _a08_source.after_context.lineages[-1].lineage_hash,
                        ).assurance().to_dict()
                        != _a08_source.after_context.assurance().to_dict()
                    )
                )
                or not self._artifact_snapshot_matches_context(
                    context, stored_bundle
                )
                or not self._validation_evidence_snapshot_matches_context(
                    source_validation_context,
                    source_validation_bundle,
                )
                or not self._validation_evidence_snapshot_matches_context(
                    resolved_validation_context,
                    resolved_validation_bundle,
                )
                # Full semantic reconstruction here would reopen the artifact
                # parser multiple times inside one trust stage.  Every replay
                # entity is compared above against the already rebuilt,
                # immutable contexts; the raw audit/business-key pass then
                # proves the exact transaction snapshot without substituting
                # the audit chain for those semantic comparisons.
                or not self.verify_audit_chain(_semantic=False)
            ):
                raise StoreIntegrityError("replay final semantic preflight failed")
            self._fault_point("before_commit")

    def counts(self) -> dict[str, int]:
        parent_names = (
            "cases",
            "runs",
            "run_reference_sets",
            "run_validation_sets",
            "approvals",
            "baselines",
            "artifact_blobs",
            "artifact_sets",
            "artifact_set_members",
            "controlled_reference_sets",
            "controlled_reference_members",
            "validation_evidence_sets",
            "validation_evidence_members",
            "replay_admissions",
            "replay_ledger",
            "replay_validation_bindings",
            "authorization_record_sets",
            "authorization_record_members",
            "authorization_trust_snapshots",
            "replay_authorization_authenticity_bindings",
            "approval_subjects",
            "approval_assertions",
            "approval_consumptions",
            "replay_approval_expectations",
            "baseline_approval_bindings",
            "audit_events",
        )
        names = (
            (*parent_names, *sorted(A08_REQUIRED_TABLES))
            if self.feature_profile() == STORE_FEATURE_A08_0_1
            else parent_names
        )
        return {
            name: self.connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            for name in names
        }

    def audit_events(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        return [dict(row) for row in rows]

    def _entity_for_audit(self, action: str, primary_key: dict[str, Any]) -> tuple[str, tuple[Any, ...], dict[str, Any]] | None:
        if action == "CASE_REGISTERED":
            key = (primary_key.get("case_id"), primary_key.get("case_hash"))
            row = self.connection.execute(
                "SELECT case_id, case_hash, synthetic, payload_json FROM cases WHERE case_id=? AND case_hash=?",
                key,
            ).fetchone()
            return ("cases", key, dict(row)) if row else None
        if action == "CHECK_RUN_RECORDED":
            key = (primary_key.get("run_id"),)
            row = self.connection.execute(
                "SELECT run_id, case_id, status, ruleset_version, payload_json FROM runs WHERE run_id=?",
                key,
            ).fetchone()
            return ("runs", key, dict(row)) if row else None
        if action == "RUN_REFERENCE_SET_RECORDED":
            key = (primary_key.get("run_id"),)
            row = self.connection.execute(
                "SELECT run_id,reference_set_hash FROM run_reference_sets WHERE run_id=?",
                key,
            ).fetchone()
            return ("run_reference_sets", key, dict(row)) if row else None
        if action == "RUN_VALIDATION_SET_RECORDED":
            key = (primary_key.get("run_id"),)
            row = self.connection.execute(
                "SELECT run_id,evidence_set_hash FROM run_validation_sets WHERE run_id=?",
                key,
            ).fetchone()
            return ("run_validation_sets", key, dict(row)) if row else None
        if action == "APPROVAL_RECORDED":
            key = (
                primary_key.get("resolution_id"),
                primary_key.get("case_id"),
                primary_key.get("event_id"),
                primary_key.get("event_revision"),
                primary_key.get("approved_case_hash"),
                primary_key.get("role"),
            )
            row = self.connection.execute(
                """SELECT resolution_id, case_id, event_id, event_revision,
                          approved_case_hash, approved_patch_hash, role, decision, payload_json
                   FROM approvals
                   WHERE resolution_id=? AND case_id=? AND event_id=?
                     AND event_revision=? AND approved_case_hash=? AND role=?""",
                key,
            ).fetchone()
            return ("approvals", key, dict(row)) if row else None
        if action == "BASELINE_CREATED":
            key = (primary_key.get("baseline_id"),)
            row = self.connection.execute(
                "SELECT baseline_id, case_id, source_run_id, payload_json FROM baselines WHERE baseline_id=?",
                key,
            ).fetchone()
            return ("baselines", key, dict(row)) if row else None
        if action == "ARTIFACT_SET_RECORDED":
            key = (primary_key.get("artifact_set_hash"),)
            entity = self._artifact_set_entity(str(key[0]))
            return ("artifact_sets", key, entity) if entity else None
        if action == "CONTROLLED_REFERENCE_SET_RECORDED":
            key = (primary_key.get("reference_set_hash"),)
            entity = self._controlled_reference_set_entity(str(key[0]))
            return ("controlled_reference_sets", key, entity) if entity else None
        if action == "VALIDATION_EVIDENCE_SET_RECORDED":
            key = (primary_key.get("evidence_set_hash"),)
            entity = self._validation_evidence_set_entity(str(key[0]))
            return ("validation_evidence_sets", key, entity) if entity else None
        if action == "CASE_SOURCE_SET_RECORDED":
            key = (primary_key.get("source_set_hash"),)
            entity = self._case_source_set_entity(str(key[0]))
            return ("case_source_sets", key, entity) if entity else None
        if action == "CASE_LINEAGE_BINDING_RECORDED":
            key = (primary_key.get("lineage_hash"),)
            entity = self._case_lineage_entity(str(key[0]))
            return ("case_lineage_bindings", key, entity) if entity else None
        if action == "RUN_CASE_SOURCE_SET_RECORDED":
            key = (primary_key.get("run_id"),)
            entity = self._run_case_source_set_entity(str(key[0]))
            return ("run_case_source_sets", key, entity) if entity else None
        if action == "REPLAY_ADMISSION_RECORDED":
            key = (primary_key.get("replay_admission_hash"),)
            row = self.connection.execute(
                """SELECT replay_admission_hash,resolution_id,artifact_set_hash,
                          approved_case_hash,resolution_json,payload_json
                   FROM replay_admissions WHERE replay_admission_hash=?""",
                key,
            ).fetchone()
            return ("replay_admissions", key, dict(row)) if row else None
        if action == "REPLAY_LEDGER_RECORDED":
            key = (primary_key.get("replay_ledger_hash"),)
            row = self.connection.execute(
                "SELECT * FROM replay_ledger WHERE replay_ledger_hash=?", key
            ).fetchone()
            return ("replay_ledger", key, dict(row)) if row else None
        if action == "REPLAY_VALIDATION_BINDING_RECORDED":
            key = (primary_key.get("validation_binding_hash"),)
            row = self.connection.execute(
                "SELECT * FROM replay_validation_bindings "
                "WHERE validation_binding_hash=?",
                key,
            ).fetchone()
            return ("replay_validation_bindings", key, dict(row)) if row else None
        if action == "AUTHORIZATION_RECORD_SET_RECORDED":
            key = (primary_key.get("record_set_hash"),)
            entity = self._authorization_record_set_entity(str(key[0]))
            return ("authorization_record_sets", key, entity) if entity else None
        if action == "AUTHORIZATION_TRUST_SNAPSHOT_RECORDED":
            key = (primary_key.get("trust_snapshot_hash"),)
            row = self.connection.execute(
                "SELECT * FROM authorization_trust_snapshots "
                "WHERE trust_snapshot_hash=?",
                key,
            ).fetchone()
            return ("authorization_trust_snapshots", key, dict(row)) if row else None
        if action == "REPLAY_AUTHORIZATION_AUTHENTICITY_BINDING_RECORDED":
            key = (
                primary_key.get(
                    "replay_authorization_authenticity_binding_hash"
                ),
            )
            row = self.connection.execute(
                "SELECT * FROM replay_authorization_authenticity_bindings "
                "WHERE replay_authorization_authenticity_binding_hash=?",
                key,
            ).fetchone()
            return (
                "replay_authorization_authenticity_bindings",
                key,
                dict(row),
            ) if row else None
        if action == "APPROVAL_SUBJECT_RECORDED":
            key = (primary_key.get("approval_subject_hash"),)
            row = self.connection.execute(
                "SELECT * FROM approval_subjects WHERE approval_subject_hash=?", key
            ).fetchone()
            return ("approval_subjects", key, dict(row)) if row else None
        if action == "APPROVAL_ASSERTION_RECORDED":
            key = (primary_key.get("assertion_hash"),)
            row = self.connection.execute(
                "SELECT * FROM approval_assertions WHERE assertion_hash=?", key
            ).fetchone()
            return ("approval_assertions", key, dict(row)) if row else None
        if action == "APPROVAL_CONSUMPTION_RECORDED":
            key = (primary_key.get("consumption_hash"),)
            row = self.connection.execute(
                "SELECT * FROM approval_consumptions WHERE consumption_hash=?", key
            ).fetchone()
            return ("approval_consumptions", key, dict(row)) if row else None
        if action == "REPLAY_APPROVAL_EXPECTATION_RECORDED":
            key = (primary_key.get("expectation_hash"),)
            row = self.connection.execute(
                "SELECT * FROM replay_approval_expectations WHERE expectation_hash=?",
                key,
            ).fetchone()
            return (
                "replay_approval_expectations",
                key,
                dict(row),
            ) if row else None
        if action == "BASELINE_APPROVAL_BINDING_RECORDED":
            key = (primary_key.get("baseline_binding_hash"),)
            row = self.connection.execute(
                "SELECT * FROM baseline_approval_bindings "
                "WHERE baseline_binding_hash=?",
                key,
            ).fetchone()
            return ("baseline_approval_bindings", key, dict(row)) if row else None
        return None

    def _business_keys(self) -> dict[str, set[tuple[Any, ...]]]:
        keys = {
            "cases": {
                (row["case_id"], row["case_hash"])
                for row in self.connection.execute("SELECT case_id, case_hash FROM cases")
            },
            "runs": {
                (row["run_id"],)
                for row in self.connection.execute("SELECT run_id FROM runs")
            },
            "run_reference_sets": {
                (row["run_id"],)
                for row in self.connection.execute(
                    "SELECT run_id FROM run_reference_sets"
                )
            },
            "run_validation_sets": {
                (row["run_id"],)
                for row in self.connection.execute(
                    "SELECT run_id FROM run_validation_sets"
                )
            },
            "approvals": {
                (
                    row["resolution_id"],
                    row["case_id"],
                    row["event_id"],
                    row["event_revision"],
                    row["approved_case_hash"],
                    row["role"],
                )
                for row in self.connection.execute(
                    """SELECT resolution_id, case_id, event_id, event_revision,
                              approved_case_hash, role FROM approvals"""
                )
            },
            "baselines": {
                (row["baseline_id"],)
                for row in self.connection.execute("SELECT baseline_id FROM baselines")
            },
            "artifact_sets": {
                (row["artifact_set_hash"],)
                for row in self.connection.execute(
                    "SELECT artifact_set_hash FROM artifact_sets"
                )
            },
            "controlled_reference_sets": {
                (row["reference_set_hash"],)
                for row in self.connection.execute(
                    "SELECT reference_set_hash FROM controlled_reference_sets"
                )
            },
            "validation_evidence_sets": {
                (row["evidence_set_hash"],)
                for row in self.connection.execute(
                    "SELECT evidence_set_hash FROM validation_evidence_sets"
                )
            },
            "replay_admissions": {
                (row["replay_admission_hash"],)
                for row in self.connection.execute(
                    "SELECT replay_admission_hash FROM replay_admissions"
                )
            },
            "replay_ledger": {
                (row["replay_ledger_hash"],)
                for row in self.connection.execute(
                    "SELECT replay_ledger_hash FROM replay_ledger"
                )
            },
            "replay_validation_bindings": {
                (row["validation_binding_hash"],)
                for row in self.connection.execute(
                    "SELECT validation_binding_hash FROM replay_validation_bindings"
                )
            },
            "authorization_record_sets": {
                (row["record_set_hash"],)
                for row in self.connection.execute(
                    "SELECT record_set_hash FROM authorization_record_sets"
                )
            },
            "authorization_trust_snapshots": {
                (row["trust_snapshot_hash"],)
                for row in self.connection.execute(
                    "SELECT trust_snapshot_hash FROM authorization_trust_snapshots"
                )
            },
            "replay_authorization_authenticity_bindings": {
                (row["replay_authorization_authenticity_binding_hash"],)
                for row in self.connection.execute(
                    "SELECT replay_authorization_authenticity_binding_hash "
                    "FROM replay_authorization_authenticity_bindings"
                )
            },
            "approval_subjects": {
                (row["approval_subject_hash"],)
                for row in self.connection.execute(
                    "SELECT approval_subject_hash FROM approval_subjects"
                )
            },
            "approval_assertions": {
                (row["assertion_hash"],)
                for row in self.connection.execute(
                    "SELECT assertion_hash FROM approval_assertions"
                )
            },
            "approval_consumptions": {
                (row["consumption_hash"],)
                for row in self.connection.execute(
                    "SELECT consumption_hash FROM approval_consumptions"
                )
            },
            "replay_approval_expectations": {
                (row["expectation_hash"],)
                for row in self.connection.execute(
                    "SELECT expectation_hash FROM replay_approval_expectations"
                )
            },
            "baseline_approval_bindings": {
                (row["baseline_binding_hash"],)
                for row in self.connection.execute(
                    "SELECT baseline_binding_hash FROM baseline_approval_bindings"
                )
            },
        }
        if self.feature_profile() == STORE_FEATURE_A08_0_1:
            keys["case_source_sets"] = {
                (row["source_set_hash"],)
                for row in self.connection.execute(
                    "SELECT source_set_hash FROM case_source_sets"
                )
            }
            keys["run_case_source_sets"] = {
                (row["run_id"],)
                for row in self.connection.execute(
                    "SELECT run_id FROM run_case_source_sets"
                )
            }
            keys["case_lineage_bindings"] = {
                (row["lineage_hash"],)
                for row in self.connection.execute(
                    "SELECT lineage_hash FROM case_lineage_bindings"
                )
            }
        return keys

    def _controlled_reference_set_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            reference_set_hash = entity["reference_set_hash"]
            rebuilt = self._controlled_reference_set_entity(reference_set_hash)
            if rebuilt != entity:
                return False
            try:
                bundle = self._load_controlled_reference_bundle(reference_set_hash)
                context = _prepare_controlled_reference_context(bundle)
                if context.reference_set_hash == reference_set_hash:
                    return True
            except (TypeError, ValueError, StoreIntegrityError):
                pass
            return self._case_source_context_for_reference_set(
                reference_set_hash
            ) is not None
        except (KeyError, TypeError, ValueError, StoreIntegrityError):
            return False

    def _authorization_record_set_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            if set(entity) != {
                "record_set_hash",
                "contract_version",
                "bundle_id",
                "normalized_bundle_id",
                "manifest_bytes",
            }:
                return False
            bundle = self._load_authorization_record_bundle(
                entity["record_set_hash"]
            )
            context = prepare_authorization_record_context(bundle)
            return (
                context.record_set_hash == entity["record_set_hash"]
                and context.contract_version == entity["contract_version"]
                and context.contract_version in {
                    AUTHORIZATION_RECORD_SET_VERSION,
                    SIGNED_AUTHORIZATION_RECORD_SET_VERSION,
                }
                and context.bundle_id == entity["bundle_id"]
                and entity["normalized_bundle_id"]
                == normalized_identity(entity["bundle_id"])
                and bundle.canonical_manifest_bytes == bytes(entity["manifest_bytes"])
                and self._authorization_record_set_entity(
                    context.record_set_hash
                )
                == entity
            )
        except (KeyError, TypeError, ValueError, StoreIntegrityError, sqlite3.Error):
            return False

    def _authorization_trust_snapshot_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        cache = getattr(self, "_verify_authorization_snapshot_cache", None)
        cache_key = (
            entity.get("trust_snapshot_hash"),
            _fingerprint(entity),
        )
        if isinstance(cache, dict) and cache_key in cache:
            return bool(cache[cache_key])
        valid = self._authorization_trust_snapshot_entity_is_semantically_valid_uncached(
            entity
        )
        if isinstance(cache, dict):
            cache[cache_key] = valid
        return valid

    def _authorization_trust_snapshot_entity_is_semantically_valid_uncached(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            if set(entity) != {
                "trust_snapshot_hash",
                "contract_version",
                "trust_policy_hash",
                "trust_policy_version",
                "snapshot_bytes",
            }:
                return False
            bundle = AuthorizationTrustSnapshotBundle(entity["snapshot_bytes"])
            binding_rows = self.connection.execute(
                "SELECT authorization_record_set_hash,"
                "authorization_authenticity_context_hash "
                "FROM replay_authorization_authenticity_bindings "
                "WHERE trust_snapshot_hash=?",
                (entity["trust_snapshot_hash"],),
            ).fetchall()
            lineage_refs: list[dict[str, Any]] = []
            if not binding_rows:
                for row in self.connection.execute(
                    "SELECT b.raw_bytes FROM case_lineage_bindings l "
                    "JOIN artifact_blobs b ON "
                    "b.source_hash=l.operation_material_source_hash "
                    "WHERE l.operation_kind='NATIVE_REPLAY'"
                ):
                    material = strict_json_loads(
                        bytes(row["raw_bytes"]).decode("utf-8")
                    )
                    if (
                        type(material) is dict
                        and material.get("authorization_trust_snapshot_hash")
                        == entity["trust_snapshot_hash"]
                    ):
                        lineage_refs.append(material)
                if not lineage_refs:
                    return False
            for row in binding_rows:
                context = self._stored_authorization_authenticity_context(
                    row["authorization_record_set_hash"],
                    entity["trust_snapshot_hash"],
                )
                if (
                    context.state != AUTHORIZATION_AUTHENTICITY_PASS
                    or context.authorization_authenticity_context_hash
                    != row["authorization_authenticity_context_hash"]
                    or self._authorization_trust_snapshot_entity_from_context(
                        context, bundle
                    )
                    != entity
                ):
                    return False
            for material in lineage_refs:
                context = self._stored_authorization_authenticity_context(
                    material["authorization_record_set_hash"],
                    entity["trust_snapshot_hash"],
                )
                if (
                    context.state != AUTHORIZATION_AUTHENTICITY_PASS
                    or context.authorization_authenticity_context_hash
                    != material["authorization_authenticity_context_hash"]
                    or self._authorization_trust_snapshot_entity_from_context(
                        context,
                        bundle,
                    )
                    != entity
                ):
                    return False
            return True
        except (
            KeyError,
            TypeError,
            ValueError,
            StoreIntegrityError,
            sqlite3.Error,
        ):
            return False

    def _replay_authorization_authenticity_binding_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        cache = getattr(self, "_verify_authorization_binding_cache", None)
        cache_key = (
            entity.get("replay_authorization_authenticity_binding_hash"),
            _fingerprint(entity),
        )
        if isinstance(cache, dict) and cache_key in cache:
            return bool(cache[cache_key])
        valid = (
            self._replay_authorization_authenticity_binding_entity_is_semantically_valid_uncached(
                entity
            )
        )
        if isinstance(cache, dict):
            cache[cache_key] = valid
        return valid

    def _replay_authorization_authenticity_binding_entity_is_semantically_valid_uncached(
        self, entity: dict[str, Any]
    ) -> bool:
        required_payload_fields = {
            "contract_version",
            "resolution_id",
            "replay_admission_hash",
            "approval_subject_hash",
            "approval_assertion_set_hash",
            *_A06_AUTHENTICITY_REF_KEYS,
            "after_case_hash",
            "after_run_id",
        }
        required_entity_fields = {
            "replay_authorization_authenticity_binding_hash",
            "replay_admission_hash",
            "approval_subject_hash",
            "approval_assertion_set_hash",
            "authorization_record_set_hash",
            "trust_snapshot_hash",
            "authorization_authenticity_context_hash",
            "stateless_authenticity_binding_hash",
            "after_case_hash",
            "after_run_id",
            "payload_json",
        }
        try:
            if set(entity) != required_entity_fields:
                return False
            payload = strict_json_loads(entity["payload_json"])
            if (
                not isinstance(payload, dict)
                or set(payload) != required_payload_fields
                or entity["payload_json"] != _json(payload)
                or payload["contract_version"]
                != REPLAY_AUTHORIZATION_AUTHENTICITY_BINDING_CONTRACT_VERSION
                or entity["replay_authorization_authenticity_binding_hash"]
                != _domain_hash(
                    _REPLAY_AUTHORIZATION_AUTHENTICITY_BINDING_DOMAIN,
                    entity["payload_json"].encode("utf-8"),
                )
            ):
                return False
            a06_refs = _a06_refs_from_payload(payload)
            if any(
                entity[field] != payload[payload_field]
                for field, payload_field in (
                    ("replay_admission_hash", "replay_admission_hash"),
                    ("approval_subject_hash", "approval_subject_hash"),
                    ("approval_assertion_set_hash", "approval_assertion_set_hash"),
                    ("authorization_record_set_hash", "authorization_record_set_hash"),
                    ("trust_snapshot_hash", "authorization_trust_snapshot_hash"),
                    (
                        "authorization_authenticity_context_hash",
                        "authorization_authenticity_context_hash",
                    ),
                    (
                        "stateless_authenticity_binding_hash",
                        "authorization_authenticity_binding_hash",
                    ),
                    ("after_case_hash", "after_case_hash"),
                    ("after_run_id", "after_run_id"),
                )
            ):
                return False
            admission_row = self.connection.execute(
                "SELECT payload_json FROM replay_admissions "
                "WHERE replay_admission_hash=?",
                (entity["replay_admission_hash"],),
            ).fetchone()
            subject_row = self.connection.execute(
                "SELECT payload_json FROM approval_subjects "
                "WHERE approval_subject_hash=?",
                (entity["approval_subject_hash"],),
            ).fetchone()
            after_case_row = self.connection.execute(
                "SELECT payload_json FROM cases WHERE case_hash=?",
                (entity["after_case_hash"],),
            ).fetchone()
            after_run_row = self.connection.execute(
                "SELECT payload_json FROM runs WHERE run_id=?",
                (entity["after_run_id"],),
            ).fetchone()
            if None in (
                admission_row,
                subject_row,
                after_case_row,
                after_run_row,
            ):
                return False
            admission = strict_json_loads(admission_row["payload_json"])
            subject = strict_json_loads(subject_row["payload_json"])
            after_case = self._verify_stored_case_payload(
                after_case_row["payload_json"]
            )
            after_run = strict_json_loads(after_run_row["payload_json"])
            if (
                admission.get("contract_version")
                not in {
                    A06_REPLAY_ADMISSION_CONTRACT_VERSION,
                    A08_REPLAY_ADMISSION_CONTRACT_VERSION,
                }
                or admission.get("resolution_id") != payload["resolution_id"]
                or admission.get("approval_subject_hash")
                != entity["approval_subject_hash"]
                or admission.get("approval_assertion_set_hash")
                != entity["approval_assertion_set_hash"]
                or admission.get("after_case", {}).get("case_hash")
                != entity["after_case_hash"]
                or admission.get("after_run", {}).get("run_id")
                != entity["after_run_id"]
                or after_case.get("applied_resolution")
                != payload["resolution_id"]
                or after_run.get("case_hash") != entity["after_case_hash"]
                or any(admission.get(key) != value for key, value in a06_refs.items())
            ):
                return False
            context = self._stored_authorization_authenticity_context(
                entity["authorization_record_set_hash"],
                entity["trust_snapshot_hash"],
            )
            assertion_rows = self.connection.execute(
                "SELECT payload_json FROM approval_assertions "
                "WHERE approval_subject_hash=? ORDER BY assertion_hash",
                (entity["approval_subject_hash"],),
            ).fetchall()
            assertions = tuple(
                validate_approval_assertion_shape(
                    strict_json_loads(row["payload_json"])
                )
                for row in assertion_rows
            )
            validation = validate_approval_assertions(
                subject,
                assertions,
                context.record_context,
            )
            require_authenticated_assertion_records(assertions, context)
            expected_refs = {
                "authorization_record_set_hash": context.authorization_record_set_hash,
                "authorization_record_set_contract_version": (
                    context.authorization_record_set_contract_version
                ),
                "authorization_authenticity_state": context.state,
                "authorization_authenticity_context_hash": (
                    context.authorization_authenticity_context_hash
                ),
                "authorization_authenticity_binding_hash": (
                    authorization_authenticity_binding_hash(
                        approval_subject_hash=entity["approval_subject_hash"],
                        approval_assertion_set_hash=entity[
                            "approval_assertion_set_hash"
                        ],
                        authorization_authenticity_context_hash=(
                            context.authorization_authenticity_context_hash
                        ),
                        after_case_hash=entity["after_case_hash"],
                        after_run_hash=canonical_hash(after_run),
                    )
                ),
                "authorization_trust_snapshot_hash": context.trust_snapshot_hash,
                "authorization_trust_snapshot_contract_version": (
                    context.trust_snapshot_contract_version
                ),
                "authorization_trust_policy_hash": context.trust_policy_hash,
                "authorization_trust_policy_version": context.trust_policy_version,
            }
            return (
                context.state == AUTHORIZATION_AUTHENTICITY_PASS
                and a06_refs == expected_refs
                and validation.approval_subject_hash
                == entity["approval_subject_hash"]
                and self._assertion_set_hash(validation.assertion_hashes)
                == entity["approval_assertion_set_hash"]
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            StoreIntegrityError,
            sqlite3.Error,
        ):
            return False

    def _approval_subject_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            payload = strict_json_loads(entity["payload_json"])
            expected = self._approval_subject_entity(payload)
            return (
                entity == expected
                and payload["contract_version"]
                in {
                    APPROVAL_SUBJECT_CONTRACT_VERSION,
                    SOURCE_APPROVAL_SUBJECT_CONTRACT_VERSION,
                }
                and payload["use_policy"] == APPROVAL_USE_POLICY
            )
        except (KeyError, TypeError, ValueError):
            return False

    def _approval_assertion_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            assertion = validate_approval_assertion_shape(
                strict_json_loads(entity["payload_json"])
            )
            if (
                entity["normalized_approval_id"]
                != normalized_identity(entity["approval_id"])
                or assertion["assertion_contract_version"]
                != APPROVAL_ASSERTION_CONTRACT_VERSION
                or entity["assertion_hash"]
                != approval_assertion_hash(assertion)
                or assertion["approval_subject_hash"]
                != entity["approval_subject_hash"]
                or assertion["approval_id"] != entity["approval_id"]
                or assertion["role_claim"] != entity["role_claim"]
                or assertion["authorization_record_id"]
                != entity["authorization_record_id"]
                or assertion["authorization_record_hash"]
                != entity["authorization_record_hash"]
            ):
                return False
            subject_row = self.connection.execute(
                "SELECT * FROM approval_subjects WHERE approval_subject_hash=?",
                (entity["approval_subject_hash"],),
            ).fetchone()
            auth_entity = self._authorization_record_set_entity(
                entity["authorization_record_set_hash"]
            )
            if (
                subject_row is None
                or auth_entity is None
                or not self._approval_subject_entity_is_semantically_valid(
                    dict(subject_row)
                )
                or not self._authorization_record_set_entity_is_semantically_valid(
                    auth_entity
                )
            ):
                return False
            context = prepare_authorization_record_context(
                self._load_authorization_record_bundle(
                    entity["authorization_record_set_hash"]
                )
            )
            record = context.record(
                entity["authorization_record_id"],
                entity["authorization_record_hash"],
            )
            subject = strict_json_loads(subject_row["payload_json"])
            return (
                assertion["approver_id_claim"] == record.approver_id_claim
                and assertion["role_claim"] == record.role_claim
                and assertion["role_claim"] in subject["required_role_claims"]
                and record.purpose_code == subject["purpose_code"]
                and record.scope_code == subject["scope_code"]
                and assertion["effective_from"] == record.effective_from
                and assertion["expires_at"] == record.expires_at
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            StoreIntegrityError,
            sqlite3.Error,
        ):
            return False

    def _approval_consumption_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        cache = getattr(self, "_verify_approval_consumption_semantic_cache", None)
        if not isinstance(cache, dict):
            return self._approval_consumption_entity_is_semantically_valid_uncached(
                entity
            )
        try:
            key = self._verification_semantic_cache_key(entity)
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False
        if key not in cache:
            cache[key] = (
                self._approval_consumption_entity_is_semantically_valid_uncached(
                    entity
                )
            )
        return bool(cache[key])

    def _approval_consumption_entity_is_semantically_valid_uncached(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            payload = strict_json_loads(entity["payload_json"])
            base_fields = {
                "contract_version",
                "approval_subject_hash",
                "assertion_set_hash",
                "authorization_record_set_hash",
                "execution_nonce",
                "use_policy",
                "replay_admission_hash",
                "after_case_hash",
                "after_run_id",
            }
            a06 = (
                isinstance(payload, dict)
                and payload.get("contract_version")
                == A06_APPROVAL_CONSUMPTION_CONTRACT_VERSION
            )
            expected_fields = base_fields | (
                {
                    *_A06_AUTHENTICITY_REF_KEYS,
                    "replay_authorization_authenticity_binding_hash",
                }
                if a06
                else set()
            )
            if not isinstance(payload, dict) or set(payload) != expected_fields:
                return False
            a06_refs = _a06_refs_from_payload(payload) if a06 else {}
            persistent_binding_hash = (
                payload["replay_authorization_authenticity_binding_hash"]
                if a06
                else None
            )
            subject_row = self.connection.execute(
                "SELECT * FROM approval_subjects WHERE approval_subject_hash=?",
                (entity["approval_subject_hash"],),
            ).fetchone()
            admission_row = self.connection.execute(
                "SELECT payload_json FROM replay_admissions "
                "WHERE replay_admission_hash=?",
                (entity["replay_admission_hash"],),
            ).fetchone()
            if subject_row is None or admission_row is None:
                return False
            subject = strict_json_loads(subject_row["payload_json"])
            admission = strict_json_loads(admission_row["payload_json"])
            expected = self._approval_consumption_entity(
                subject=subject,
                assertion_set_hash=entity["assertion_set_hash"],
                authorization_record_set_hash=entity[
                    "authorization_record_set_hash"
                ],
                replay_admission_hash=entity["replay_admission_hash"],
                after_case_hash=payload["after_case_hash"],
                after_run_id=payload["after_run_id"],
                a06_refs=a06_refs,
                replay_authorization_authenticity_binding_hash=(
                    persistent_binding_hash
                ),
            )
            binding_entity = (
                self._replay_authorization_authenticity_binding_entity_for_hash(
                    persistent_binding_hash
                )
                if a06
                else None
            )
            return (
                entity == expected
                and payload["contract_version"]
                == (
                    A06_APPROVAL_CONSUMPTION_CONTRACT_VERSION
                    if a06
                    else APPROVAL_CONSUMPTION_CONTRACT_VERSION
                )
                and payload["use_policy"] == APPROVAL_USE_POLICY
                and admission.get("contract_version")
                in (
                    {
                        A06_REPLAY_ADMISSION_CONTRACT_VERSION,
                        A08_REPLAY_ADMISSION_CONTRACT_VERSION,
                    }
                    if a06
                    else {A05_REPLAY_ADMISSION_CONTRACT_VERSION}
                )
                and admission.get("approval_subject_hash")
                == entity["approval_subject_hash"]
                and admission.get("approval_assertion_set_hash")
                == entity["assertion_set_hash"]
                and admission.get("authorization_record_set_hash")
                == entity["authorization_record_set_hash"]
                and admission.get("execution_nonce")
                == entity["execution_nonce"]
                and admission.get("after_case", {}).get("case_hash")
                == payload["after_case_hash"]
                and admission.get("after_run", {}).get("run_id")
                == entity["after_run_id"]
                and (
                    not a06
                    or (
                        binding_entity is not None
                        and binding_entity["replay_admission_hash"]
                        == entity["replay_admission_hash"]
                        and binding_entity["approval_subject_hash"]
                        == entity["approval_subject_hash"]
                        and binding_entity["approval_assertion_set_hash"]
                        == entity["assertion_set_hash"]
                        and self._replay_authorization_authenticity_binding_entity_is_semantically_valid(
                            binding_entity
                        )
                        and all(
                            admission.get(key) == value
                            for key, value in a06_refs.items()
                        )
                    )
                )
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            StoreIntegrityError,
            sqlite3.Error,
        ):
            return False

    def _baseline_approval_binding_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        cache = getattr(self, "_verify_baseline_binding_semantic_cache", None)
        if not isinstance(cache, dict):
            return self._baseline_approval_binding_entity_is_semantically_valid_uncached(
                entity
            )
        try:
            key = self._verification_semantic_cache_key(entity)
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False
        if key not in cache:
            cache[key] = (
                self._baseline_approval_binding_entity_is_semantically_valid_uncached(
                    entity
                )
            )
        return bool(cache[key])

    def _baseline_approval_binding_entity_is_semantically_valid_uncached(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            payload = strict_json_loads(entity["payload_json"])
            base_fields = {
                "contract_version",
                "baseline_id",
                "baseline_hash",
                "after_case_hash",
                "after_run_id",
                "resolution_id",
                "artifact_set_hash",
                "approval_subject_hash",
                "assertion_hashes",
                "assertion_set_hash",
                "authorization_record_set_hash",
            }
            a06 = (
                isinstance(payload, dict)
                and payload.get("contract_version")
                == A06_BASELINE_APPROVAL_BINDING_CONTRACT_VERSION
            )
            expected_fields = base_fields | (
                {
                    *_A06_AUTHENTICITY_REF_KEYS,
                    "replay_authorization_authenticity_binding_hash",
                }
                if a06
                else set()
            )
            if not isinstance(payload, dict) or set(payload) != expected_fields:
                return False
            core_hash = _domain_hash(
                (
                    _A06_BASELINE_APPROVAL_BINDING_DOMAIN
                    if a06
                    else _BASELINE_APPROVAL_BINDING_DOMAIN
                ),
                entity["payload_json"].encode("utf-8"),
            )
            a06_refs = _a06_refs_from_payload(payload) if a06 else {}
            persistent_binding = (
                self._replay_authorization_authenticity_binding_entity_for_hash(
                    payload[
                        "replay_authorization_authenticity_binding_hash"
                    ]
                )
                if a06
                else None
            )
            baseline_row = self.connection.execute(
                "SELECT payload_json FROM baselines WHERE baseline_id=?",
                (entity["baseline_id"],),
            ).fetchone()
            if baseline_row is None:
                return False
            baseline = strict_json_loads(baseline_row["payload_json"])
            assertion_rows = self.connection.execute(
                "SELECT assertion_hash,authorization_record_set_hash "
                "FROM approval_assertions WHERE approval_subject_hash=? "
                "ORDER BY assertion_hash",
                (entity["approval_subject_hash"],),
            ).fetchall()
            assertion_hashes = tuple(row["assertion_hash"] for row in assertion_rows)
            return (
                core_hash == entity["baseline_binding_hash"]
                and payload["contract_version"]
                == (
                    A06_BASELINE_APPROVAL_BINDING_CONTRACT_VERSION
                    if a06
                    else BASELINE_APPROVAL_BINDING_CONTRACT_VERSION
                )
                and payload["baseline_id"] == entity["baseline_id"]
                and payload["baseline_hash"] == canonical_hash(baseline)
                and payload["after_case_hash"] == entity["after_case_hash"]
                and payload["after_run_id"] == entity["after_run_id"]
                and payload["resolution_id"] == entity["resolution_id"]
                and payload["artifact_set_hash"] == entity["artifact_set_hash"]
                and payload["approval_subject_hash"]
                == entity["approval_subject_hash"]
                and tuple(payload["assertion_hashes"]) == assertion_hashes
                and payload["assertion_set_hash"]
                == entity["assertion_set_hash"]
                == self._assertion_set_hash(assertion_hashes)
                and payload["authorization_record_set_hash"]
                == entity["authorization_record_set_hash"]
                and bool(assertion_rows)
                and all(
                    row["authorization_record_set_hash"]
                    == entity["authorization_record_set_hash"]
                    for row in assertion_rows
                )
                and baseline.get("case_hash") == entity["after_case_hash"]
                and baseline.get("source_run_id") == entity["after_run_id"]
                and baseline.get("resolution_id") == entity["resolution_id"]
                and baseline.get("artifact_set_hash")
                == entity["artifact_set_hash"]
                and (
                    not a06
                    or (
                        persistent_binding is not None
                        and persistent_binding["approval_subject_hash"]
                        == entity["approval_subject_hash"]
                        and persistent_binding["approval_assertion_set_hash"]
                        == entity["assertion_set_hash"]
                        and persistent_binding["authorization_record_set_hash"]
                        == entity["authorization_record_set_hash"]
                        and persistent_binding["after_case_hash"]
                        == entity["after_case_hash"]
                        and persistent_binding["after_run_id"]
                        == entity["after_run_id"]
                        and self._replay_authorization_authenticity_binding_entity_is_semantically_valid(
                            persistent_binding
                        )
                        and all(
                            strict_json_loads(
                                persistent_binding["payload_json"]
                            ).get(key)
                            == value
                            for key, value in a06_refs.items()
                        )
                    )
                )
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            StoreIntegrityError,
            sqlite3.Error,
        ):
            return False

    def _replay_approval_expectation_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        cache = getattr(self, "_verify_replay_expectation_semantic_cache", None)
        if not isinstance(cache, dict):
            return self._replay_approval_expectation_entity_is_semantically_valid_uncached(
                entity
            )
        try:
            key = self._verification_semantic_cache_key(entity)
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False
        if key not in cache:
            cache[key] = (
                self._replay_approval_expectation_entity_is_semantically_valid_uncached(
                    entity
                )
            )
        return bool(cache[key])

    def _replay_approval_expectation_entity_is_semantically_valid_uncached(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            payload = strict_json_loads(entity["payload_json"])
            base_fields = {
                "contract_version",
                "resolution_id",
                "after_case_hash",
                "after_run_id",
                "artifact_set_hash",
                "approval_subject_hash",
                "assertion_hashes",
                "assertion_set_hash",
                "authorization_record_set_hash",
                "consumption_hash",
                "replay_admission_hash",
                "baseline",
                "baseline_binding_hash",
            }
            a06 = (
                isinstance(payload, dict)
                and payload.get("contract_version")
                == A06_REPLAY_APPROVAL_EXPECTATION_CONTRACT_VERSION
            )
            expected_fields = base_fields | (
                {
                    *_A06_AUTHENTICITY_REF_KEYS,
                    "replay_authorization_authenticity_binding_hash",
                }
                if a06
                else set()
            )
            if not isinstance(payload, dict) or set(payload) != expected_fields:
                return False
            a06_refs = _a06_refs_from_payload(payload) if a06 else {}
            persistent_binding = (
                self._replay_authorization_authenticity_binding_entity_for_hash(
                    payload[
                        "replay_authorization_authenticity_binding_hash"
                    ]
                )
                if a06
                else None
            )
            if (
                entity["expectation_hash"]
                != _domain_hash(
                    (
                        _A06_REPLAY_APPROVAL_EXPECTATION_DOMAIN
                        if a06
                        else _REPLAY_APPROVAL_EXPECTATION_DOMAIN
                    ),
                    entity["payload_json"].encode("utf-8"),
                )
                or payload["contract_version"]
                != (
                    A06_REPLAY_APPROVAL_EXPECTATION_CONTRACT_VERSION
                    if a06
                    else REPLAY_APPROVAL_EXPECTATION_CONTRACT_VERSION
                )
                or any(
                    payload[field] != entity[field]
                    for field in (
                        "resolution_id",
                        "after_case_hash",
                        "after_run_id",
                        "artifact_set_hash",
                        "approval_subject_hash",
                        "assertion_set_hash",
                        "authorization_record_set_hash",
                        "consumption_hash",
                        "replay_admission_hash",
                        "baseline_binding_hash",
                    )
                )
            ):
                return False
            case_row = self.connection.execute(
                "SELECT payload_json FROM cases WHERE case_hash=?",
                (entity["after_case_hash"],),
            ).fetchone()
            run_row = self.connection.execute(
                "SELECT payload_json FROM runs WHERE run_id=?",
                (entity["after_run_id"],),
            ).fetchone()
            admission_row = self.connection.execute(
                "SELECT payload_json FROM replay_admissions "
                "WHERE replay_admission_hash=?",
                (entity["replay_admission_hash"],),
            ).fetchone()
            consumption_row = self.connection.execute(
                "SELECT * FROM approval_consumptions WHERE consumption_hash=?",
                (entity["consumption_hash"],),
            ).fetchone()
            if None in (case_row, run_row, admission_row, consumption_row):
                return False
            case = self._verify_stored_case_payload(case_row["payload_json"])
            run = strict_json_loads(run_row["payload_json"])
            admission = strict_json_loads(admission_row["payload_json"])
            assertion_rows = self.connection.execute(
                "SELECT assertion_hash,authorization_record_set_hash "
                "FROM approval_assertions WHERE approval_subject_hash=? "
                "ORDER BY assertion_hash",
                (entity["approval_subject_hash"],),
            ).fetchall()
            assertion_hashes = tuple(row["assertion_hash"] for row in assertion_rows)
            baseline_binding_rows = self.connection.execute(
                "SELECT * FROM baseline_approval_bindings "
                "WHERE after_case_hash=?",
                (entity["after_case_hash"],),
            ).fetchall()
            baseline_value = payload["baseline"]
            if baseline_value is None:
                if (
                    entity["baseline_id"] is not None
                    or entity["baseline_binding_hash"] is not None
                    or admission.get("baseline") is not None
                ):
                    return False
                expected_baseline_count = 0
            else:
                if (
                    not isinstance(baseline_value, dict)
                    or set(baseline_value) != {"baseline_id", "baseline_hash"}
                    or baseline_value != admission.get("baseline")
                    or baseline_value["baseline_id"] != entity["baseline_id"]
                    or entity["baseline_binding_hash"] is None
                ):
                    return False
                baseline_row = self.connection.execute(
                    "SELECT payload_json FROM baselines WHERE baseline_id=?",
                    (entity["baseline_id"],),
                ).fetchone()
                if (
                    baseline_row is None
                    or baseline_value["baseline_hash"]
                    != canonical_hash(
                        strict_json_loads(baseline_row["payload_json"])
                    )
                ):
                    return False
                expected_baseline_count = 1
            return (
                case.get("applied_resolution") == entity["resolution_id"]
                and run.get("run_id") == entity["after_run_id"]
                and run.get("case_hash") == entity["after_case_hash"]
                and admission.get("after_case", {}).get("case_hash")
                == entity["after_case_hash"]
                and admission.get("after_run", {}).get("run_id")
                == entity["after_run_id"]
                and admission.get("artifact_set_hash")
                == entity["artifact_set_hash"]
                and admission.get("approval_subject_hash")
                == entity["approval_subject_hash"]
                and admission.get("approval_assertion_set_hash")
                == entity["assertion_set_hash"]
                and admission.get("authorization_record_set_hash")
                == entity["authorization_record_set_hash"]
                and tuple(payload["assertion_hashes"]) == assertion_hashes
                and entity["assertion_set_hash"]
                == self._assertion_set_hash(assertion_hashes)
                and bool(assertion_rows)
                and all(
                    row["authorization_record_set_hash"]
                    == entity["authorization_record_set_hash"]
                    for row in assertion_rows
                )
                and self._approval_consumption_entity_is_semantically_valid(
                    dict(consumption_row)
                )
                and (
                    not a06
                    or (
                        persistent_binding is not None
                        and persistent_binding["replay_admission_hash"]
                        == entity["replay_admission_hash"]
                        and persistent_binding["approval_subject_hash"]
                        == entity["approval_subject_hash"]
                        and persistent_binding["approval_assertion_set_hash"]
                        == entity["assertion_set_hash"]
                        and persistent_binding["authorization_record_set_hash"]
                        == entity["authorization_record_set_hash"]
                        and persistent_binding["after_case_hash"]
                        == entity["after_case_hash"]
                        and persistent_binding["after_run_id"]
                        == entity["after_run_id"]
                        and self._replay_authorization_authenticity_binding_entity_is_semantically_valid(
                            persistent_binding
                        )
                        and all(
                            strict_json_loads(
                                persistent_binding["payload_json"]
                            ).get(key)
                            == value
                            for key, value in a06_refs.items()
                        )
                    )
                )
                and len(baseline_binding_rows) == expected_baseline_count
                and (
                    not baseline_binding_rows
                    or (
                        entity["baseline_binding_hash"]
                        == baseline_binding_rows[0]["baseline_binding_hash"]
                        and self._baseline_approval_binding_entity_is_semantically_valid(
                            dict(baseline_binding_rows[0])
                        )
                    )
                )
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            StoreIntegrityError,
            sqlite3.Error,
        ):
            return False

    def _artifact_set_entity_is_semantically_valid(
        self, entity: dict[str, Any], *, validate_linked_baselines: bool = True
    ) -> bool:
        try:
            artifact_set_hash = entity["artifact_set_hash"]
            bundle = self._load_artifact_bundle(artifact_set_hash)
            if hashlib.sha256(bundle.canonical_manifest_bytes).hexdigest() != entity["manifest_bytes_hash"]:
                return False
            rows = self.connection.execute(
                "SELECT source_hash,raw_bytes,size_bytes FROM artifact_blobs WHERE source_hash IN "
                "(SELECT source_hash FROM artifact_set_members WHERE artifact_set_hash=?)",
                (artifact_set_hash,),
            ).fetchall()
            if not rows:
                return False
            if not all(
                len(bytes(row["raw_bytes"])) == row["size_bytes"]
                and hashlib.sha256(bytes(row["raw_bytes"])).hexdigest() == row["source_hash"]
                for row in rows
            ):
                return False
            reference_set_hash = entity.get("controlled_reference_set_hash")
            reference_entity = self._controlled_reference_set_entity(
                str(reference_set_hash)
            )
            lineage_rows: list[dict[str, Any]] = []
            for lineage_row in self.connection.execute(
                "SELECT l.lineage_hash,b.raw_bytes "
                "FROM case_lineage_bindings l JOIN artifact_blobs b ON "
                "b.source_hash=l.operation_material_source_hash "
                "WHERE l.operation_kind='NATIVE_REPLAY'"
            ):
                material = strict_json_loads(
                    bytes(lineage_row["raw_bytes"]).decode("utf-8")
                )
                if (
                    type(material) is dict
                    and material.get("artifact_set_hash") == artifact_set_hash
                ):
                    lineage_entity = self._case_lineage_entity(
                        lineage_row["lineage_hash"]
                    )
                    if lineage_entity is not None:
                        lineage_rows.append(lineage_entity)
            if (
                reference_entity is None
                and not lineage_rows
            ):
                return False
            if reference_entity is not None and not (
                self._controlled_reference_set_entity_is_semantically_valid(
                    reference_entity
                )
            ):
                return False
            if not validate_linked_baselines:
                return True
            admission_rows = self.connection.execute(
                """SELECT replay_admission_hash,resolution_id,artifact_set_hash,
                          approved_case_hash,resolution_json,payload_json
                   FROM replay_admissions WHERE artifact_set_hash=?""",
                (artifact_set_hash,),
            ).fetchall()
            if admission_rows:
                return all(
                    self._replay_admission_entity_is_semantically_valid(dict(row))
                    for row in admission_rows
                ) and all(
                    self._case_lineage_entity_is_semantically_valid(row)
                    for row in lineage_rows
                )
            if lineage_rows:
                return all(
                    self._case_lineage_entity_is_semantically_valid(row)
                    for row in lineage_rows
                )
            matching_baselines: list[dict[str, Any]] = []
            for row in self.connection.execute(
                "SELECT baseline_id,case_id,source_run_id,payload_json FROM baselines"
            ):
                payload = strict_json_loads(row["payload_json"])
                if (
                    isinstance(payload, dict)
                    and payload.get("artifact_set_hash") == artifact_set_hash
                ):
                    matching_baselines.append(dict(row))
            if matching_baselines:
                return False
            context = self._reconstruct_artifact_context_from_approvals(
                artifact_set_hash
            )
            # Stored approvals that have already produced a replay must be
            # closed by a ReplayAdmission.  Context-only reconstruction is a
            # pre-replay staging state, never proof of a saved replay.
            if context is None or context.artifact_set_hash != artifact_set_hash:
                return False
            return not any(
                strict_json_loads(row["payload_json"]).get("applied_resolution")
                for row in self.connection.execute("SELECT payload_json FROM cases")
                if isinstance(strict_json_loads(row["payload_json"]), dict)
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _replay_admission_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        cache = getattr(self, "_verify_admission_cache", None)
        cache_key = entity.get("replay_admission_hash")
        if isinstance(cache, dict) and cache_key in cache:
            return bool(cache[cache_key])
        valid = self._replay_admission_entity_is_semantically_valid_uncached(entity)
        if isinstance(cache, dict) and isinstance(cache_key, str):
            cache[cache_key] = valid
        return valid

    def _replay_admission_entity_is_semantically_valid_uncached(
        self, entity: dict[str, Any]
    ) -> bool:
        required_payload_fields = {
            "replay_admission_hash",
            "contract_version",
            "resolution_id",
            "resolution_hash",
            "assurance_state",
            "artifact_set_hash",
            "controlled_reference_set_hash",
            "controlled_reference_source_set_hash",
            "pre_case",
            "before_case",
            "before_run",
            "after_case",
            "after_run",
            "approval_subject",
            "approval_subject_hash",
            "approved_patch_hash",
            "approval_refs",
            "baseline",
            "ruleset_versions",
            "artifact_contract_version",
            "reference_contract_version",
            "source_validation_evidence_set_hash",
            "resolved_validation_evidence_set_hash",
            "validation_evidence_pair_hash",
            "validation_evidence_contract_version",
            "validation_contract_version",
            "case_schema_version",
            "parser_contract_version",
            "mapping_contract_version",
            "security_root_policy_version",
        }
        try:
            payload = strict_json_loads(entity["payload_json"])
            resolution = strict_json_loads(entity["resolution_json"])
            admission_contract_version = (
                payload.get("contract_version")
                if isinstance(payload, dict)
                else None
            )
            a08 = (
                admission_contract_version
                == A08_REPLAY_ADMISSION_CONTRACT_VERSION
            )
            a06 = admission_contract_version in {
                A06_REPLAY_ADMISSION_CONTRACT_VERSION,
                A08_REPLAY_ADMISSION_CONTRACT_VERSION,
            }
            native = admission_contract_version in {
                A05_REPLAY_ADMISSION_CONTRACT_VERSION,
                A06_REPLAY_ADMISSION_CONTRACT_VERSION,
                A08_REPLAY_ADMISSION_CONTRACT_VERSION,
            }
            if native:
                required_payload_fields = required_payload_fields | {
                    "authorization_record_set_hash",
                    "approval_assertion_set_hash",
                    "execution_nonce",
                    "use_policy",
                }
            if a06:
                required_payload_fields = required_payload_fields | set(
                    _A06_AUTHENTICITY_REF_KEYS
                )
            if a08:
                required_payload_fields = required_payload_fields | {
                    "before_case_source",
                    "after_case_source",
                }
            if (
                not isinstance(payload, dict)
                or set(payload) != required_payload_fields
                or not isinstance(resolution, dict)
            ):
                return False
            canonical_resolution_bytes = self._canonical_resolution_bytes(resolution)
            if entity["resolution_json"] != canonical_resolution_bytes.decode("utf-8"):
                return False
            core = dict(payload)
            replay_admission_hash = core.pop("replay_admission_hash", None)
            admission_domain = (
                _A08_REPLAY_ADMISSION_DOMAIN
                if a08
                else (
                    _A06_REPLAY_ADMISSION_DOMAIN
                    if a06
                    else (
                        _A05_REPLAY_ADMISSION_DOMAIN
                        if native
                        else _REPLAY_ADMISSION_DOMAIN
                    )
                )
            )
            expected_subject_hash = (
                approval_subject_hash(payload["approval_subject"])
                if native
                else canonical_hash(payload["approval_subject"])
            )
            if (
                replay_admission_hash != entity["replay_admission_hash"]
                or replay_admission_hash
                != _domain_hash(admission_domain, _json(core).encode("utf-8"))
                or payload["contract_version"]
                not in {
                    REPLAY_ADMISSION_CONTRACT_VERSION,
                    A05_REPLAY_ADMISSION_CONTRACT_VERSION,
                    A06_REPLAY_ADMISSION_CONTRACT_VERSION,
                    A08_REPLAY_ADMISSION_CONTRACT_VERSION,
                }
                or payload["assurance_state"] != "ATTESTED_REPLACEMENT"
                or payload["resolution_id"] != entity["resolution_id"]
                or payload["artifact_set_hash"] != entity["artifact_set_hash"]
                or not _is_lower_hex(payload["controlled_reference_set_hash"], 64)
                or not _is_lower_hex(
                    payload["controlled_reference_source_set_hash"], 64
                )
                or not _is_lower_hex(
                    payload["source_validation_evidence_set_hash"], 64
                )
                or not _is_lower_hex(
                    payload["resolved_validation_evidence_set_hash"], 64
                )
                or not _is_lower_hex(payload["validation_evidence_pair_hash"], 64)
                or payload["validation_evidence_contract_version"]
                != VALIDATION_EVIDENCE_CONTRACT_VERSION
                or payload["validation_contract_version"]
                != VALIDATION_EVIDENCE_CONTRACT_VERSION
                or payload["pre_case"].get("case_hash")
                != entity["approved_case_hash"]
                or payload["resolution_hash"]
                != _domain_hash(_RESOLUTION_RECORD_DOMAIN, canonical_resolution_bytes)
                or payload["approval_subject_hash"]
                != expected_subject_hash
                or payload["approved_patch_hash"]
                != payload["approval_subject_hash"]
                or (
                    native
                    and (
                        payload["use_policy"] != APPROVAL_USE_POLICY
                        or payload["execution_nonce"]
                        != payload["approval_subject"]["execution_nonce"]
                        or not _is_lower_hex(
                            payload["authorization_record_set_hash"], 64
                        )
                        or not _is_lower_hex(
                            payload["approval_assertion_set_hash"], 64
                        )
                    )
                )
            ):
                return False
            pre_case = payload["pre_case"]
            row = self.connection.execute(
                "SELECT case_id,case_hash,synthetic,payload_json FROM cases "
                "WHERE case_id=? AND case_hash=?",
                (pre_case["case_id"], pre_case["case_hash"]),
            ).fetchone()
            if row is None or not self._case_entity_is_semantically_valid(dict(row)):
                return False
            approved_case = strict_json_loads(row["payload_json"])
            return self._rebuild_replay_admission_semantics(
                entity, payload, resolution, approved_case
            )
        except (
            ApprovalGateError,
            KeyError,
            TypeError,
            ValueError,
            sqlite3.Error,
        ):
            return False

    def _replay_ledger_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        cache = getattr(self, "_verify_replay_ledger_semantic_cache", None)
        if not isinstance(cache, dict):
            return self._replay_ledger_entity_is_semantically_valid_uncached(entity)
        try:
            key = self._verification_semantic_cache_key(entity)
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False
        if key not in cache:
            cache[key] = self._replay_ledger_entity_is_semantically_valid_uncached(
                entity
            )
        return bool(cache[key])

    def _replay_ledger_entity_is_semantically_valid_uncached(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            payload = strict_json_loads(entity["payload_json"])
            required_fields = {
                "contract_version",
                "replay_admission_hash",
                "assurance_state",
                "resolution_id",
                "artifact_set_hash",
                "controlled_reference_set_hash",
                "controlled_reference_source_set_hash",
                "source_validation_evidence_set_hash",
                "resolved_validation_evidence_set_hash",
                "validation_evidence_pair_hash",
                "approved_case_hash",
                "before_run",
                "after_case",
                "after_run",
                "baseline",
            }
            ledger_contract_version = (
                payload.get("contract_version")
                if isinstance(payload, dict)
                else None
            )
            a08 = ledger_contract_version == A08_REPLAY_LEDGER_CONTRACT_VERSION
            a06 = ledger_contract_version in {
                A06_REPLAY_LEDGER_CONTRACT_VERSION,
                A08_REPLAY_LEDGER_CONTRACT_VERSION,
            }
            native = ledger_contract_version in {
                A05_REPLAY_LEDGER_CONTRACT_VERSION,
                A06_REPLAY_LEDGER_CONTRACT_VERSION,
                A08_REPLAY_LEDGER_CONTRACT_VERSION,
            }
            if native:
                required_fields |= {
                    "approval_subject_hash",
                    "approval_assertion_set_hash",
                    "authorization_record_set_hash",
                    "execution_nonce",
                    "use_policy",
                    "consumption_hash",
                }
            if a06:
                required_fields |= {
                    *_A06_AUTHENTICITY_REF_KEYS,
                    "replay_authorization_authenticity_binding_hash",
                }
            if a08:
                required_fields |= {
                    "before_case_source",
                    "after_case_source",
                }
            if not isinstance(payload, dict) or set(payload) != required_fields:
                return False
            ledger_domain = (
                _A08_REPLAY_LEDGER_DOMAIN
                if a08
                else (
                    _A06_REPLAY_LEDGER_DOMAIN
                    if a06
                    else (
                        _A05_REPLAY_LEDGER_DOMAIN
                        if native
                        else _REPLAY_LEDGER_DOMAIN
                    )
                )
            )
            if (
                payload["contract_version"]
                not in {
                    REPLAY_LEDGER_CONTRACT_VERSION,
                    A05_REPLAY_LEDGER_CONTRACT_VERSION,
                    A06_REPLAY_LEDGER_CONTRACT_VERSION,
                    A08_REPLAY_LEDGER_CONTRACT_VERSION,
                }
                or payload["assurance_state"] != "ATTESTED_REPLACEMENT"
                or payload["replay_admission_hash"]
                != entity["replay_admission_hash"]
                or payload.get("consumption_hash")
                != entity["consumption_hash"]
                or payload["resolution_id"] != entity["resolution_id"]
                or payload["artifact_set_hash"] != entity["artifact_set_hash"]
                or payload["approved_case_hash"] != entity["approved_case_hash"]
                or payload["after_run"].get("run_id") != entity["after_run_id"]
                or entity["replay_ledger_hash"]
                != _domain_hash(
                    ledger_domain, entity["payload_json"].encode("utf-8")
                )
                or (native and payload["use_policy"] != APPROVAL_USE_POLICY)
            ):
                return False
            admission_row = self.connection.execute(
                "SELECT payload_json FROM replay_admissions "
                "WHERE replay_admission_hash=?",
                (entity["replay_admission_hash"],),
            ).fetchone()
            if admission_row is None:
                return False
            admission = strict_json_loads(admission_row["payload_json"])
            if not isinstance(admission, dict):
                return False
            if a08 and (
                admission.get("contract_version")
                != A08_REPLAY_ADMISSION_CONTRACT_VERSION
                or payload["before_case_source"]
                != admission.get("before_case_source")
                or payload["after_case_source"]
                != admission.get("after_case_source")
            ):
                return False
            if native:
                consumption_row = self.connection.execute(
                    "SELECT * FROM approval_consumptions WHERE consumption_hash=?",
                    (entity["consumption_hash"],),
                ).fetchone()
                if (
                    consumption_row is None
                    or not self._approval_consumption_entity_is_semantically_valid(
                        dict(consumption_row)
                    )
                    or payload["approval_subject_hash"]
                    != consumption_row["approval_subject_hash"]
                    or payload["approval_assertion_set_hash"]
                    != consumption_row["assertion_set_hash"]
                    or payload["authorization_record_set_hash"]
                    != consumption_row["authorization_record_set_hash"]
                ):
                    return False
            persistent_binding_hash = (
                payload["replay_authorization_authenticity_binding_hash"]
                if a06
                else None
            )
            if a06:
                binding_entity = (
                    self._replay_authorization_authenticity_binding_entity_for_hash(
                        persistent_binding_hash
                    )
                )
                if (
                    binding_entity is None
                    or binding_entity["replay_admission_hash"]
                    != entity["replay_admission_hash"]
                    or not self._replay_authorization_authenticity_binding_entity_is_semantically_valid(
                        binding_entity
                    )
                    or any(
                        payload.get(key)
                        != strict_json_loads(binding_entity["payload_json"]).get(
                            key
                        )
                        for key in _A06_AUTHENTICITY_REF_KEYS
                    )
                ):
                    return False
            expected = self._replay_ledger_entity(
                ReplayAdmission(
                    entity["replay_admission_hash"],
                    _json(admission).encode("utf-8"),
                ),
                consumption_hash=entity["consumption_hash"],
                replay_authorization_authenticity_binding_hash=(
                    persistent_binding_hash
                ),
            )
            if entity != expected:
                return False
            before_run = payload["before_run"]
            after_run = payload["after_run"]
            after_case = payload["after_case"]
            return all(
                self.connection.execute(query, values).fetchone() is not None
                for query, values in (
                    (
                        "SELECT 1 FROM runs WHERE run_id=?",
                        (before_run["run_id"],),
                    ),
                    (
                        "SELECT 1 FROM runs WHERE run_id=?",
                        (after_run["run_id"],),
                    ),
                    (
                        "SELECT 1 FROM cases WHERE case_id=? AND case_hash=?",
                        (after_case["case_id"], after_case["case_hash"]),
                    ),
                    (
                        "SELECT 1 FROM artifact_sets WHERE artifact_set_hash=?",
                        (payload["artifact_set_hash"],),
                    ),
                    (
                        "SELECT 1 FROM controlled_reference_sets WHERE reference_set_hash=?",
                        (payload["controlled_reference_source_set_hash"],),
                    ),
                )
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _replay_validation_binding_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        cache = getattr(
            self, "_verify_replay_validation_binding_semantic_cache", None
        )
        if not isinstance(cache, dict):
            return self._replay_validation_binding_is_semantically_valid_uncached(
                entity
            )
        try:
            key = self._verification_semantic_cache_key(entity)
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False
        if key not in cache:
            cache[key] = (
                self._replay_validation_binding_is_semantically_valid_uncached(
                    entity
                )
            )
        return bool(cache[key])

    def _replay_validation_binding_is_semantically_valid_uncached(
        self, entity: dict[str, Any]
    ) -> bool:
        required_payload_fields = {
            "contract_version",
            "resolution_id",
            "source_case_hash",
            "after_case_hash",
            "after_run_id",
            "source_evidence_set_hash",
            "source_case_subject_hash",
            "source_scope_digest",
            "resolved_evidence_set_hash",
            "resolved_case_subject_hash",
            "resolved_scope_digest",
            "evidence_pair_hash",
            "replay_admission_hash",
            "ruleset_version",
            "validation_contract_version",
        }
        try:
            payload = strict_json_loads(entity["payload_json"])
            if not isinstance(payload, dict) or set(payload) != required_payload_fields:
                return False
            binding_hash = _domain_hash(
                _REPLAY_VALIDATION_BINDING_DOMAIN,
                entity["payload_json"].encode("utf-8"),
            )
            if (
                binding_hash != entity["validation_binding_hash"]
                or payload["contract_version"]
                != REPLAY_VALIDATION_BINDING_CONTRACT_VERSION
                or payload["validation_contract_version"]
                != VALIDATION_EVIDENCE_CONTRACT_VERSION
                or any(
                    payload[field] != entity[field]
                    for field in (
                        "resolution_id",
                        "source_case_hash",
                        "after_case_hash",
                        "after_run_id",
                        "source_evidence_set_hash",
                        "resolved_evidence_set_hash",
                        "evidence_pair_hash",
                        "replay_admission_hash",
                    )
                )
            ):
                return False
            source_case_row = self.connection.execute(
                "SELECT payload_json FROM cases WHERE case_hash=?",
                (entity["source_case_hash"],),
            ).fetchone()
            after_case_row = self.connection.execute(
                "SELECT payload_json FROM cases WHERE case_hash=?",
                (entity["after_case_hash"],),
            ).fetchone()
            after_run_row = self.connection.execute(
                "SELECT payload_json FROM runs WHERE run_id=?",
                (entity["after_run_id"],),
            ).fetchone()
            admission_row = self.connection.execute(
                "SELECT payload_json FROM replay_admissions "
                "WHERE replay_admission_hash=?",
                (entity["replay_admission_hash"],),
            ).fetchone()
            if None in (
                source_case_row,
                after_case_row,
                after_run_row,
                admission_row,
            ):
                return False
            source_case = self._verify_stored_case_payload(
                source_case_row["payload_json"]
            )
            after_case = self._verify_stored_case_payload(
                after_case_row["payload_json"]
            )
            after_run = strict_json_loads(after_run_row["payload_json"])
            admission = strict_json_loads(admission_row["payload_json"])
            source_context = self._stored_validation_context(
                entity["source_evidence_set_hash"],
                source_case,
                "SOURCE",
                case_hash=entity["source_case_hash"],
            )
            resolved_context = self._stored_validation_context(
                entity["resolved_evidence_set_hash"],
                after_case,
                "RESOLVED",
                case_hash=entity["after_case_hash"],
            )
            return (
                payload["source_case_subject_hash"]
                == source_context.case_subject_hash
                and payload["source_scope_digest"] == source_context.scope_digest
                and payload["resolved_case_subject_hash"]
                == resolved_context.case_subject_hash
                and payload["resolved_scope_digest"]
                == resolved_context.scope_digest
                and payload["evidence_pair_hash"]
                == validation_evidence_pair_hash(
                    source_context, resolved_context
                )
                and after_run.get("validation_assurance_state")
                == VALIDATION_ASSURANCE_ATTESTED
                and after_run.get("validation_evidence_set_hash")
                == resolved_context.evidence_set_hash
                and admission.get("source_validation_evidence_set_hash")
                == source_context.evidence_set_hash
                and admission.get("resolved_validation_evidence_set_hash")
                == resolved_context.evidence_set_hash
                and admission.get("validation_evidence_pair_hash")
                == payload["evidence_pair_hash"]
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            StoreIntegrityError,
            sqlite3.Error,
        ):
            return False

    def _rebuild_replay_admission_semantics(
        self,
        entity: dict[str, Any],
        payload: dict[str, Any],
        resolution: dict[str, Any],
        approved_case: dict[str, Any],
    ) -> bool:
        if payload.get("contract_version") == (
            A08_REPLAY_ADMISSION_CONTRACT_VERSION
        ):
            (
                _root_bundle,
                _prior,
                current,
                before_context,
                after_context,
                stateless,
            ) = self._rebuild_a08_replay_from_source_payload(payload)
            replay = stateless.replay
            native_resolution = _native_resolution_from_bytes(
                current.native_resolution_bytes
            )
            if any(
                resolution.get(key) != value
                for key, value in native_resolution.items()
            ):
                return False
            subject_value = strict_json_loads(
                current.approval_subject_bytes.decode("utf-8")
            )
            if type(subject_value) is not dict:
                return False
            native_subject = validate_approval_subject(subject_value)
            assertions = _approval_assertions_from_bytes(
                current.approval_assertions_bytes
            )
            authenticity = prepare_authorization_authenticity_context(
                current.authorization_bundle,
                current.authorization_trust_bundle,
            )
            if authenticity.state != AUTHORIZATION_AUTHENTICITY_PASS:
                return False
            validation = validate_approval_assertions(
                native_subject,
                assertions,
                authenticity.record_context,
            )
            require_authenticated_assertion_records(assertions, authenticity)
            artifact_context = prepare_artifact_context(
                current.artifact_bundle,
                before_context.case(),
                native_resolution["operations"],
                _baseline_reference_context=before_context._reference_context,
            )
            expected_subject, legacy_subject = _source_subject_from_context(
                native_resolution,
                before_context,
                artifact_context,
                execution_nonce=native_subject["execution_nonce"],
            )
            validate_approval_subject(native_subject, expected=expected_subject)
            expected_resolution = {
                **native_resolution,
                "approvals": [
                    {
                        "role": role,
                        "decision": "APPROVED",
                        "case_id": legacy_subject["case_id"],
                        "event_id": legacy_subject["event_id"],
                        "event_revision": legacy_subject["event_revision"],
                        "approved_case_hash": legacy_subject[
                            "approved_case_hash"
                        ],
                        "approved_patch_hash": canonical_hash(legacy_subject),
                    }
                    for role in validation.approved_roles
                ],
            }
            if resolution != expected_resolution:
                return False
            assertion_set_hash = self._assertion_set_hash(
                validation.assertion_hashes
            )
            stateless_binding_hash = authorization_authenticity_binding_hash(
                approval_subject_hash=validation.approval_subject_hash,
                approval_assertion_set_hash=assertion_set_hash,
                authorization_authenticity_context_hash=(
                    authenticity.authorization_authenticity_context_hash
                ),
                after_case_hash=replay.after.case_hash,
                after_run_hash=canonical_hash(replay.after.to_dict()),
            )
            a06_refs = {
                "authorization_record_set_hash": (
                    authenticity.authorization_record_set_hash
                ),
                "authorization_record_set_contract_version": (
                    authenticity.authorization_record_set_contract_version
                ),
                "authorization_authenticity_state": authenticity.state,
                "authorization_authenticity_context_hash": (
                    authenticity.authorization_authenticity_context_hash
                ),
                "authorization_authenticity_binding_hash": (
                    stateless_binding_hash
                ),
                "authorization_trust_snapshot_hash": (
                    authenticity.trust_snapshot_hash
                ),
                "authorization_trust_snapshot_contract_version": (
                    authenticity.trust_snapshot_contract_version
                ),
                "authorization_trust_policy_hash": (
                    authenticity.trust_policy_hash
                ),
                "authorization_trust_policy_version": (
                    authenticity.trust_policy_version
                ),
            }
            if any(payload.get(key) != value for key, value in a06_refs.items()):
                return False
            native = _NativeApprovalPersistence(
                subject=native_subject,
                assertions=tuple(
                    validate_approval_assertion_shape(item)
                    for item in assertions
                ),
                authorization_bundle=current.authorization_bundle,
                authorization_context=authenticity.record_context,
                authorization_trust_bundle=(
                    current.authorization_trust_bundle
                ),
                authenticity_context=authenticity,
                a06_refs=tuple(sorted(a06_refs.items())),
            )
            expected_admission, expected_resolution_json = (
                self._build_replay_admission(
                    replay,
                    resolution,
                    before_context.case(),
                    after_context.case(),
                    legacy_subject,
                    artifact_context,
                    native_approval=native,
                    source_contexts=(before_context, after_context),
                )
            )
            expected_entity = self._replay_admission_entity(
                expected_admission,
                expected_resolution_json,
            )
            return (
                approved_case == before_context.case()
                and entity == expected_entity
                and self._replay_admission_links_match(
                    expected_entity,
                    replay,
                    resolution,
                    before_context.case(),
                    after_context.case(),
                    legacy_subject,
                )
            )
        bundle = self._load_artifact_bundle(payload["artifact_set_hash"])
        reference_bundle = self._load_controlled_reference_bundle(
            payload["controlled_reference_source_set_hash"]
        )
        identity_cache = getattr(self, "_verify_validation_identity_cache", None)
        source_identity = (
            identity_cache.get(payload["pre_case"]["case_hash"])
            if isinstance(identity_cache, dict)
            else None
        )
        resolved_identity = (
            identity_cache.get(payload["after_case"]["case_hash"])
            if isinstance(identity_cache, dict)
            else None
        )
        attested = _attest_approved_resolution(
            approved_case,
            resolution,
            artifact_bundle=bundle,
            reference_bundle=reference_bundle,
            _source_validation_identity=source_identity,
            _resolved_validation_identity=resolved_identity,
        )
        resolved_case = attested.resolved_case()
        source_validation_context = self._stored_validation_context(
            payload["source_validation_evidence_set_hash"],
            approved_case,
            "SOURCE",
            case_hash=payload["pre_case"]["case_hash"],
            _case_identity=attested.source_validation_identity,
        )
        resolved_validation_context = self._stored_validation_context(
            payload["resolved_validation_evidence_set_hash"],
            resolved_case,
            "RESOLVED",
            case_hash=payload["after_case"]["case_hash"],
            _case_identity=attested.resolved_validation_identity,
        )
        expected_replay = _replay_attested_resolution(
            approved_case,
            resolution,
            attested,
            source_validation_context=source_validation_context,
            resolved_validation_context=resolved_validation_context,
        )
        subject = attested.subject()
        native_approval: _NativeApprovalPersistence | None = None
        admission_contract_version = payload.get("contract_version")
        if admission_contract_version in {
            A05_REPLAY_ADMISSION_CONTRACT_VERSION,
            A06_REPLAY_ADMISSION_CONTRACT_VERSION,
        }:
            native_subject = validate_approval_subject(
                payload["approval_subject"]
            )
            native_resolution = {
                key: resolution[key]
                for key in NATIVE_RESOLUTION_KEYS
            }
            expected_native_subject = _native_subject_from_legacy_projection(
                native_resolution,
                subject,
                execution_nonce=native_subject["execution_nonce"],
            )
            validate_approval_subject(
                native_subject, expected=expected_native_subject
            )
            authorization_bundle = self._load_authorization_record_bundle(
                payload["authorization_record_set_hash"]
            )
            authorization_context = prepare_authorization_record_context(
                authorization_bundle
            )
            trust_bundle: AuthorizationTrustSnapshotBundle | None = None
            authenticity_context: AuthorizationAuthenticityContext | None = None
            a06_refs: tuple[tuple[str, str], ...] = ()
            if admission_contract_version == A06_REPLAY_ADMISSION_CONTRACT_VERSION:
                trust_bundle = self._load_authorization_trust_snapshot_bundle(
                    payload["authorization_trust_snapshot_hash"]
                )
                authenticity_context = self._stored_authorization_authenticity_context(
                    payload["authorization_record_set_hash"],
                    payload["authorization_trust_snapshot_hash"],
                )
                if (
                    authenticity_context.state != AUTHORIZATION_AUTHENTICITY_PASS
                    or authenticity_context.record_context != authorization_context
                ):
                    return False
                expected_context_refs = {
                    "authorization_record_set_hash": (
                        authenticity_context.authorization_record_set_hash
                    ),
                    "authorization_record_set_contract_version": (
                        authenticity_context.authorization_record_set_contract_version
                    ),
                    "authorization_authenticity_state": authenticity_context.state,
                    "authorization_authenticity_context_hash": (
                        authenticity_context.authorization_authenticity_context_hash
                    ),
                    "authorization_authenticity_binding_hash": (
                        authorization_authenticity_binding_hash(
                            approval_subject_hash=payload[
                                "approval_subject_hash"
                            ],
                            approval_assertion_set_hash=payload[
                                "approval_assertion_set_hash"
                            ],
                            authorization_authenticity_context_hash=(
                                authenticity_context.authorization_authenticity_context_hash
                            ),
                            after_case_hash=expected_replay.after.case_hash,
                            after_run_hash=canonical_hash(
                                expected_replay.after.to_dict()
                            ),
                        )
                    ),
                    "authorization_trust_snapshot_hash": (
                        authenticity_context.trust_snapshot_hash
                    ),
                    "authorization_trust_snapshot_contract_version": (
                        authenticity_context.trust_snapshot_contract_version
                    ),
                    "authorization_trust_policy_hash": (
                        authenticity_context.trust_policy_hash
                    ),
                    "authorization_trust_policy_version": (
                        authenticity_context.trust_policy_version
                    ),
                }
                if any(
                    payload.get(key) != value
                    for key, value in expected_context_refs.items()
                ):
                    return False
                a06_refs = tuple(sorted(expected_context_refs.items()))
            assertion_rows = self.connection.execute(
                "SELECT payload_json FROM approval_assertions "
                "WHERE approval_subject_hash=? ORDER BY assertion_hash",
                (payload["approval_subject_hash"],),
            ).fetchall()
            assertions = tuple(
                validate_approval_assertion_shape(
                    strict_json_loads(row["payload_json"])
                )
                for row in assertion_rows
            )
            validation = validate_approval_assertions(
                native_subject, assertions, authorization_context
            )
            if authenticity_context is not None:
                require_authenticated_assertion_records(
                    assertions,
                    authenticity_context,
                )
            if (
                validation.assertion_hashes
                != tuple(
                    sorted(item["assertion_hash"] for item in payload["approval_refs"])
                )
                or self._assertion_set_hash(validation.assertion_hashes)
                != payload["approval_assertion_set_hash"]
            ):
                return False
            native_approval = _NativeApprovalPersistence(
                subject=native_subject,
                assertions=assertions,
                authorization_bundle=authorization_bundle,
                authorization_context=authorization_context,
                authorization_trust_bundle=trust_bundle,
                authenticity_context=authenticity_context,
                a06_refs=a06_refs,
            )
        expected_admission, expected_resolution_json = self._build_replay_admission(
            expected_replay,
            resolution,
            approved_case,
            resolved_case,
            subject,
            attested.context,
            native_approval=native_approval,
        )
        expected_entity = self._replay_admission_entity(
            expected_admission, expected_resolution_json
        )
        return entity == expected_entity and self._replay_admission_links_match(
            expected_entity,
            expected_replay,
            resolution,
            approved_case,
            resolved_case,
            subject,
        )

    def verify_replay_admission_semantics(
        self, replay_admission_hash: str
    ) -> bool:
        row = self.connection.execute(
            """SELECT replay_admission_hash,resolution_id,artifact_set_hash,
                      approved_case_hash,resolution_json,payload_json
               FROM replay_admissions WHERE replay_admission_hash=?""",
            (replay_admission_hash,),
        ).fetchone()
        return row is not None and self._replay_admission_entity_is_semantically_valid(
            dict(row)
        )

    def export_replay_admission(self, replay_admission_hash: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT payload_json FROM replay_admissions WHERE replay_admission_hash=?",
            (replay_admission_hash,),
        ).fetchone()
        if row is None or not self.verify_audit_chain():
            raise StoreIntegrityError(
                "replay admission export requires intact audit and semantic closure"
            )
        payload = strict_json_loads(row["payload_json"])
        if not isinstance(payload, dict):
            raise StoreIntegrityError("stored replay admission payload is invalid")
        return payload

    def export_baseline(self, baseline_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT payload_json FROM baselines WHERE baseline_id=?", (baseline_id,)
        ).fetchone()
        if row is None or not self.verify_audit_chain():
            raise StoreIntegrityError(
                "baseline export requires intact audit and semantic closure"
            )
        payload = strict_json_loads(row["payload_json"])
        if not isinstance(payload, dict):
            raise StoreIntegrityError("stored baseline payload is invalid")
        return payload

    def _artifact_set_has_linked_baseline(self, artifact_set_hash: str) -> bool:
        try:
            for row in self.connection.execute("SELECT payload_json FROM baselines"):
                payload = strict_json_loads(row["payload_json"])
                if (
                    isinstance(payload, dict)
                    and payload.get("artifact_set_hash") == artifact_set_hash
                ):
                    return True
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False
        return False

    def _replay_admission_coverage_is_complete(self) -> bool:
        """After-case facts, ledger rows, and admissions must close exactly."""

        try:
            expected_cohorts: set[tuple[str, str, str]] = set()
            for case_row in self.connection.execute(
                "SELECT case_id,case_hash,synthetic,payload_json FROM cases"
            ):
                case_entity = dict(case_row)
                if not self._case_entity_is_semantically_valid(case_entity):
                    return False
                case = self._verify_stored_case_payload(
                    case_entity["payload_json"]
                )
                resolution_id = case.get("applied_resolution")
                if resolution_id is None:
                    continue
                if not isinstance(resolution_id, str) or not resolution_id.strip():
                    return False
                artifact_set_hashes: set[str] = set()
                for document in case.get("documents", []):
                    if not isinstance(document, dict):
                        return False
                    revision_artifact = document.get("revision_artifact")
                    if revision_artifact is None:
                        continue
                    if not isinstance(revision_artifact, dict):
                        return False
                    artifact_set_hash = revision_artifact.get("artifact_set_hash")
                    if not _is_lower_hex(artifact_set_hash, 64):
                        return False
                    artifact_set_hashes.add(artifact_set_hash)
                if len(artifact_set_hashes) != 1:
                    return False
                artifact_set_hash = next(iter(artifact_set_hashes))
                artifact_row = self.connection.execute(
                    "SELECT resolved_reference_set_hash,reference_contract_version "
                    "FROM artifact_sets WHERE artifact_set_hash=?",
                    (artifact_set_hash,),
                ).fetchone()
                if artifact_row is None:
                    return False
                binding_rows = self.connection.execute(
                    "SELECT * FROM replay_validation_bindings "
                    "WHERE after_case_hash=?",
                    (case_entity["case_hash"],),
                ).fetchall()
                if not binding_rows:
                    source_run_rows = self.connection.execute(
                        "SELECT r.run_id,r.case_id,r.status,r.ruleset_version,"
                        "r.payload_json FROM runs r "
                        "JOIN run_case_source_sets s ON s.run_id=r.run_id "
                        "WHERE r.case_id=? AND "
                        "json_extract(r.payload_json,'$.case_hash')=?",
                        (case_entity["case_id"], case_entity["case_hash"]),
                    ).fetchall()
                    if any(
                        self._source_run_entity_is_semantically_valid(
                            dict(run_row)
                        )
                        for run_row in source_run_rows
                    ):
                        continue
                    lineage_row = self.connection.execute(
                        "SELECT lineage_hash FROM case_lineage_bindings "
                        "WHERE output_case_hash=? AND operation_kind='NATIVE_REPLAY'",
                        (case_entity["case_hash"],),
                    ).fetchone()
                    used_as_prior = self.connection.execute(
                        "SELECT 1 FROM case_lineage_bindings "
                        "WHERE input_case_hash=? LIMIT 1",
                        (case_entity["case_hash"],),
                    ).fetchone()
                    if (
                        lineage_row is not None
                        and used_as_prior is not None
                        and self._case_lineage_entity_is_semantically_valid(
                            self._case_lineage_entity(
                                lineage_row["lineage_hash"]
                            )
                            or {}
                        )
                    ):
                        continue
                    return False
                if len(binding_rows) != 1:
                    return False
                binding = dict(binding_rows[0])
                if (
                    binding["resolution_id"] != resolution_id
                    or not self._replay_validation_binding_is_semantically_valid(
                        binding
                    )
                ):
                    return False
                admission_row = self.connection.execute(
                    "SELECT payload_json FROM replay_admissions "
                    "WHERE replay_admission_hash=?",
                    (binding["replay_admission_hash"],),
                ).fetchone()
                admission_payload = (
                    strict_json_loads(admission_row["payload_json"])
                    if admission_row is not None
                    else None
                )
                if (
                    type(admission_payload) is dict
                    and admission_payload.get("contract_version")
                    == A08_REPLAY_ADMISSION_CONTRACT_VERSION
                ):
                    after_run_id = binding["after_run_id"]
                    run_row = self.connection.execute(
                        "SELECT run_id,case_id,status,ruleset_version,payload_json "
                        "FROM runs WHERE run_id=?",
                        (after_run_id,),
                    ).fetchone()
                    if (
                        run_row is None
                        or not self._source_run_entity_is_semantically_valid(
                            dict(run_row)
                        )
                    ):
                        return False
                else:
                    after_run_id = binding["after_run_id"]
                    run_row = self.connection.execute(
                        "SELECT run_id,case_id,status,ruleset_version,payload_json "
                        "FROM runs WHERE run_id=?",
                        (after_run_id,),
                    ).fetchone()
                    if (
                        run_row is None
                        or not self._run_entity_is_semantically_valid(dict(run_row))
                    ):
                        return False
                if after_run_id != binding["after_run_id"]:
                    return False
                cohort = (resolution_id, artifact_set_hash, after_run_id)
                if cohort in expected_cohorts:
                    return False
                expected_cohorts.add(cohort)

            ledger_rows = [
                dict(row) for row in self.connection.execute("SELECT * FROM replay_ledger")
            ]
            ledger_cohorts = {
                (
                    row["resolution_id"],
                    row["artifact_set_hash"],
                    row["after_run_id"],
                )
                for row in ledger_rows
            }
            ledger_hashes = {
                row["replay_admission_hash"] for row in ledger_rows
            }
            admission_hashes = {
                row["replay_admission_hash"]
                for row in self.connection.execute(
                    "SELECT replay_admission_hash FROM replay_admissions"
                )
            }
            binding_rows = [
                dict(row)
                for row in self.connection.execute(
                    "SELECT * FROM replay_validation_bindings"
                )
            ]
            binding_admission_hashes = {
                row["replay_admission_hash"] for row in binding_rows
            }
            return (
                ledger_cohorts == expected_cohorts
                and ledger_hashes == admission_hashes
                and len(ledger_hashes) == len(ledger_rows)
                and binding_admission_hashes == admission_hashes
                and len(binding_rows) == len(expected_cohorts)
                and all(
                    self._replay_ledger_entity_is_semantically_valid(row)
                    for row in ledger_rows
                )
                and all(
                    self._replay_validation_binding_is_semantically_valid(row)
                    for row in binding_rows
                )
                and self._native_approval_coverage_is_complete(
                    expected_cohorts
                )
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _native_approval_coverage_is_complete(
        self, expected_cohorts: set[tuple[str, str, str]]
    ) -> bool:
        """Close every A05 sidecar from independent after-case replay facts."""

        try:
            native_admissions: dict[
                tuple[str, str, str], dict[str, Any]
            ] = {}
            for row in self.connection.execute(
                "SELECT resolution_id,artifact_set_hash,payload_json "
                "FROM replay_admissions"
            ):
                payload = strict_json_loads(row["payload_json"])
                if (
                    not isinstance(payload, dict)
                    or payload.get("contract_version")
                    not in {
                        A05_REPLAY_ADMISSION_CONTRACT_VERSION,
                        A06_REPLAY_ADMISSION_CONTRACT_VERSION,
                        A08_REPLAY_ADMISSION_CONTRACT_VERSION,
                    }
                ):
                    continue
                cohort = (
                    row["resolution_id"],
                    row["artifact_set_hash"],
                    payload["after_run"]["run_id"],
                )
                if cohort not in expected_cohorts or cohort in native_admissions:
                    return False
                native_admissions[cohort] = payload

            expectations = [
                dict(row)
                for row in self.connection.execute(
                    "SELECT * FROM replay_approval_expectations"
                )
            ]
            expectation_cohorts = {
                (
                    row["resolution_id"],
                    row["artifact_set_hash"],
                    row["after_run_id"],
                )
                for row in expectations
            }
            if (
                len(expectation_cohorts) != len(expectations)
                or expectation_cohorts != set(native_admissions)
                or expectation_cohorts != expected_cohorts
                or not all(
                    self._replay_approval_expectation_entity_is_semantically_valid(
                        row
                    )
                    for row in expectations
                )
            ):
                return False

            expected_subjects = {
                row["approval_subject_hash"] for row in expectations
            }
            expected_consumptions = {
                row["consumption_hash"] for row in expectations
            }
            expected_auth_sets = {
                row["authorization_record_set_hash"] for row in expectations
            }
            lineage_materials: list[dict[str, Any]] = []
            if self.feature_profile() == STORE_FEATURE_A08_0_1:
                for row in self.connection.execute(
                    "SELECT b.raw_bytes FROM case_lineage_bindings l "
                    "JOIN artifact_blobs b ON "
                    "b.source_hash=l.operation_material_source_hash "
                    "WHERE l.operation_kind='NATIVE_REPLAY'"
                ):
                    material = strict_json_loads(
                        bytes(row["raw_bytes"]).decode("utf-8")
                    )
                    if type(material) is not dict:
                        return False
                    lineage_materials.append(material)
            expected_subjects |= {
                item["approval_subject_hash"] for item in lineage_materials
            }
            expected_auth_sets |= {
                item["authorization_record_set_hash"]
                for item in lineage_materials
            }
            expected_baseline_bindings = {
                row["baseline_binding_hash"]
                for row in expectations
                if row["baseline_binding_hash"] is not None
            }
            actual_subjects = {
                row["approval_subject_hash"]
                for row in self.connection.execute(
                    "SELECT approval_subject_hash FROM approval_subjects"
                )
            }
            actual_consumptions = {
                row["consumption_hash"]
                for row in self.connection.execute(
                    "SELECT consumption_hash FROM approval_consumptions"
                )
            }
            actual_auth_sets = {
                row["record_set_hash"]
                for row in self.connection.execute(
                    "SELECT record_set_hash FROM authorization_record_sets"
                )
            }
            actual_baseline_bindings = {
                row["baseline_binding_hash"]
                for row in self.connection.execute(
                    "SELECT baseline_binding_hash FROM baseline_approval_bindings"
                )
            }
            assertion_subjects = {
                row["approval_subject_hash"]
                for row in self.connection.execute(
                    "SELECT approval_subject_hash FROM approval_assertions"
                )
            }
            a06_expectation_payloads = [
                strict_json_loads(row["payload_json"])
                for row in expectations
                if strict_json_loads(row["payload_json"]).get(
                    "contract_version"
                )
                == A06_REPLAY_APPROVAL_EXPECTATION_CONTRACT_VERSION
            ]
            expected_persistent_bindings = {
                payload[
                    "replay_authorization_authenticity_binding_hash"
                ]
                for payload in a06_expectation_payloads
            }
            expected_trust_snapshots = {
                payload["authorization_trust_snapshot_hash"]
                for payload in a06_expectation_payloads
            }
            expected_trust_snapshots |= {
                item["authorization_trust_snapshot_hash"]
                for item in lineage_materials
            }
            actual_binding_rows = [
                dict(row)
                for row in self.connection.execute(
                    "SELECT * FROM replay_authorization_authenticity_bindings"
                )
            ]
            actual_persistent_bindings = {
                row["replay_authorization_authenticity_binding_hash"]
                for row in actual_binding_rows
            }
            actual_snapshot_rows = [
                dict(row)
                for row in self.connection.execute(
                    "SELECT * FROM authorization_trust_snapshots"
                )
            ]
            actual_trust_snapshots = {
                row["trust_snapshot_hash"] for row in actual_snapshot_rows
            }
            return (
                actual_subjects == expected_subjects
                and actual_consumptions == expected_consumptions
                and actual_auth_sets == expected_auth_sets
                and actual_baseline_bindings == expected_baseline_bindings
                and assertion_subjects == expected_subjects
                and len(expected_persistent_bindings)
                == len(a06_expectation_payloads)
                and actual_persistent_bindings
                == expected_persistent_bindings
                and len(actual_binding_rows)
                == len(expected_persistent_bindings)
                and actual_trust_snapshots == expected_trust_snapshots
                and all(
                    self._replay_authorization_authenticity_binding_entity_is_semantically_valid(
                        row
                    )
                    for row in actual_binding_rows
                )
                and all(
                    self._authorization_trust_snapshot_entity_is_semantically_valid(
                        row
                    )
                    for row in actual_snapshot_rows
                )
                and all(
                    self._approval_consumption_entity_is_semantically_valid(
                        dict(row)
                    )
                    for row in self.connection.execute(
                        "SELECT * FROM approval_consumptions"
                    )
                )
                and all(
                    self._baseline_approval_binding_entity_is_semantically_valid(
                        dict(row)
                    )
                    for row in self.connection.execute(
                        "SELECT * FROM baseline_approval_bindings"
                    )
                )
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _reconstruct_artifact_context_from_approvals(
        self, artifact_set_hash: str
    ) -> ArtifactContext | None:
        """Re-attest a non-baselined set from stored bytes and stored approvals."""

        groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        for row in self.connection.execute("SELECT * FROM approvals"):
            entity = dict(row)
            if not self._approval_entity_is_semantically_valid(entity):
                continue
            payload = strict_json_loads(entity["payload_json"])
            artifact_subject = payload.get("artifact_subject")
            if (
                not isinstance(artifact_subject, dict)
                or artifact_subject.get("artifact_set_hash") != artifact_set_hash
            ):
                continue
            key = tuple(
                str(payload[field])
                for field in (
                    "resolution_id",
                    "case_id",
                    "event_id",
                    "event_revision",
                    "approved_case_hash",
                    "approved_patch_hash",
                )
            )
            groups.setdefault(key, []).append(payload)

        if not groups:
            return None
        bundle = self._load_artifact_bundle(artifact_set_hash)
        artifact_row = self.connection.execute(
            "SELECT controlled_reference_set_hash FROM artifact_sets WHERE artifact_set_hash=?",
            (artifact_set_hash,),
        ).fetchone()
        if artifact_row is None:
            return None
        reference_bundle = self._load_controlled_reference_bundle(
            artifact_row["controlled_reference_set_hash"]
        )
        for payloads in groups.values():
            first = payloads[0]
            if any(
                item["operations"] != first["operations"]
                or item["artifact_subject"] != first["artifact_subject"]
                or item["validation_policy"] != first["validation_policy"]
                for item in payloads[1:]
            ):
                continue
            case_row = self.connection.execute(
                "SELECT case_id,case_hash,synthetic,payload_json FROM cases "
                "WHERE case_id=? AND case_hash=?",
                (first["case_id"], first["approved_case_hash"]),
            ).fetchone()
            if case_row is None or not self._case_entity_is_semantically_valid(
                dict(case_row)
            ):
                continue
            case = strict_json_loads(case_row["payload_json"])
            approvals: list[dict[str, Any]] = []
            for item in payloads:
                approval = {
                    field: item[field]
                    for field in (
                        "role",
                        "decision",
                        "case_id",
                        "event_id",
                        "event_revision",
                        "approved_case_hash",
                        "approved_patch_hash",
                    )
                }
                if "comment" in item:
                    approval["comment"] = item["comment"]
                approvals.append(approval)
            resolution = {
                "resolution_id": first["resolution_id"],
                "replacement_set_id": first["artifact_subject"][
                    "replacement_set_id"
                ],
                "description": "reconstructed stored artifact approval subject",
                "operations": first["operations"],
                "approvals": approvals,
            }
            try:
                attested = _attest_approved_resolution(
                    case,
                    resolution,
                    artifact_bundle=bundle,
                    reference_bundle=reference_bundle,
                )
            except ApprovalGateError:
                continue
            if (
                attested.context.artifact_set_hash == artifact_set_hash
                and attested.context.subject_fields() == first["artifact_subject"]
            ):
                return attested.context
        return None

    def _case_entity_is_semantically_valid(self, entity: dict[str, Any]) -> bool:
        try:
            key = tuple(
                entity[field]
                for field in ("case_id", "case_hash", "synthetic", "payload_json")
            )
        except (KeyError, TypeError):
            return False
        cache = getattr(self, "_verify_case_semantic_cache", None)
        if isinstance(cache, dict) and key in cache:
            return cache[key]
        try:
            case = self._verify_stored_case_payload(entity["payload_json"])
            if not isinstance(case, dict):
                result = False
            else:
                validate_case(case)
                result = (
                    case.get("case_id") == entity["case_id"]
                    and canonical_hash(case) == entity["case_hash"]
                    and int(case.get("synthetic_for_competition") is True)
                    == entity["synthetic"]
                )
        except (KeyError, TypeError, ValueError):
            result = False
        if isinstance(cache, dict):
            cache[key] = result
        return result

    def _run_entity_is_semantically_valid(self, entity: dict[str, Any]) -> bool:
        try:
            key = tuple(
                entity[field]
                for field in (
                    "run_id",
                    "case_id",
                    "status",
                    "ruleset_version",
                    "payload_json",
                )
            )
        except (KeyError, TypeError):
            return False
        cache = getattr(self, "_verify_run_semantic_cache", None)
        if isinstance(cache, dict) and key in cache:
            return cache[key]
        result = self._run_entity_is_semantically_valid_uncached(entity)
        if isinstance(cache, dict):
            cache[key] = result
        return result

    def _run_entity_is_semantically_valid_uncached(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            payload = strict_json_loads(entity["payload_json"])
            if not isinstance(payload, dict):
                return False
            profile = _stored_run_payload_profile(payload)
            if profile is None:
                return False
            if (
                profile == _RUN_PROFILE_CURRENT_V4
                and payload.get("case_source_assurance_state")
                in {CASE_SOURCE_BOUND, CASE_SOURCE_DERIVED}
            ):
                return self._source_run_entity_is_semantically_valid(entity)
            if (
                profile == _RUN_PROFILE_CURRENT_V4
                and payload.get("case_source_assurance_state")
                != CASE_SOURCE_UNBOUND
            ):
                return False
            case_hash = payload.get("case_hash")
            if not isinstance(case_hash, str) or not case_hash:
                return False
            reference_row = self.connection.execute(
                "SELECT reference_set_hash FROM run_reference_sets WHERE run_id=?",
                (entity["run_id"],),
            ).fetchone()
            validation_row = self.connection.execute(
                "SELECT evidence_set_hash FROM run_validation_sets WHERE run_id=?",
                (entity["run_id"],),
            ).fetchone()
            linked_admissions = []
            for row in self.connection.execute(
                """SELECT replay_admission_hash,resolution_id,artifact_set_hash,
                          approved_case_hash,resolution_json,payload_json
                   FROM replay_admissions
                   WHERE json_extract(payload_json,'$.before_run.run_id')=?
                      OR json_extract(payload_json,'$.after_run.run_id')=?""",
                (entity["run_id"], entity["run_id"]),
            ):
                admission = strict_json_loads(row["payload_json"])
                if not isinstance(admission, dict):
                    return False
                expected_run = (
                    admission.get("before_run")
                    if admission.get("before_run", {}).get("run_id")
                    == entity["run_id"]
                    else admission.get("after_run")
                )
                if not isinstance(expected_run, dict):
                    return False
                linked_admissions.append((dict(row), expected_run))
            if linked_admissions:
                if len(linked_admissions) != 1:
                    return False
                if reference_row is not None:
                    return False
                admission_entity, expected_run = linked_admissions[0]
                expected_validation_set = expected_run.get(
                    "validation_evidence_set_hash"
                )
                if expected_run.get("validation_assurance_state") == "ATTESTED_VALIDATION_SET":
                    if (
                        validation_row is None
                        or validation_row["evidence_set_hash"]
                        != expected_validation_set
                        or not self._validation_evidence_set_is_semantically_valid(
                            expected_validation_set
                        )
                    ):
                        return False
                elif validation_row is not None:
                    return False
                return (
                    self._replay_admission_entity_is_semantically_valid(
                        admission_entity
                    )
                    and expected_run.get("run_id") == entity["run_id"]
                    and expected_run.get("case_id") == entity["case_id"]
                    and expected_run.get("status") == entity["status"]
                    and expected_run.get("run_hash") == canonical_hash(payload)
                )
            if self.feature_profile() == STORE_FEATURE_A08_0_1:
                source_link = self._run_case_source_set_entity(
                    entity["run_id"]
                )
                if profile == _RUN_PROFILE_CURRENT_V4:
                    if source_link != self._unbound_run_case_source_entity(
                        entity["run_id"]
                    ):
                        return False
                elif source_link is not None:
                    return False
            case_row = self.connection.execute(
                "SELECT case_id, case_hash, synthetic, payload_json "
                "FROM cases WHERE case_id=? AND case_hash=?",
                (entity["case_id"], case_hash),
            ).fetchone()
            if case_row is None:
                return False
            case_entity = dict(case_row)
            if not self._case_entity_is_semantically_valid(case_entity):
                return False
            case = strict_json_loads(case_entity["payload_json"])
            if reference_row is not None:
                reference_bundle = self._load_controlled_reference_bundle(
                    reference_row["reference_set_hash"]
                )
                validation_context = None
                if validation_row is not None:
                    validation_bundle = self._load_validation_evidence_bundle(
                        validation_row["evidence_set_hash"]
                    )
                    validation_context = _prepare_validation_evidence_context(
                        validation_bundle,
                        case,
                        expected_phase="SOURCE",
                    )
                expected = _run_case_with_reference_context(
                    case,
                    _prepare_controlled_reference_context(reference_bundle),
                    validation_context,
                )
            else:
                if validation_row is not None:
                    return False
                expected = run_case(case)
            expected_payload = (
                expected.to_dict()
                if profile == _RUN_PROFILE_CURRENT_V4
                else legacy_run_result_projection(expected)
            )
            return (
                entity["run_id"] == expected_payload["run_id"]
                and entity["case_id"] == expected_payload["case_id"]
                and entity["status"] == str(expected.overall_status)
                and entity["ruleset_version"] == expected.ruleset_version
                and entity["payload_json"] == _json(expected_payload)
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def _run_reference_set_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            if set(entity) != {"run_id", "reference_set_hash"}:
                return False
            run_row = self.connection.execute(
                "SELECT run_id,case_id,status,ruleset_version,payload_json "
                "FROM runs WHERE run_id=?",
                (entity["run_id"],),
            ).fetchone()
            reference_entity = self._controlled_reference_set_entity(
                entity["reference_set_hash"]
            )
            return (
                run_row is not None
                and reference_entity is not None
                and (
                    not self._run_is_linked_to_replay_admission(
                        entity["run_id"]
                    )
                    or self._a08_prior_locator_reference_link_is_valid(
                        entity["run_id"]
                    )
                )
                and self._controlled_reference_set_entity_is_semantically_valid(
                    reference_entity
                )
                and self._run_entity_is_semantically_valid(dict(run_row))
            )
        except (KeyError, TypeError, ValueError, StoreIntegrityError):
            return False

    def _run_validation_set_entity_is_semantically_valid(
        self, entity: dict[str, Any]
    ) -> bool:
        try:
            if set(entity) != {"run_id", "evidence_set_hash"}:
                return False
            run_row = self.connection.execute(
                "SELECT run_id,case_id,status,ruleset_version,payload_json "
                "FROM runs WHERE run_id=?",
                (entity["run_id"],),
            ).fetchone()
            return (
                run_row is not None
                and self._validation_evidence_set_is_semantically_valid(
                    entity["evidence_set_hash"]
                )
                and self._run_entity_is_semantically_valid(dict(run_row))
            )
        except (KeyError, TypeError, ValueError, StoreIntegrityError):
            return False

    def _approval_entity_is_semantically_valid(self, entity: dict[str, Any]) -> bool:
        required_payload_fields = {
            "resolution_id",
            "operations",
            "role",
            "decision",
            "case_id",
            "event_id",
            "event_revision",
            "approved_case_hash",
            "approved_patch_hash",
            "artifact_subject",
            "validation_policy",
        }
        allowed_payload_fields = required_payload_fields | {"comment"}
        try:
            payload = strict_json_loads(entity["payload_json"])
            if not isinstance(payload, dict):
                return False
            if set(payload) != required_payload_fields and not (
                set(payload) == allowed_payload_fields
                and isinstance(payload.get("comment"), str)
            ):
                return False
            for field in (
                "resolution_id",
                "case_id",
                "event_id",
                "event_revision",
                "approved_case_hash",
                "approved_patch_hash",
                "role",
                "decision",
            ):
                if payload[field] != entity[field] or not _is_nonempty_string(payload[field]):
                    return False
            if payload["role"] not in REQUIRED_APPROVAL_ROLES:
                return False
            if payload["decision"] != "APPROVED":
                return False
            if not _is_lower_hex(payload["approved_case_hash"], 64):
                return False
            if not _is_lower_hex(payload["approved_patch_hash"], 64):
                return False
            if not _resolution_operations_are_valid(payload["operations"]):
                return False

            case_row = self.connection.execute(
                "SELECT case_id, case_hash, synthetic, payload_json "
                "FROM cases WHERE case_id=? AND case_hash=?",
                (payload["case_id"], payload["approved_case_hash"]),
            ).fetchone()
            if case_row is None:
                return False
            case_entity = dict(case_row)
            if not self._case_entity_is_semantically_valid(case_entity):
                return False
            case = strict_json_loads(case_entity["payload_json"])
            event = case["event"]
            if (
                event.get("event_id") != payload["event_id"]
                or event.get("revision") != payload["event_revision"]
            ):
                return False
            artifact_subject = payload["artifact_subject"]
            if (
                not isinstance(artifact_subject, dict)
                or not _is_lower_hex(artifact_subject.get("artifact_set_hash"), 64)
            ):
                return False
            expected_subject = self._artifact_subject_from_stored_index(
                artifact_subject["artifact_set_hash"]
            )
            if expected_subject is None or expected_subject != artifact_subject:
                return False
            admission_rows = self.connection.execute(
                "SELECT payload_json FROM replay_admissions "
                "WHERE resolution_id=? AND artifact_set_hash=? "
                "AND approved_case_hash=?",
                (
                    payload["resolution_id"],
                    artifact_subject["artifact_set_hash"],
                    payload["approved_case_hash"],
                ),
            ).fetchall()
            if len(admission_rows) != 1:
                return False
            admission_payload = strict_json_loads(
                admission_rows[0]["payload_json"]
            )
            after_identity = admission_payload["after_case"]
            after_case_row = self.connection.execute(
                "SELECT case_id,case_hash,synthetic,payload_json FROM cases "
                "WHERE case_id=? AND case_hash=?",
                (after_identity["case_id"], after_identity["case_hash"]),
            ).fetchone()
            if after_case_row is None or not self._case_entity_is_semantically_valid(
                dict(after_case_row)
            ):
                return False
            resolved_case = strict_json_loads(after_case_row["payload_json"])
            source_set_hash = admission_payload[
                "source_validation_evidence_set_hash"
            ]
            resolved_set_hash = admission_payload[
                "resolved_validation_evidence_set_hash"
            ]
            if (
                not self._validation_evidence_set_is_semantically_valid(
                    source_set_hash
                )
                or not self._validation_evidence_set_is_semantically_valid(
                    resolved_set_hash
                )
            ):
                return False
            source_context = self._stored_validation_context(
                source_set_hash,
                case,
                "SOURCE",
                case_hash=payload["approved_case_hash"],
            )
            resolved_context = self._stored_validation_context(
                resolved_set_hash,
                resolved_case,
                "RESOLVED",
                case_hash=after_identity["case_hash"],
            )
            expected_validation_policy = {
                "contract_version": VALIDATION_APPROVAL_POLICY_VERSION,
                "validation_evidence_contract_version": (
                    VALIDATION_EVIDENCE_CONTRACT_VERSION
                ),
                "required_phases": ["SOURCE", "RESOLVED"],
                "source_case_subject_hash": source_context.case_subject_hash,
                "source_scope_digest": source_context.scope_digest,
                "resolved_case_subject_hash": resolved_context.case_subject_hash,
                "resolved_scope_digest": resolved_context.scope_digest,
            }
            if (
                payload["validation_policy"] != expected_validation_policy
                or expected_validation_policy.get("contract_version")
                != VALIDATION_APPROVAL_POLICY_VERSION
            ):
                return False
            expected_patch_hash = resolution_patch_hash_for_subject(
                {
                    "resolution_id": payload["resolution_id"],
                    "operations": payload["operations"],
                },
                case_id=payload["case_id"],
                event_id=payload["event_id"],
                event_revision=payload["event_revision"],
                approved_case_hash=payload["approved_case_hash"],
                artifact_subject=payload["artifact_subject"],
                validation_policy=payload["validation_policy"],
            )
            return expected_patch_hash == payload["approved_patch_hash"]
        except (KeyError, TypeError, ValueError, RevisionArtifactError, sqlite3.Error):
            return False

    def _baseline_entity_is_semantically_valid(self, entity: dict[str, Any]) -> bool:
        required_payload_fields = {
            "baseline_id",
            "case_id",
            "source_run_id",
            "case_hash",
            "ruleset_version",
            "resolution_id",
            "approved_case_hash",
            "approved_event_id",
            "approved_event_revision",
            "approved_patch_hash",
            "approved_roles",
            "artifact_set_hash",
            "controlled_reference_set_hash",
            "reference_contract_version",
            "source_validation_evidence_set_hash",
            "resolved_validation_evidence_set_hash",
            "validation_evidence_pair_hash",
            "validation_evidence_contract_version",
            "artifact_contract_version",
            "case_schema_version",
            "parser_contract_version",
            "mapping_contract_version",
            "security_root_policy_version",
            "touched_document_artifacts",
            "status",
        }
        try:
            payload = strict_json_loads(entity["payload_json"])
            if not isinstance(payload, dict) or set(payload) != required_payload_fields:
                return False
            if (
                payload["baseline_id"] != entity["baseline_id"]
                or payload["case_id"] != entity["case_id"]
                or payload["source_run_id"] != entity["source_run_id"]
            ):
                return False
            for field in (
                "baseline_id",
                "case_id",
                "source_run_id",
                "case_hash",
                "ruleset_version",
                "resolution_id",
                "approved_case_hash",
                "approved_event_id",
                "approved_event_revision",
                "approved_patch_hash",
                "artifact_set_hash",
                "controlled_reference_set_hash",
                "reference_contract_version",
                "source_validation_evidence_set_hash",
                "resolved_validation_evidence_set_hash",
                "validation_evidence_pair_hash",
                "validation_evidence_contract_version",
                "artifact_contract_version",
                "case_schema_version",
                "parser_contract_version",
                "mapping_contract_version",
                "security_root_policy_version",
                "status",
            ):
                if not _is_nonempty_string(payload[field]):
                    return False
            if not _is_lower_hex(payload["baseline_id"], 16):
                return False
            if not _is_lower_hex(payload["source_run_id"], 16):
                return False
            for field in ("case_hash", "approved_case_hash", "approved_patch_hash"):
                if not _is_lower_hex(payload[field], 64):
                    return False
            if not _is_lower_hex(payload["artifact_set_hash"], 64):
                return False
            if not _is_lower_hex(payload["controlled_reference_set_hash"], 64):
                return False
            touched_artifacts = payload["touched_document_artifacts"]
            if not isinstance(touched_artifacts, list) or not touched_artifacts:
                return False
            if payload["status"] != "BASELINED":
                return False
            approved_roles = payload["approved_roles"]
            if (
                not isinstance(approved_roles, list)
                or not approved_roles
                or approved_roles != sorted(set(approved_roles))
                or any(role not in REQUIRED_APPROVAL_ROLES for role in approved_roles)
            ):
                return False

            before_case_row = self.connection.execute(
                "SELECT case_id, case_hash, synthetic, payload_json "
                "FROM cases WHERE case_id=? AND case_hash=?",
                (payload["case_id"], payload["approved_case_hash"]),
            ).fetchone()
            after_case_row = self.connection.execute(
                "SELECT case_id, case_hash, synthetic, payload_json "
                "FROM cases WHERE case_id=? AND case_hash=?",
                (payload["case_id"], payload["case_hash"]),
            ).fetchone()
            if before_case_row is None or after_case_row is None:
                return False
            before_case_entity = dict(before_case_row)
            after_case_entity = dict(after_case_row)
            if not self._case_entity_is_semantically_valid(before_case_entity):
                return False
            if not self._case_entity_is_semantically_valid(after_case_entity):
                return False
            before_case = strict_json_loads(before_case_entity["payload_json"])
            after_case = strict_json_loads(after_case_entity["payload_json"])
            before_event = before_case["event"]
            if (
                before_event.get("event_id") != payload["approved_event_id"]
                or before_event.get("revision") != payload["approved_event_revision"]
                or after_case.get("applied_resolution") != payload["resolution_id"]
            ):
                return False

            run_row = self.connection.execute(
                "SELECT run_id, case_id, status, ruleset_version, payload_json "
                "FROM runs WHERE run_id=?",
                (payload["source_run_id"],),
            ).fetchone()
            if run_row is None:
                return False
            run_entity = dict(run_row)
            if not self._run_entity_is_semantically_valid(run_entity):
                return False
            run_payload = strict_json_loads(run_entity["payload_json"])
            if (
                run_entity["status"] != "PASS"
                or run_entity["case_id"] != payload["case_id"]
                or run_entity["ruleset_version"] != payload["ruleset_version"]
                or run_payload.get("case_hash") != payload["case_hash"]
            ):
                return False

            approval_rows = self.connection.execute(
                """SELECT resolution_id, case_id, event_id, event_revision,
                          approved_case_hash, approved_patch_hash, role, decision, payload_json
                   FROM approvals
                   WHERE resolution_id=? AND case_id=? AND event_id=?
                     AND event_revision=? AND approved_case_hash=?
                     AND approved_patch_hash=? AND decision='APPROVED'""",
                (
                    payload["resolution_id"],
                    payload["case_id"],
                    payload["approved_event_id"],
                    payload["approved_event_revision"],
                    payload["approved_case_hash"],
                    payload["approved_patch_hash"],
                ),
            ).fetchall()
            if not approval_rows:
                return False
            approval_payloads: list[dict[str, Any]] = []
            for approval_row in approval_rows:
                approval_entity = dict(approval_row)
                if not self._approval_entity_is_semantically_valid(approval_entity):
                    return False
                approval_payload = strict_json_loads(approval_entity["payload_json"])
                approval_payloads.append(approval_payload)
            matched_roles = sorted(item["role"] for item in approval_payloads)
            if matched_roles != approved_roles:
                return False
            if (
                before_event.get("risk_level") == "HIGH"
                and not REQUIRED_APPROVAL_ROLES.issubset(set(matched_roles))
            ):
                return False
            operations = approval_payloads[0]["operations"]
            if any(item["operations"] != operations for item in approval_payloads[1:]):
                return False
            artifact_subject = approval_payloads[0]["artifact_subject"]
            if (
                any(item["artifact_subject"] != artifact_subject for item in approval_payloads[1:])
                or artifact_subject.get("artifact_set_hash") != payload["artifact_set_hash"]
                or artifact_subject.get("controlled_reference_set_hash")
                != payload["controlled_reference_set_hash"]
                or artifact_subject.get("reference_contract_version")
                != payload["reference_contract_version"]
                or artifact_subject.get("touched_document_artifacts")
                != payload["touched_document_artifacts"]
            ):
                return False
            approval_records = []
            for item in approval_payloads:
                record = {
                    key: item[key]
                    for key in (
                        "role",
                        "decision",
                        "case_id",
                        "event_id",
                        "event_revision",
                        "approved_case_hash",
                        "approved_patch_hash",
                    )
                }
                if "comment" in item:
                    record["comment"] = item["comment"]
                approval_records.append(record)
            reconstructed_resolution = {
                "resolution_id": payload["resolution_id"],
                "replacement_set_id": artifact_subject["replacement_set_id"],
                "description": "reconstructed stored approval subject",
                "operations": operations,
                "approvals": approval_records,
            }
            stored_bundle = self._load_artifact_bundle(payload["artifact_set_hash"])
            artifact_row = self.connection.execute(
                "SELECT controlled_reference_set_hash FROM artifact_sets WHERE artifact_set_hash=?",
                (payload["artifact_set_hash"],),
            ).fetchone()
            if artifact_row is None:
                return False
            stored_reference_bundle = self._load_controlled_reference_bundle(
                artifact_row["controlled_reference_set_hash"]
            )
            try:
                reconstructed_case, reconstructed_roles, reconstructed_context = apply_approved_resolution(
                    before_case,
                    reconstructed_resolution,
                    artifact_bundle=stored_bundle,
                    reference_bundle=stored_reference_bundle,
                )
            except (ApprovalGateError, StoreIntegrityError):
                return False
            if (
                list(reconstructed_roles) != approved_roles
                or reconstructed_context.artifact_set_hash != payload["artifact_set_hash"]
                or _json(reconstructed_case) != after_case_entity["payload_json"]
            ):
                return False
            expected_artifact_subject = reconstructed_context.subject_fields()
            if artifact_subject != expected_artifact_subject:
                return False
            for field in (
                "artifact_set_hash",
                "controlled_reference_set_hash",
                "reference_contract_version",
                "artifact_contract_version",
                "case_schema_version",
                "parser_contract_version",
                "mapping_contract_version",
                "security_root_policy_version",
                "touched_document_artifacts",
            ):
                if payload[field] != expected_artifact_subject[field]:
                    return False
            expected_baseline_id = hashlib.sha256(
                (
                    f"{payload['source_run_id']}:{payload['resolution_id']}:"
                    f"{payload['approved_patch_hash']}:{canonical_hash(tuple(approved_roles))}"
                ).encode("utf-8")
            ).hexdigest()[:16]
            return expected_baseline_id == payload["baseline_id"]
        except (KeyError, TypeError, ValueError):
            return False

    def verify_audit_chain(self, *, _semantic: bool = True) -> bool:
        semantic_cache_names = (
            "_verify_validation_evidence_semantic_cache",
            "_verify_approval_consumption_semantic_cache",
            "_verify_baseline_binding_semantic_cache",
            "_verify_replay_expectation_semantic_cache",
            "_verify_replay_ledger_semantic_cache",
            "_verify_replay_validation_binding_semantic_cache",
        )
        missing_cache = object()
        previous_semantic_caches = {
            name: getattr(self, name, missing_cache)
            for name in semantic_cache_names
        }
        previous_cache = getattr(self, "_verify_admission_cache", None)
        previous_validation_cache = getattr(
            self, "_verify_validation_context_cache", None
        )
        previous_run_cache = getattr(self, "_verify_run_semantic_cache", None)
        previous_case_cache = getattr(self, "_verify_case_semantic_cache", None)
        previous_validation_identity_cache = getattr(
            self, "_verify_validation_identity_cache", None
        )
        previous_authorization_context_cache = getattr(
            self, "_verify_authorization_context_cache", None
        )
        previous_authorization_snapshot_cache = getattr(
            self, "_verify_authorization_snapshot_cache", None
        )
        previous_authorization_binding_cache = getattr(
            self, "_verify_authorization_binding_cache", None
        )
        previous_case_payload_cache = getattr(
            self, "_verify_case_payload_cache", missing_cache
        )
        self._verify_admission_cache = {}
        self._verify_validation_context_cache = {}
        self._verify_run_semantic_cache = {}
        self._verify_case_semantic_cache = {}
        self._verify_validation_identity_cache = {}
        self._verify_authorization_context_cache = {}
        self._verify_authorization_snapshot_cache = {}
        self._verify_authorization_binding_cache = {}
        self._verify_case_payload_cache = {} if _semantic else None
        for name in semantic_cache_names:
            setattr(self, name, {} if _semantic else None)
        try:
            result = self._verify_audit_chain_impl(_semantic=_semantic)
            if result and _semantic:
                try:
                    if any(
                        not _is_exact_json_value(value)
                        or _json(value) != payload_json
                        for payload_json, value in (
                            self._verify_case_payload_cache.items()
                        )
                    ):
                        return False
                except (TypeError, ValueError):
                    return False
            return result
        finally:
            if previous_cache is None:
                del self._verify_admission_cache
            else:
                self._verify_admission_cache = previous_cache
            if previous_validation_cache is None:
                del self._verify_validation_context_cache
            else:
                self._verify_validation_context_cache = previous_validation_cache
            if previous_run_cache is None:
                del self._verify_run_semantic_cache
            else:
                self._verify_run_semantic_cache = previous_run_cache
            if previous_case_cache is None:
                del self._verify_case_semantic_cache
            else:
                self._verify_case_semantic_cache = previous_case_cache
            if previous_validation_identity_cache is None:
                del self._verify_validation_identity_cache
            else:
                self._verify_validation_identity_cache = (
                    previous_validation_identity_cache
                )
            if previous_authorization_context_cache is None:
                del self._verify_authorization_context_cache
            else:
                self._verify_authorization_context_cache = (
                    previous_authorization_context_cache
                )
            if previous_authorization_snapshot_cache is None:
                del self._verify_authorization_snapshot_cache
            else:
                self._verify_authorization_snapshot_cache = (
                    previous_authorization_snapshot_cache
                )
            if previous_authorization_binding_cache is None:
                del self._verify_authorization_binding_cache
            else:
                self._verify_authorization_binding_cache = (
                    previous_authorization_binding_cache
                )
            if previous_case_payload_cache is missing_cache:
                del self._verify_case_payload_cache
            else:
                self._verify_case_payload_cache = previous_case_payload_cache
            for name, previous in previous_semantic_caches.items():
                if previous is missing_cache:
                    delattr(self, name)
                else:
                    setattr(self, name, previous)

    def _verify_stored_case_payload(self, payload_json: str) -> Any:
        """Strictly parse a stored Case once within one semantic verify call."""

        cache = getattr(self, "_verify_case_payload_cache", None)
        if not isinstance(cache, dict):
            return strict_json_loads(payload_json)
        if payload_json not in cache:
            cache[payload_json] = strict_json_loads(payload_json)
        return cache[payload_json]

    def _verify_audit_chain_impl(self, *, _semantic: bool = True) -> bool:
        rows = self.connection.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        if not rows:
            return False

        previous_hash = "GENESIS"
        audited_keys: dict[str, set[tuple[Any, ...]]] = {
            "cases": set(),
            "runs": set(),
            "run_reference_sets": set(),
            "run_validation_sets": set(),
            "approvals": set(),
            "baselines": set(),
            "artifact_sets": set(),
            "controlled_reference_sets": set(),
            "validation_evidence_sets": set(),
            "replay_admissions": set(),
            "replay_ledger": set(),
            "replay_validation_bindings": set(),
            "authorization_record_sets": set(),
            "authorization_trust_snapshots": set(),
            "replay_authorization_authenticity_bindings": set(),
            "approval_subjects": set(),
            "approval_assertions": set(),
            "approval_consumptions": set(),
            "replay_approval_expectations": set(),
            "baseline_approval_bindings": set(),
        }
        if self.feature_profile() == STORE_FEATURE_A08_0_1:
            audited_keys["case_source_sets"] = set()
            audited_keys["case_lineage_bindings"] = set()
            audited_keys["run_case_source_sets"] = set()
        expected_sequence = 1
        for row in rows:
            if row["sequence"] != expected_sequence or row["previous_hash"] != previous_hash:
                return False
            seed = "|".join(
                (
                    row["previous_hash"],
                    row["created_at"],
                    row["entity_type"],
                    row["entity_id"],
                    row["action"],
                    row["payload_json"],
                )
            )
            event_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()
            if event_hash != row["event_hash"]:
                return False
            try:
                audit_payload = json.loads(row["payload_json"])
                primary_key = audit_payload["primary_key"]
                expected_fingerprint = audit_payload["entity_fingerprint"]
            except (json.JSONDecodeError, KeyError, TypeError):
                return False
            entity = self._entity_for_audit(row["action"], primary_key)
            if entity is None:
                return False
            table, key, current = entity
            if table == "cases":
                expected_header = ("case", f"{key[0]}@{key[1]}")
            elif table == "runs":
                expected_header = ("run", str(key[0]))
            elif table == "run_reference_sets":
                expected_header = ("run_reference_set", str(key[0]))
            elif table == "run_validation_sets":
                expected_header = ("run_validation_set", str(key[0]))
            elif table == "approvals":
                expected_header = (
                    "approval",
                    f"{key[0]}@{key[1]}@{key[2]}@{key[3]}@{key[4]}@{key[5]}",
                )
            elif table == "baselines":
                expected_header = ("baseline", str(key[0]))
            elif table == "artifact_sets":
                expected_header = ("artifact_set", str(key[0]))
            elif table == "controlled_reference_sets":
                expected_header = ("controlled_reference_set", str(key[0]))
            elif table == "validation_evidence_sets":
                expected_header = ("validation_evidence_set", str(key[0]))
            elif table == "case_source_sets":
                expected_header = ("case_source_set", str(key[0]))
            elif table == "case_lineage_bindings":
                expected_header = ("case_lineage_binding", str(key[0]))
            elif table == "run_case_source_sets":
                expected_header = ("run_case_source_set", str(key[0]))
            elif table == "replay_admissions":
                expected_header = ("replay_admission", str(key[0]))
            elif table == "replay_validation_bindings":
                expected_header = ("replay_validation_binding", str(key[0]))
            elif table == "authorization_record_sets":
                expected_header = ("authorization_record_set", str(key[0]))
            elif table == "authorization_trust_snapshots":
                expected_header = ("authorization_trust_snapshot", str(key[0]))
            elif table == "replay_authorization_authenticity_bindings":
                expected_header = (
                    "replay_authorization_authenticity_binding",
                    str(key[0]),
                )
            elif table == "approval_subjects":
                expected_header = ("approval_subject", str(key[0]))
            elif table == "approval_assertions":
                expected_header = ("approval_assertion", str(key[0]))
            elif table == "approval_consumptions":
                expected_header = ("approval_consumption", str(key[0]))
            elif table == "replay_approval_expectations":
                expected_header = ("replay_approval_expectation", str(key[0]))
            elif table == "baseline_approval_bindings":
                expected_header = ("baseline_approval_binding", str(key[0]))
            else:
                expected_header = ("replay_ledger", str(key[0]))
            if (row["entity_type"], row["entity_id"]) != expected_header:
                return False
            if key in audited_keys[table] or _fingerprint(current) != expected_fingerprint:
                return False
            if _semantic and table == "cases" and not self._case_entity_is_semantically_valid(current):
                return False
            if _semantic and table == "runs" and not self._run_entity_is_semantically_valid(current):
                return False
            if (
                _semantic
                and table == "run_reference_sets"
                and not self._run_reference_set_entity_is_semantically_valid(current)
            ):
                return False
            if (
                _semantic
                and table == "run_validation_sets"
                and not self._run_validation_set_entity_is_semantically_valid(current)
            ):
                return False
            if _semantic and table == "approvals" and not self._approval_entity_is_semantically_valid(current):
                return False
            if (
                _semantic
                and table == "baselines"
                and not self.connection.execute(
                    "SELECT 1 FROM replay_admissions WHERE json_extract(payload_json, '$.baseline.baseline_id')=?",
                    (current["baseline_id"],),
                ).fetchone()
                and not self._baseline_entity_is_semantically_valid(current)
            ):
                return False
            if _semantic and table == "artifact_sets" and not self._artifact_set_entity_is_semantically_valid(
                current,
                validate_linked_baselines=False,
            ):
                return False
            if (
                _semantic
                and table == "controlled_reference_sets"
                and not self._controlled_reference_set_entity_is_semantically_valid(current)
            ):
                return False
            if (
                _semantic
                and table == "validation_evidence_sets"
                and not self._validation_evidence_set_is_semantically_valid(
                    current["evidence_set_hash"]
                )
            ):
                return False
            if (
                _semantic
                and table == "case_source_sets"
                and not self._case_source_set_entity_is_semantically_valid(current)
            ):
                return False
            if (
                _semantic
                and table == "case_lineage_bindings"
                and not self._case_lineage_entity_is_semantically_valid(current)
            ):
                return False
            if (
                _semantic
                and table == "run_case_source_sets"
                and not self._run_case_source_set_entity_is_semantically_valid(
                    current
                )
            ):
                return False
            if (
                _semantic
                and table == "replay_admissions"
                and not self._replay_admission_entity_is_semantically_valid(current)
            ):
                return False
            if (
                _semantic
                and table == "replay_ledger"
                and not self._replay_ledger_entity_is_semantically_valid(current)
            ):
                return False
            if (
                _semantic
                and table == "replay_validation_bindings"
                and not self._replay_validation_binding_is_semantically_valid(current)
            ):
                return False
            if (
                _semantic
                and table == "authorization_record_sets"
                and not self._authorization_record_set_entity_is_semantically_valid(
                    current
                )
            ):
                return False
            if (
                _semantic
                and table == "authorization_trust_snapshots"
                and not self._authorization_trust_snapshot_entity_is_semantically_valid(
                    current
                )
            ):
                return False
            if (
                _semantic
                and table == "replay_authorization_authenticity_bindings"
                and not self._replay_authorization_authenticity_binding_entity_is_semantically_valid(
                    current
                )
            ):
                return False
            if (
                _semantic
                and table == "approval_subjects"
                and not self._approval_subject_entity_is_semantically_valid(current)
            ):
                return False
            if (
                _semantic
                and table == "approval_assertions"
                and not self._approval_assertion_entity_is_semantically_valid(current)
            ):
                return False
            if (
                _semantic
                and table == "approval_consumptions"
                and not self._approval_consumption_entity_is_semantically_valid(
                    current
                )
            ):
                return False
            if (
                _semantic
                and table == "replay_approval_expectations"
                and not self._replay_approval_expectation_entity_is_semantically_valid(
                    current
                )
            ):
                return False
            if (
                _semantic
                and table == "baseline_approval_bindings"
                and not self._baseline_approval_binding_entity_is_semantically_valid(
                    current
                )
            ):
                return False
            audited_keys[table].add(key)
            previous_hash = row["event_hash"]
            expected_sequence += 1

        return (
            audited_keys == self._business_keys()
            and (not _semantic or self._case_source_coverage_is_complete())
            and (not _semantic or self._replay_admission_coverage_is_complete())
        )
