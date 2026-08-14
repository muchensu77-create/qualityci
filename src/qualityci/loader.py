from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import unicodedata
from datetime import date, datetime
from pathlib import Path
from typing import Any


REQUIRED_DOCUMENT_TYPES = {
    "PROCESS_FLOW",
    "PFMEA",
    "CONTROL_PLAN",
    "SOP",
    "INSPECTION_RECORD",
}

EVENT_TYPES = {"ENGINEERING_CHANGE", "QUALITY_EVENT"}
RISK_LEVELS = {"LOW", "MEDIUM", "HIGH"}
DOCUMENT_STATUSES = {"DRAFT", "APPROVED", "SUPERSEDED"}
APPROVAL_DECISIONS = {"APPROVED", "REJECTED", "CHANGES_REQUESTED"}
VALIDATION_RESULTS = {"PASS", "FAIL", "PENDING"}

# Public ingestion limits.  File limits protect disk-backed inputs while the
# collection limits also protect callers that construct cases in memory.
MAX_JSON_FILE_BYTES = 5 * 1024 * 1024
MAX_SOURCE_ANCHOR_CHARACTERS = 256
MAX_DOCUMENTS = 1_024
MAX_EVENT_AFFECTED_ITEMS = 10_000
MAX_VALIDATION_EVIDENCE_ITEMS = 10_000
MAX_APPROVAL_ITEMS = 10_000
MAX_PROCESS_STEPS_PER_DOCUMENT = 10_000
MAX_CHARACTERISTICS_PER_DOCUMENT = 10_000
MAX_RISKS_PER_DOCUMENT = 20_000
MAX_MUTATION_OPERATIONS = 10_000

CASE_SCHEMA_VERSION = "qualityci-case-0.4"
PREVIOUS_CASE_SCHEMA_VERSION = "qualityci-case-0.3"
CONTROLLED_REFERENCE_CASE_SCHEMA_VERSION = PREVIOUS_CASE_SCHEMA_VERSION
RELATIONSHIP_CASE_SCHEMA_VERSION = "qualityci-case-0.2"
LEGACY_CASE_SCHEMA_VERSION = "qualityci-case-0.1"
CONTROLLED_REFERENCE_CONTRACT_VERSION = "qualityci-controlled-reference-0.1"
RELATIONSHIP_MIGRATION_STATUSES = {"DETERMINISTIC_1X1", "AMBIGUOUS"}
REFERENCE_MIGRATION_STATUSES = {"LEGACY_UNATTESTED"}
VALIDATION_MIGRATION_STATUSES = {"LEGACY_UNATTESTED"}
REFERENCE_IDENTITY_KEYS = {
    "document_type",
    "document_id",
    "revision",
    "source_hash",
}
REFERENCE_ROLES = {"SOP", "CONTROL_PLAN"}
LOWERCASE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RFC3339_UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?Z\Z"
)


def normalized_identity(value: str) -> str:
    """Return the documented comparison key for QualityCI entity identities."""

    return " ".join(unicodedata.normalize("NFKC", value).strip().split()).casefold()


def relationship_key(process_step_id: str, characteristic_id: str) -> tuple[str, str]:
    return normalized_identity(process_step_id), normalized_identity(characteristic_id)


def canonical_case_projection(case: dict[str, Any]) -> dict[str, Any]:
    """Normalize arrays whose order has no business meaning in the v0.2 contract."""

    # Copy only containers whose ordering is changed.  A full deepcopy turns
    # one 3,000-row identity projection into millions of recursive visits even
    # though scalar/member objects are read-only during canonical JSON output.
    normalized = dict(case)
    event = normalized.get("event")
    if isinstance(event, dict):
        event = dict(event)
        normalized["event"] = event
        for key in ("affected_process_steps", "affected_characteristics"):
            values = event.get(key)
            if isinstance(values, list) and all(isinstance(item, str) for item in values):
                values = list(values)
                event[key] = values
                values.sort(key=normalized_identity)
        links = event.get("affected_links")
        if isinstance(links, list) and all(isinstance(item, dict) for item in links):
            links = list(links)
            event["affected_links"] = links
            links.sort(
                key=lambda item: relationship_key(
                    item.get("process_step_id", ""), item.get("characteristic_id", "")
                )
            )
        approvals = event.get("approvals")
        if isinstance(approvals, list) and all(isinstance(item, dict) for item in approvals):
            approvals = list(approvals)
            event["approvals"] = approvals
            approvals.sort(
                key=lambda item: (
                    normalized_identity(item.get("role", "")),
                    normalized_identity(item.get("event_revision", "")),
                )
            )
        evidence = event.get("validation_evidence")
        if isinstance(evidence, list) and all(isinstance(item, dict) for item in evidence):
            evidence = list(evidence)
            event["validation_evidence"] = evidence
            evidence.sort(key=lambda item: normalized_identity(item.get("evidence_id", "")))
        validation_plan = event.get("validation_plan")
        if isinstance(validation_plan, dict):
            validation_plan = dict(validation_plan)
            event["validation_plan"] = validation_plan
            required_evidence = validation_plan.get("required_evidence")
            if isinstance(required_evidence, list) and all(
                isinstance(item, dict) for item in required_evidence
            ):
                required_evidence = list(required_evidence)
                validation_plan["required_evidence"] = required_evidence
                required_evidence.sort(
                    key=lambda item: (
                        normalized_identity(item.get("evidence_id", "")),
                        item.get("evidence_id", ""),
                    )
                )

    documents = normalized.get("documents")
    if isinstance(documents, list) and all(isinstance(item, dict) for item in documents):
        documents = [dict(item) for item in documents]
        normalized["documents"] = documents
        documents.sort(key=lambda item: normalized_identity(item.get("document_id", "")))
        for document in documents:
            fields = document.get("fields")
            if not isinstance(fields, dict):
                continue
            fields = dict(fields)
            document["fields"] = fields
            process_steps = fields.get("process_steps")
            if isinstance(process_steps, list) and all(
                isinstance(item, str) for item in process_steps
            ):
                process_steps = list(process_steps)
                fields["process_steps"] = process_steps
                process_steps.sort(key=normalized_identity)
            characteristics = fields.get("characteristics")
            if isinstance(characteristics, list) and all(
                isinstance(item, dict) for item in characteristics
            ):
                characteristics = list(characteristics)
                fields["characteristics"] = characteristics
                characteristics.sort(
                    key=lambda item: (
                        *relationship_key(
                            item.get("process_step_id", ""),
                            item.get("characteristic_id", ""),
                        ),
                        normalized_identity(item.get("control_id", "")),
                    )
                )
            risks = fields.get("risks")
            if isinstance(risks, list) and all(isinstance(item, dict) for item in risks):
                risks = list(risks)
                fields["risks"] = risks
                risks.sort(
                    key=lambda item: (
                        *relationship_key(
                            item.get("process_step_id", ""),
                            item.get("characteristic_id", ""),
                        ),
                        normalized_identity(item.get("failure_mode_id", "")),
                    )
                )
    return normalized


def canonical_hash(value: Any) -> str:
    if (
        isinstance(value, dict)
        and value.get("schema_version") == CASE_SCHEMA_VERSION
        and isinstance(value.get("event"), dict)
        and isinstance(value.get("documents"), list)
    ):
        # Validate before semantic sorting.  Otherwise two exact IDs with one
        # normalized identity could be reordered/hashed as if both were safe
        # members while a later normalized dictionary silently overwrote one.
        validate_case(value)
        value = canonical_case_projection(value)
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _strict_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number is not allowed: {value}")
    return parsed


def strict_json_loads(payload: str) -> Any:
    try:
        return json.loads(
            payload,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_strict_json_float,
        )
    except RecursionError as error:
        raise ValueError("JSON nesting exceeds the supported limit") from error


def load_json(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    with source.open("rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        if size > MAX_JSON_FILE_BYTES:
            raise ValueError(
                f"JSON file exceeds {MAX_JSON_FILE_BYTES} byte input limit: {size}"
            )
        raw = handle.read(MAX_JSON_FILE_BYTES + 1)
    if len(raw) > MAX_JSON_FILE_BYTES:
        raise ValueError(
            f"JSON file exceeds {MAX_JSON_FILE_BYTES} byte input limit while reading"
        )
    text = raw.decode("utf-8")
    payload = strict_json_loads(text)
    if not isinstance(payload, dict):
        raise ValueError("JSON document root must be an object")
    return payload


def _require_nonempty_string(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")


def _require_enum(value: Any, label: str, allowed: set[str]) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"unsupported {label}: {value!r}")


def _require_iso_date(value: Any, label: str) -> None:
    _require_nonempty_string(value, label)
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
        raise ValueError(f"{label} must use YYYY-MM-DD format")
    try:
        date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO calendar date") from error


def parse_rfc3339_utc(value: Any, label: str) -> datetime:
    """Parse the strict wire timestamp contract: RFC3339 date-time in UTC/Z."""

    if type(value) is not str or RFC3339_UTC.fullmatch(value) is None:
        raise ValueError(f"{label} must be RFC3339 UTC with Z suffix")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{label} must be RFC3339 UTC with Z suffix") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError(f"{label} must be RFC3339 UTC with Z suffix")
    return parsed


def _require_bounded_list(value: Any, label: str, maximum: int) -> None:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds maximum of {maximum} items")


def _require_string_list(
    value: Any, label: str, maximum: int | None = None
) -> None:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list of non-empty strings")
    if maximum is not None and len(value) > maximum:
        raise ValueError(f"{label} exceeds maximum of {maximum} items")
    if any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"{label} must be a list of non-empty strings")


def _reject_normalized_duplicates(values: list[str], label: str) -> None:
    keys = [normalized_identity(item) for item in values]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{label} contains duplicate normalized identities")


def _migrate_v02_references(case: dict[str, Any]) -> dict[str, Any]:
    """Move revision-only v0.2 references into an explicit untrusted shape.

    A revision string cannot prove document or byte identity.  The migration
    deliberately preserves only what the old payload actually said and never
    fills document IDs or hashes from the currently approved documents.
    """

    migrated = copy.deepcopy(case)
    if migrated.get("schema_version") != RELATIONSHIP_CASE_SCHEMA_VERSION:
        raise ValueError("controlled-reference migration requires a v0.2 case")
    legacy_documents: list[str] = []
    for document in migrated.get("documents", []):
        if not isinstance(document, dict) or document.get("document_type") != "INSPECTION_RECORD":
            continue
        document["reference_contract_version"] = CONTROLLED_REFERENCE_CONTRACT_VERSION
        fields = document.get("fields")
        if not isinstance(fields, dict):
            continue
        references = fields.get("references")
        if references is None:
            legacy_documents.append(str(document.get("document_id", "<missing>")))
            continue
        if not isinstance(references, dict) or any(
            not isinstance(key, str)
            or not key.strip()
            or not isinstance(value, str)
            for key, value in references.items()
        ):
            raise ValueError(
                "v0.2 controlled references must be revision-only strings; "
                "declare schema_version='qualityci-case-0.3' for native identities"
            )
        fields["references"] = {"LEGACY_UNATTESTED": copy.deepcopy(references)}
        legacy_documents.append(str(document.get("document_id", "<missing>")))
    migrated["schema_version"] = CONTROLLED_REFERENCE_CASE_SCHEMA_VERSION
    migrated["reference_migration"] = {
        "source_schema_version": RELATIONSHIP_CASE_SCHEMA_VERSION,
        "target_schema_version": CONTROLLED_REFERENCE_CASE_SCHEMA_VERSION,
        "status": "LEGACY_UNATTESTED",
        "inference_scope": "NONE",
        "document_ids": legacy_documents,
        "reason": (
            "revision-only references do not prove exact controlled-document "
            "or source-byte identity"
        ),
    }
    return migrated


def _migrate_v03_validation(case: dict[str, Any]) -> dict[str, Any]:
    """Preserve v0.3 validation text without synthesizing an A04 subject."""

    migrated = copy.deepcopy(case)
    if migrated.get("schema_version") != CONTROLLED_REFERENCE_CASE_SCHEMA_VERSION:
        raise ValueError("validation migration requires a v0.3 case")
    event = migrated.get("event")
    evidence_ids: list[str] = []
    if isinstance(event, dict):
        evidence = event.get("validation_evidence")
        if isinstance(evidence, list):
            evidence_ids = [
                str(item.get("evidence_id", "<missing>"))
                for item in evidence
                if isinstance(item, dict)
            ]
    migrated["schema_version"] = CASE_SCHEMA_VERSION
    migrated["validation_migration"] = {
        "source_schema_version": CONTROLLED_REFERENCE_CASE_SCHEMA_VERSION,
        "target_schema_version": CASE_SCHEMA_VERSION,
        "status": "LEGACY_UNATTESTED",
        "inference_scope": "NONE",
        "evidence_ids": evidence_ids,
        "reason": (
            "v0.3 validation records do not bind event, scope, case subject, "
            "raw report bytes, issuer claim or time claim"
        ),
    }
    return migrated


def migrate_legacy_relationships(case: dict[str, Any]) -> dict[str, Any]:
    """Migrate only relationship scopes that are uniquely inferable.

    A legacy 1-step x 1-characteristic event has one possible pair.  Any other
    legacy scope is marked AMBIGUOUS and intentionally remains without inferred
    edges so relationship rules return UNVERIFIABLE rather than guessing.
    """

    migrated = copy.deepcopy(case)
    source_version = migrated.get("schema_version", LEGACY_CASE_SCHEMA_VERSION)
    if source_version == CASE_SCHEMA_VERSION:
        return migrated
    if source_version == CONTROLLED_REFERENCE_CASE_SCHEMA_VERSION:
        return _migrate_v03_validation(migrated)
    if source_version == RELATIONSHIP_CASE_SCHEMA_VERSION:
        return _migrate_v03_validation(_migrate_v02_references(migrated))
    if source_version != LEGACY_CASE_SCHEMA_VERSION:
        raise ValueError(f"unsupported case schema_version: {source_version!r}")

    event = migrated.get("event")
    if not isinstance(event, dict):
        return migrated
    has_v02_row_fields = any(
        isinstance(document, dict)
        and isinstance(document.get("fields"), dict)
        and any(
            isinstance(item, dict)
            and ("process_step_id" in item or "control_id" in item)
            for collection in ("risks", "characteristics")
            for item in document["fields"].get(collection, [])
        )
        for document in migrated.get("documents", [])
    )
    if "affected_links" in event or has_v02_row_fields:
        raise ValueError(
            "legacy case contains v0.2 relationship fields; declare "
            f"schema_version={CASE_SCHEMA_VERSION!r} instead of using compatibility migration"
        )
    steps = event.get("affected_process_steps")
    characteristics = event.get("affected_characteristics")
    migrated["schema_version"] = RELATIONSHIP_CASE_SCHEMA_VERSION
    marker: dict[str, Any] = {
        "source_schema_version": source_version,
        "target_schema_version": RELATIONSHIP_CASE_SCHEMA_VERSION,
    }
    if (
        isinstance(steps, list)
        and len(steps) == 1
        and isinstance(steps[0], str)
        and steps[0].strip()
        and isinstance(characteristics, list)
        and len(characteristics) == 1
        and isinstance(characteristics[0], str)
        and characteristics[0].strip()
    ):
        step = steps[0]
        characteristic_id = characteristics[0]
        event["affected_links"] = [
            {"process_step_id": step, "characteristic_id": characteristic_id}
        ]
        marker.update(
            status="DETERMINISTIC_1X1",
            inference_scope="EVENT_SCOPE_ONLY",
            inferred_affected_links=copy.deepcopy(event["affected_links"]),
            reason=(
                "event scope has one possible pair; legacy document rows remain "
                "unbound and cannot support relationship PASS"
            ),
        )
    else:
        marker.update(
            status="AMBIGUOUS",
            reason="legacy relationship scope is not uniquely inferable",
        )
    migrated["relationship_migration"] = marker
    return _migrate_v03_validation(_migrate_v02_references(migrated))


def validate_case(case: dict[str, Any]) -> None:
    if not isinstance(case, dict):
        raise ValueError("case must be an object")
    required = {
        "schema_version",
        "case_id",
        "synthetic_for_competition",
        "event",
        "documents",
    }
    missing = sorted(required - set(case))
    if missing:
        raise ValueError(f"case missing required keys: {missing}")
    if case["schema_version"] != CASE_SCHEMA_VERSION:
        raise ValueError(
            f"case schema_version must be {CASE_SCHEMA_VERSION!r}; "
            "use migrate_legacy_relationships for a legacy case"
        )
    if case["synthetic_for_competition"] is not True:
        raise ValueError("v0.2 only accepts cases explicitly marked synthetic_for_competition=true")
    _require_nonempty_string(case["case_id"], "case_id")

    migration = case.get("relationship_migration")
    if migration is not None:
        if not isinstance(migration, dict):
            raise ValueError("relationship_migration must be an object")
        required_migration = {
            "source_schema_version",
            "target_schema_version",
            "status",
        }
        missing_migration = required_migration - set(migration)
        if missing_migration:
            raise ValueError(
                "relationship_migration missing required keys: "
                f"{sorted(missing_migration)}"
            )
        if migration["source_schema_version"] != LEGACY_CASE_SCHEMA_VERSION:
            raise ValueError("relationship_migration has unsupported source_schema_version")
        if migration["target_schema_version"] != RELATIONSHIP_CASE_SCHEMA_VERSION:
            raise ValueError("relationship_migration target_schema_version is not v0.2")
        _require_enum(
            migration["status"],
            "relationship_migration status",
            RELATIONSHIP_MIGRATION_STATUSES,
        )
        if (
            migration["status"] == "DETERMINISTIC_1X1"
            and migration.get("inference_scope") != "EVENT_SCOPE_ONLY"
        ):
            raise ValueError(
                "deterministic legacy migration must be explicitly limited to "
                "EVENT_SCOPE_ONLY"
            )

    reference_migration = case.get("reference_migration")
    if reference_migration is not None:
        if not isinstance(reference_migration, dict):
            raise ValueError("reference_migration must be an object")
        required_reference_migration = {
            "source_schema_version",
            "target_schema_version",
            "status",
            "inference_scope",
            "document_ids",
        }
        missing_reference_migration = required_reference_migration - set(reference_migration)
        if missing_reference_migration:
            raise ValueError(
                "reference_migration missing required keys: "
                f"{sorted(missing_reference_migration)}"
            )
        if reference_migration["source_schema_version"] != RELATIONSHIP_CASE_SCHEMA_VERSION:
            raise ValueError("reference_migration has unsupported source_schema_version")
        if (
            reference_migration["target_schema_version"]
            != CONTROLLED_REFERENCE_CASE_SCHEMA_VERSION
        ):
            raise ValueError("reference_migration target_schema_version is not v0.3")
        _require_enum(
            reference_migration["status"],
            "reference_migration status",
            REFERENCE_MIGRATION_STATUSES,
        )
        if reference_migration["inference_scope"] != "NONE":
            raise ValueError("legacy references must not infer identity")
        _require_string_list(
            reference_migration["document_ids"],
            "reference_migration document_ids",
            MAX_DOCUMENTS,
        )

    validation_migration = case.get("validation_migration")
    if validation_migration is not None:
        if not isinstance(validation_migration, dict):
            raise ValueError("validation_migration must be an object")
        required_validation_migration = {
            "source_schema_version",
            "target_schema_version",
            "status",
            "inference_scope",
            "evidence_ids",
        }
        missing_validation_migration = required_validation_migration - set(
            validation_migration
        )
        if missing_validation_migration:
            raise ValueError(
                "validation_migration missing required keys: "
                f"{sorted(missing_validation_migration)}"
            )
        if (
            validation_migration["source_schema_version"]
            != CONTROLLED_REFERENCE_CASE_SCHEMA_VERSION
            or validation_migration["target_schema_version"] != CASE_SCHEMA_VERSION
        ):
            raise ValueError("validation_migration version chain must be v0.3 to v0.4")
        _require_enum(
            validation_migration["status"],
            "validation_migration status",
            VALIDATION_MIGRATION_STATUSES,
        )
        if validation_migration["inference_scope"] != "NONE":
            raise ValueError("legacy validation evidence must not infer a subject")
        _require_string_list(
            validation_migration["evidence_ids"],
            "validation_migration evidence_ids",
            MAX_VALIDATION_EVIDENCE_ITEMS,
        )

    event = case["event"]
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    required_event = {
        "event_id",
        "event_type",
        "revision",
        "risk_level",
        "affected_process_steps",
        "affected_characteristics",
    }
    missing_event = sorted(required_event - set(event))
    if missing_event:
        raise ValueError(f"event missing required keys: {missing_event}")
    _require_nonempty_string(event["event_id"], "event_id")
    _require_nonempty_string(event["revision"], "event revision")
    _require_enum(event["event_type"], "event_type", EVENT_TYPES)
    _require_enum(event["risk_level"], "risk_level", RISK_LEVELS)
    for key in ("affected_process_steps", "affected_characteristics"):
        _require_string_list(
            event[key], f"event {key}", MAX_EVENT_AFFECTED_ITEMS
        )
        _reject_normalized_duplicates(event[key], f"event {key}")
    affected_links = event.get("affected_links")
    if affected_links is not None:
        _require_bounded_list(
            affected_links, "event affected_links", MAX_EVENT_AFFECTED_ITEMS
        )
        link_keys: set[tuple[str, str]] = set()
        step_keys = {normalized_identity(item) for item in event["affected_process_steps"]}
        characteristic_keys = {
            normalized_identity(item) for item in event["affected_characteristics"]
        }
        for index, link in enumerate(affected_links):
            if not isinstance(link, dict):
                raise ValueError(f"event affected_links[{index}] must be an object")
            missing_link = {"process_step_id", "characteristic_id"} - set(link)
            if missing_link:
                raise ValueError(
                    f"event affected_links[{index}] missing required keys: {sorted(missing_link)}"
                )
            _require_nonempty_string(
                link["process_step_id"],
                f"event affected_links[{index}].process_step_id",
            )
            _require_nonempty_string(
                link["characteristic_id"],
                f"event affected_links[{index}].characteristic_id",
            )
            key = relationship_key(
                link["process_step_id"], link["characteristic_id"]
            )
            if key in link_keys:
                raise ValueError("event affected_links contains duplicate normalized pairs")
            link_keys.add(key)
            if key[0] not in step_keys or key[1] not in characteristic_keys:
                raise ValueError(
                    "event affected_links must reference identities declared in "
                    "affected_process_steps and affected_characteristics"
                )
    if "approved_at" in event:
        _require_iso_date(event["approved_at"], "event approved_at")
    if "change_summary" in event and not isinstance(event["change_summary"], str):
        raise ValueError("event change_summary must be a string")

    validation_plan = event.get("validation_plan")
    if validation_plan is None:
        if validation_migration is None:
            raise ValueError("native v0.4 event requires validation_plan")
    else:
        if not isinstance(validation_plan, dict) or set(validation_plan) != {
            "contract_version",
            "required_evidence",
        }:
            raise ValueError("event validation_plan has unsupported shape")
        if validation_plan["contract_version"] != "qualityci-validation-plan-0.1":
            raise ValueError("event validation_plan contract version is unsupported")
        required_evidence = validation_plan["required_evidence"]
        _require_bounded_list(
            required_evidence,
            "event validation_plan required_evidence",
            MAX_VALIDATION_EVIDENCE_ITEMS,
        )
        if not required_evidence:
            raise ValueError("event validation_plan required_evidence must not be empty")
        identities: list[str] = []
        required_keys = {
            "evidence_id",
            "evidence_type",
            "claim",
            "issuer_id",
            "issuer_role",
            "valid_from",
            "valid_until",
        }
        for index, requirement in enumerate(required_evidence):
            if not isinstance(requirement, dict) or set(requirement) != required_keys:
                raise ValueError(
                    f"validation_plan required_evidence[{index}] has unsupported shape"
                )
            for key in required_keys:
                _require_nonempty_string(
                    requirement[key],
                    f"validation_plan required_evidence[{index}].{key}",
                )
            identities.append(requirement["evidence_id"])
            for key in ("valid_from", "valid_until"):
                parse_rfc3339_utc(
                    requirement[key],
                    f"validation_plan required_evidence[{index}].{key}",
                )
            if parse_rfc3339_utc(
                requirement["valid_until"], "validation_plan valid_until"
            ) < parse_rfc3339_utc(
                requirement["valid_from"], "validation_plan valid_from"
            ):
                raise ValueError("validation_plan valid_until precedes valid_from")
        _reject_normalized_duplicates(
            identities, "validation_plan required evidence_id"
        )

    validation_evidence = event.get("validation_evidence")
    if validation_evidence is not None:
        _require_bounded_list(
            validation_evidence,
            "event validation_evidence",
            MAX_VALIDATION_EVIDENCE_ITEMS,
        )
        if any(not isinstance(item, dict) for item in validation_evidence):
            raise ValueError("event validation_evidence must be a list of objects")
        evidence_identities: list[str] = []
        for index, item in enumerate(validation_evidence):
            missing_evidence = {"evidence_id", "result", "locator"} - set(item)
            if missing_evidence:
                raise ValueError(
                    f"validation_evidence[{index}] missing required keys: {sorted(missing_evidence)}"
                )
            _require_nonempty_string(
                item["evidence_id"], f"validation_evidence[{index}].evidence_id"
            )
            evidence_identities.append(item["evidence_id"])
            _require_enum(
                item["result"],
                f"validation_evidence[{index}].result",
                VALIDATION_RESULTS,
            )
            if not isinstance(item["locator"], str):
                raise ValueError(f"validation_evidence[{index}].locator must be a string")
            if "summary" in item and not isinstance(item["summary"], str):
                raise ValueError(f"validation_evidence[{index}].summary must be a string")
        _reject_normalized_duplicates(
            evidence_identities, "duplicate validation evidence identity"
        )

    approvals = event.get("approvals")
    if approvals is not None:
        _require_bounded_list(approvals, "event approvals", MAX_APPROVAL_ITEMS)
        if any(not isinstance(item, dict) for item in approvals):
            raise ValueError("event approvals must be a list of objects")
        approval_subjects: set[tuple[str, str]] = set()
        for index, item in enumerate(approvals):
            missing_approval = {"role", "decision", "event_revision"} - set(item)
            if missing_approval:
                raise ValueError(
                    f"event approvals[{index}] missing required keys: {sorted(missing_approval)}"
                )
            _require_nonempty_string(item["role"], f"event approvals[{index}].role")
            _require_enum(
                item["decision"],
                f"event approvals[{index}].decision",
                APPROVAL_DECISIONS,
            )
            _require_nonempty_string(
                item["event_revision"], f"event approvals[{index}].event_revision"
            )
            approval_subject = (item["role"], item["event_revision"])
            if approval_subject in approval_subjects:
                raise ValueError(
                    "event approvals must have a unique role + event_revision subject: "
                    f"{approval_subject!r}"
                )
            approval_subjects.add(approval_subject)
            if "approved_at" in item:
                _require_iso_date(item["approved_at"], f"event approvals[{index}].approved_at")
            if "comment" in item and not isinstance(item["comment"], str):
                raise ValueError(f"event approvals[{index}].comment must be a string")

    documents = case["documents"]
    _require_bounded_list(documents, "documents", MAX_DOCUMENTS)
    if any(not isinstance(doc, dict) for doc in documents):
        raise ValueError("every document must be an object")
    document_ids: list[str] = []
    for index, document in enumerate(documents):
        document_id = document.get("document_id")
        _require_nonempty_string(document_id, f"documents[{index}].document_id")
        document_ids.append(document_id)
    _reject_normalized_duplicates(document_ids, "documents document_id")
    for doc in documents:
        required_document = {
            "document_id", "document_type", "revision", "status", "owner", "revision_date",
            "source_hash", "fields"
        }
        missing_document = sorted(required_document - set(doc))
        if missing_document:
            raise ValueError(f"{doc.get('document_id', '<missing>')} missing required keys: {missing_document}")
        for key in ("document_id", "revision", "owner"):
            _require_nonempty_string(doc[key], f"document {key}")
        _require_nonempty_string(doc["source_hash"], f"{doc['document_id']} source_hash")
        if len(doc["source_hash"]) > MAX_SOURCE_ANCHOR_CHARACTERS:
            raise ValueError(
                f"{doc['document_id']} source_hash exceeds maximum of "
                f"{MAX_SOURCE_ANCHOR_CHARACTERS} characters"
            )
        _require_iso_date(doc["revision_date"], f"{doc['document_id']} revision_date")
        _require_enum(doc["document_type"], "document_type", REQUIRED_DOCUMENT_TYPES)
        _require_enum(doc["status"], "document status", DOCUMENT_STATUSES)
        if not isinstance(doc["fields"], dict):
            raise ValueError(f"{doc['document_id']} fields must be an object")
        if "approved_waiver" in doc:
            waiver = doc["approved_waiver"]
            if not isinstance(waiver, dict):
                raise ValueError(f"{doc['document_id']} approved_waiver must be an object")
            for key in ("waiver_id", "document_id", "event_revision", "scope", "locator"):
                if key in waiver and not isinstance(waiver[key], str):
                    raise ValueError(f"{doc['document_id']} waiver {key} must be a string")
            if "approved_roles" in waiver:
                if not isinstance(waiver["approved_roles"], list) or any(
                    not isinstance(role, str) for role in waiver["approved_roles"]
                ):
                    raise ValueError(
                        f"{doc['document_id']} waiver approved_roles must be a list of strings"
                    )
            if "valid_from" in waiver:
                _require_iso_date(waiver["valid_from"], f"{doc['document_id']} waiver valid_from")
            if "valid_until" in waiver:
                _require_iso_date(waiver["valid_until"], f"{doc['document_id']} waiver valid_until")

        process_steps = doc["fields"].get("process_steps")
        if process_steps is not None:
            _require_string_list(
                process_steps,
                f"{doc['document_id']} process_steps",
                MAX_PROCESS_STEPS_PER_DOCUMENT,
            )
            _reject_normalized_duplicates(
                process_steps, f"{doc['document_id']} process_steps"
            )
        process_step_keys = {
            normalized_identity(item) for item in (process_steps or [])
        }
        allow_legacy_missing = migration is not None
        characteristics = doc["fields"].get("characteristics", [])
        _require_bounded_list(
            characteristics,
            f"{doc['document_id']} characteristics",
            MAX_CHARACTERISTICS_PER_DOCUMENT,
        )
        if any(not isinstance(item, dict) for item in characteristics):
            raise ValueError(f"{doc['document_id']} characteristics must be a list of objects")
        characteristic_keys: set[tuple[str, str]] = set()
        control_ids: set[str] = set()
        for index, item in enumerate(characteristics):
            characteristic_id = item.get("characteristic_id")
            _require_nonempty_string(
                characteristic_id,
                f"{doc['document_id']} characteristics[{index}].characteristic_id",
            )
            process_step_id = item.get("process_step_id")
            if process_step_id is None and allow_legacy_missing:
                continue
            _require_nonempty_string(
                process_step_id,
                f"{doc['document_id']} characteristics[{index}].process_step_id",
            )
            key = relationship_key(process_step_id, characteristic_id)
            if key in characteristic_keys:
                raise ValueError(
                    f"{doc['document_id']} contains duplicate characteristic_id "
                    "relationship pairs after normalized process_step_id + characteristic_id"
                )
            characteristic_keys.add(key)
            if key[0] not in process_step_keys:
                raise ValueError(
                    f"{doc['document_id']} characteristic relationship references a "
                    "process_step_id absent from that document's process_steps"
                )
            if doc["document_type"] == "CONTROL_PLAN":
                _require_nonempty_string(
                    item.get("control_id"),
                    f"{doc['document_id']} characteristics[{index}].control_id",
                )
                control_key = normalized_identity(item["control_id"])
                if control_key in control_ids:
                    raise ValueError(
                        f"{doc['document_id']} contains duplicate normalized control_id values"
                    )
                control_ids.add(control_key)
        for item in characteristics:
            _require_nonempty_string(
                item.get("locator"),
                f"{doc['document_id']} characteristic {item['characteristic_id']} locator",
            )
            specification = item.get("specification")
            if specification is not None:
                if not isinstance(specification, dict):
                    raise ValueError(f"{doc['document_id']} specification must be an object")
                for key in ("target", "minimum", "maximum"):
                    if key in specification:
                        value = specification[key]
                        if (
                            isinstance(value, bool)
                            or not isinstance(value, (int, float))
                            or not math.isfinite(value)
                        ):
                            raise ValueError(
                                f"{doc['document_id']} specification {key} must be a finite number"
                            )
                if "unit" in specification and not isinstance(specification["unit"], str):
                    raise ValueError(f"{doc['document_id']} specification unit must be a string")
            for key in ("control_method", "frequency", "reaction_plan"):
                if key in item and not isinstance(item[key], str):
                    raise ValueError(
                        f"{doc['document_id']} characteristic {key} must be a string"
                    )

        risks = doc["fields"].get("risks", [])
        _require_bounded_list(
            risks,
            f"{doc['document_id']} risks",
            MAX_RISKS_PER_DOCUMENT,
        )
        if any(not isinstance(item, dict) for item in risks):
            raise ValueError(f"{doc['document_id']} risks must be a list of objects")
        failure_mode_ids: set[str] = set()
        for index, risk in enumerate(risks):
            required_risk = {
                "failure_mode_id", "characteristic_id", "special_characteristic", "locator"
            }
            missing_risk = required_risk - set(risk)
            if missing_risk:
                raise ValueError(
                    f"{doc['document_id']} risks[{index}] missing required keys: {sorted(missing_risk)}"
                )
            for key in ("failure_mode_id", "characteristic_id", "locator"):
                _require_nonempty_string(risk[key], f"{doc['document_id']} risks[{index}].{key}")
            failure_mode_key = normalized_identity(risk["failure_mode_id"])
            if failure_mode_key in failure_mode_ids:
                raise ValueError(
                    f"{doc['document_id']} contains duplicate normalized failure_mode_id values"
                )
            failure_mode_ids.add(failure_mode_key)
            process_step_id = risk.get("process_step_id")
            if process_step_id is not None or not allow_legacy_missing:
                _require_nonempty_string(
                    process_step_id,
                    f"{doc['document_id']} risks[{index}].process_step_id",
                )
                if normalized_identity(process_step_id) not in process_step_keys:
                    raise ValueError(
                        f"{doc['document_id']} risk relationship references a "
                        "process_step_id absent from that document's process_steps"
                    )
            if not isinstance(risk["special_characteristic"], bool):
                raise ValueError(
                    f"{doc['document_id']} risks[{index}].special_characteristic must be boolean"
                )
            if "effect" in risk and not isinstance(risk["effect"], str):
                raise ValueError(f"{doc['document_id']} risks[{index}].effect must be a string")

        references = doc["fields"].get("references")
        reference_version = doc.get("reference_contract_version")
        if doc["document_type"] == "INSPECTION_RECORD":
            if reference_version != CONTROLLED_REFERENCE_CONTRACT_VERSION:
                raise ValueError(
                    f"{doc['document_id']} reference_contract_version must be "
                    f"{CONTROLLED_REFERENCE_CONTRACT_VERSION!r}"
                )
        elif reference_version is not None:
            raise ValueError(
                f"{doc['document_id']} reference_contract_version is only valid "
                "for INSPECTION_RECORD"
            )
        if references is None:
            continue
        if not isinstance(references, dict):
            raise ValueError(f"{doc['document_id']} references must be an object")
        role_names = list(references)
        if any(not isinstance(role, str) or not role.strip() for role in role_names):
            raise ValueError(f"{doc['document_id']} reference roles must be non-empty strings")
        _reject_normalized_duplicates(role_names, f"{doc['document_id']} reference roles")
        if set(references) == {"LEGACY_UNATTESTED"}:
            if reference_migration is None:
                raise ValueError(
                    f"{doc['document_id']} LEGACY_UNATTESTED references require "
                    "an explicit reference_migration marker"
                )
            revision_only = references["LEGACY_UNATTESTED"]
            if not isinstance(revision_only, dict) or any(
                not isinstance(role, str)
                or not role.strip()
                or not isinstance(revision, str)
                or not revision.strip()
                for role, revision in revision_only.items()
            ):
                raise ValueError(
                    f"{doc['document_id']} LEGACY_UNATTESTED references must map "
                    "roles to non-empty revision strings"
                )
            _reject_normalized_duplicates(
                list(revision_only),
                f"{doc['document_id']} legacy reference roles",
            )
            continue
        if "LEGACY_UNATTESTED" in references:
            raise ValueError(
                f"{doc['document_id']} references cannot mix legacy and native identities"
            )
        for role, identity in references.items():
            if not isinstance(identity, dict):
                raise ValueError(
                    f"{doc['document_id']} native reference {role} must be an identity object"
                )
            if set(identity) != REFERENCE_IDENTITY_KEYS:
                raise ValueError(
                    f"{doc['document_id']} native reference {role} must contain exactly "
                    f"{sorted(REFERENCE_IDENTITY_KEYS)}"
                )
            for key in REFERENCE_IDENTITY_KEYS:
                _require_nonempty_string(
                    identity[key],
                    f"{doc['document_id']} reference {role}.{key}",
                )
            if LOWERCASE_SHA256.fullmatch(identity["source_hash"]) is None:
                raise ValueError(
                    f"{doc['document_id']} reference {role}.source_hash must be a "
                    "lowercase SHA-256"
                )

    approved_counts = {
        document_type: sum(
            doc["document_type"] == document_type and doc["status"] == "APPROVED"
            for doc in documents
        )
        for document_type in REQUIRED_DOCUMENT_TYPES
    }
    invalid_approved = {
        document_type: count for document_type, count in approved_counts.items() if count != 1
    }
    if invalid_approved:
        raise ValueError(
            "every required document_type must have exactly one APPROVED document: "
            f"{invalid_approved}"
        )


def _set_nested(target: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".") if path else []
    cursor = target
    for part in parts[:-1]:
        cursor = cursor[part]
    cursor[parts[-1]] = value


def _delete_nested(target: dict[str, Any], path: str) -> None:
    parts = path.split(".") if path else []
    cursor = target
    for part in parts[:-1]:
        cursor = cursor[part]
    cursor.pop(parts[-1], None)


def apply_mutation(case: dict[str, Any], mutation: dict[str, Any]) -> dict[str, Any]:
    mutation_id = mutation.get("mutation_id")
    if not isinstance(mutation_id, str) or not mutation_id:
        raise ValueError("mutation_id must be a non-empty string")
    operations = mutation.get("operations")
    _require_bounded_list(operations, "mutation operations", MAX_MUTATION_OPERATIONS)
    mutated = copy.deepcopy(case)
    documents = {doc["document_id"]: doc for doc in mutated["documents"]}
    for operation in operations:
        if not isinstance(operation, dict):
            raise ValueError("mutation operation must be an object")
        target_name = operation.get("target", "document")
        if not isinstance(target_name, str) or target_name not in {"document", "event", "case"}:
            raise ValueError(f"unsupported mutation target: {target_name}")
        path = operation.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("mutation operation path must be a non-empty string")
        if target_name == "event":
            target = mutated["event"]
        elif target_name == "case":
            target = mutated
        else:
            document_id = operation["document_id"]
            if document_id not in documents:
                raise ValueError(f"unknown document_id in mutation: {document_id}")
            target = documents[document_id]
        op = operation.get("op")
        if op == "set":
            if "value" not in operation:
                raise ValueError("set mutation operation requires value")
            _set_nested(target, path, operation["value"])
        elif op == "delete":
            _delete_nested(target, path)
        else:
            raise ValueError(f"unsupported mutation operation: {op}")
    mutated["active_mutation"] = mutation_id
    return mutated


def prepare_case(case: dict[str, Any]) -> dict[str, Any]:
    prepared = migrate_legacy_relationships(case)
    validate_case(prepared)
    return prepared


def load_case(case_path: str | Path, mutation_path: str | Path | None = None) -> dict[str, Any]:
    case = prepare_case(load_json(case_path))
    if mutation_path:
        case = apply_mutation(case, load_json(mutation_path))
    return prepare_case(case)


def document_by_type(case: dict[str, Any], document_type: str) -> dict[str, Any] | None:
    matches = [doc for doc in case["documents"] if doc["document_type"] == document_type]
    approved = [doc for doc in matches if doc.get("status") == "APPROVED"]
    if len(approved) != 1:
        return None
    return approved[0]
