"""Test-only constructors for A04 native, byte-bound validation evidence.

Production entrypoints never synthesize these claims.  Regression tests use
this module to make the new raw trust boundary explicit while the historical
0.3 benchmark continues to exercise LEGACY_UNATTESTED migration.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from qualityci.validation_evidence import (
    VALIDATION_EVIDENCE_PACK_VERSION,
    ValidationEvidenceBundle,
    ValidationEvidenceMember,
    validation_case_subject_hash,
    validation_scope_digest,
)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def native_validation_case(case: dict[str, Any]) -> dict[str, Any]:
    native = copy.deepcopy(case)
    native["schema_version"] = "qualityci-case-0.4"
    native.pop("validation_migration", None)
    event = native["event"]
    event.pop("validation_evidence", None)
    event["validation_plan"] = {
        "contract_version": "qualityci-validation-plan-0.1",
        "required_evidence": [
            {
                "evidence_id": "VAL-SYN-001",
                "evidence_type": "PROCESS_CHANGE_VALIDATION",
                "claim": "WELD_AND_INSPECTION_CHANGE_EFFECTIVE",
                "issuer_id": "SYNTHETIC-LAB",
                "issuer_role": "VALIDATION_OWNER",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_until": "2024-12-31T23:59:59Z",
            }
        ],
    }
    return native


def validation_bundle(
    case: dict[str, Any],
    phase: str,
    **overrides: Any,
) -> ValidationEvidenceBundle:
    required = case["event"]["validation_plan"]["required_evidence"][0]
    filename = (
        "source_report.json" if phase == "SOURCE" else "resolved_report.json"
    )
    source_id = (
        "synthetic-validation-source"
        if phase == "SOURCE"
        else "synthetic-validation-resolved"
    )
    report = {
        "case_schema_version": case["schema_version"],
        "case_subject_hash": validation_case_subject_hash(case),
        "claim": required["claim"],
        "event_id": case["event"]["event_id"],
        "event_revision": case["event"]["revision"],
        "evidence_id": required["evidence_id"],
        "evidence_type": required["evidence_type"],
        "issued_at": "2024-02-01T12:30:00Z",
        "issuer_id": required["issuer_id"],
        "issuer_role": required["issuer_role"],
        "locator": f"{filename}#/result",
        "performed_at": "2024-02-01T12:00:00Z",
        "result": "PASS",
        "ruleset_version": "qci-rules-0.6.0",
        "scope_digest": validation_scope_digest(case),
        "summary": "Synthetic byte-bound validation claim",
    }
    report.update(copy.deepcopy(overrides))
    manifest = {
        "contract_version": VALIDATION_EVIDENCE_PACK_VERSION,
        "members": [
            {
                "evidence_id": required["evidence_id"],
                "format": "JSON",
                "phase": phase,
                "source_id": source_id,
                "source_path": filename,
            }
        ],
        "phase": phase,
    }
    return ValidationEvidenceBundle(
        canonical_bytes(manifest),
        (
            ValidationEvidenceMember(
                source_id,
                required["evidence_id"],
                filename,
                canonical_bytes(report),
            ),
        ),
    )
