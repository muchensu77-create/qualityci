from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


_RUN_RESULT_CONTRACT_VERSION = "qualityci-run-result-0.2"
_RUN_IDENTITY_VERSION = "qualityci-run-identity-v4"
_SOURCE_UNBOUND = "UNBOUND_SERIALIZED_CASE"
_SOURCE_BOUND = "BOUND_RAW_SOURCE_CASE"
_SOURCE_DERIVED = "SOURCE_ROOTED_DERIVATION"
_SOURCE_PACK_VERSION = "qualityci-case-source-pack-0.1"
_SOURCE_SET_VERSION = "qualityci-case-source-set-0.1"
_SOURCE_LINEAGE_VERSION = "qualityci-case-source-lineage-0.1"
_REFERENCE_UNATTESTED = "UNATTESTED_JSON"
_REFERENCE_ATTESTED = "ATTESTED_REFERENCE_SET"
_VALIDATION_UNATTESTED = "UNATTESTED_VALIDATION_JSON"
_VALIDATION_ATTESTED = "ATTESTED_VALIDATION_SET"
_REFERENCE_CONTRACT_VERSION = "qualityci-controlled-reference-0.1"
_VALIDATION_CONTRACT_VERSION = "qualityci-validation-evidence-0.1"


def _lower_hash_or_none(value: Any, label: str) -> None:
    if value is None:
        return
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be one lowercase SHA-256 value or null")


def _lower_hash(value: Any, label: str) -> None:
    _lower_hash_or_none(value, label)
    if value is None:
        raise ValueError(f"{label} must be one lowercase SHA-256 value")


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("RunResult identity is not canonical JSON") from error


def _json_native(value: Any) -> Any:
    """Return only exact JSON-native containers and scalar values."""

    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {key: _json_native(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_native(item) for item in value]
    return value


class CheckStatus(StrEnum):
    PASS = "PASS"
    CONTRADICTED = "CONTRADICTED"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True)
class EvidenceRef:
    document_id: str
    revision: str
    locator: str
    excerpt: str
    source_hash: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    status: CheckStatus
    severity: str
    summary: str
    evidence: tuple[EvidenceRef, ...] = ()
    remediation: str = ""
    acceptance_conditions: tuple[str, ...] = ()


@dataclass(frozen=True)
class ImpactPlan:
    event_id: str
    affected_process_steps: tuple[str, ...]
    affected_characteristics: tuple[str, ...]
    affected_links: tuple[tuple[str, str], ...]
    required_document_types: tuple[str, ...]
    selected_rule_ids: tuple[str, ...]
    reasoning_path: tuple[str, ...]


@dataclass(frozen=True)
class RunResult:
    run_id: str
    case_id: str
    case_hash: str
    ruleset_version: str
    run_result_contract_version: str
    run_identity_version: str
    case_source_assurance_state: str
    case_source_pack_contract_version: str | None
    case_source_set_contract_version: str | None
    case_source_set_hash: str | None
    case_source_binding_hash: str | None
    case_source_lineage_contract_version: str | None
    case_source_lineage_hash: str | None
    reference_assurance_state: str
    reference_set_hash: str | None
    reference_contract_version: str | None
    validation_assurance_state: str
    validation_evidence_set_hash: str | None
    validation_evidence_contract_version: str | None
    overall_status: CheckStatus
    impact_plan: ImpactPlan
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.run_result_contract_version != _RUN_RESULT_CONTRACT_VERSION:
            raise ValueError("RunResult contract version is unsupported")
        if self.run_identity_version != _RUN_IDENTITY_VERSION:
            raise ValueError("RunResult identity version is unsupported")
        if (
            type(self.run_id) is not str
            or len(self.run_id) != 16
            or any(character not in "0123456789abcdef" for character in self.run_id)
        ):
            raise ValueError("RunResult run_id must be one lowercase v4 identity")
        if type(self.case_id) is not str or not self.case_id.strip():
            raise ValueError("RunResult case_id must be a non-empty string")
        _lower_hash(self.case_hash, "RunResult case_hash")
        source_values = (
            self.case_source_pack_contract_version,
            self.case_source_set_contract_version,
            self.case_source_set_hash,
            self.case_source_binding_hash,
            self.case_source_lineage_contract_version,
            self.case_source_lineage_hash,
        )
        if self.case_source_assurance_state == _SOURCE_UNBOUND:
            if any(value is not None for value in source_values):
                raise ValueError("unbound RunResult requires null source identities")
        elif self.case_source_assurance_state in {_SOURCE_BOUND, _SOURCE_DERIVED}:
            if (
                self.case_source_pack_contract_version != _SOURCE_PACK_VERSION
                or self.case_source_set_contract_version != _SOURCE_SET_VERSION
            ):
                raise ValueError("source-rooted RunResult has inconsistent versions")
            _lower_hash(self.case_source_set_hash, "case source set hash")
            _lower_hash(self.case_source_binding_hash, "case source binding hash")
            if self.case_source_assurance_state == _SOURCE_BOUND:
                if (
                    self.case_source_lineage_contract_version is not None
                    or self.case_source_lineage_hash is not None
                ):
                    raise ValueError("bound RunResult cannot claim source lineage")
            elif (
                self.case_source_lineage_contract_version != _SOURCE_LINEAGE_VERSION
                or self.case_source_lineage_hash is None
            ):
                raise ValueError("derived RunResult requires exact source lineage")
            else:
                _lower_hash_or_none(
                    self.case_source_lineage_hash,
                    "case source lineage hash",
                )
        else:
            raise ValueError("RunResult source assurance state is unsupported")
        if self.reference_assurance_state == _REFERENCE_UNATTESTED:
            if (
                self.reference_set_hash is not None
                or self.reference_contract_version is not None
            ):
                raise ValueError("unattested reference assurance requires null identities")
        elif self.reference_assurance_state == _REFERENCE_ATTESTED:
            _lower_hash(self.reference_set_hash, "reference set hash")
            if self.reference_contract_version != _REFERENCE_CONTRACT_VERSION:
                raise ValueError("attested reference assurance has an invalid version")
        else:
            raise ValueError("RunResult reference assurance state is unsupported")
        if self.validation_assurance_state == _VALIDATION_UNATTESTED:
            if (
                self.validation_evidence_set_hash is not None
                or self.validation_evidence_contract_version is not None
            ):
                raise ValueError("unattested validation assurance requires null identities")
        elif self.validation_assurance_state == _VALIDATION_ATTESTED:
            _lower_hash(self.validation_evidence_set_hash, "validation evidence set hash")
            if self.validation_evidence_contract_version != _VALIDATION_CONTRACT_VERSION:
                raise ValueError("attested validation assurance has an invalid version")
        else:
            raise ValueError("RunResult validation assurance state is unsupported")
        identity = {
            "run_result_contract_version": self.run_result_contract_version,
            "run_identity_version": self.run_identity_version,
            "case_hash": self.case_hash,
            "ruleset_version": self.ruleset_version,
            "case_source_assurance_state": self.case_source_assurance_state,
            "case_source_pack_contract_version": (
                self.case_source_pack_contract_version
            ),
            "case_source_set_contract_version": (
                self.case_source_set_contract_version
            ),
            "case_source_set_hash": self.case_source_set_hash,
            "case_source_binding_hash": self.case_source_binding_hash,
            "case_source_lineage_contract_version": (
                self.case_source_lineage_contract_version
            ),
            "case_source_lineage_hash": self.case_source_lineage_hash,
            "reference_assurance_state": self.reference_assurance_state,
            "reference_set_hash": self.reference_set_hash,
            "reference_contract_version": self.reference_contract_version,
            "validation_assurance_state": self.validation_assurance_state,
            "validation_evidence_set_hash": self.validation_evidence_set_hash,
            "validation_evidence_contract_version": (
                self.validation_evidence_contract_version
            ),
        }
        expected_run_id = hashlib.sha256(
            b"QualityCI/run-identity/v4\0" + _canonical_json_bytes(identity)
        ).hexdigest()[:16]
        if self.run_id != expected_run_id:
            raise ValueError("RunResult run_id differs from its v4 identity")

    def to_dict(self) -> dict[str, Any]:
        return {
            key: _json_native(value) for key, value in asdict(self).items()
        }
