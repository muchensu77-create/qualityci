from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .impact import build_impact_plan
from .loader import canonical_hash, prepare_case
from .models import CheckStatus, RunResult
from .case_source_assurance import (
    RUN_IDENTITY_VERSION,
    RUN_RESULT_CONTRACT_VERSION,
    CaseMutationBundle,
    CaseSourceAssurance,
    CaseSourceBundle,
    _CaseSourceContext,
    _canonical_json_bytes,
    _is_sealed_case_source_context,
    _derive_case_source_mutation,
    _prepare_case_source_context,
    load_case_source_bundle,
    load_case_mutation_bundle,
    unbound_case_source_assurance,
    validate_case_source_assurance_payload,
)
from .controlled_references import (
    ControlledReferenceBundle,
    _ControlledReferenceContext,
    _is_sealed_reference_context,
    _prepare_controlled_reference_context,
)
from .rules import (
    RULES,
    RULESET_VERSION,
    rule_inspection_current_references,
    rule_validation_evidence,
)
from .validation_evidence import (
    VALIDATION_ASSURANCE_ATTESTED,
    VALIDATION_ASSURANCE_UNATTESTED,
    ValidationEvidenceBundle,
    _ValidationEvidenceContext,
    _is_sealed_validation_context,
    _prepare_validation_evidence_context,
    validation_case_subject_hash,
    validation_scope_digest,
    load_validation_evidence_bundle,
)

UNATTESTED_REFERENCE_ASSURANCE = "UNATTESTED_JSON"
ATTESTED_REFERENCE_ASSURANCE = "ATTESTED_REFERENCE_SET"


def _run_id_for_identity(
    case_hash: str,
    *,
    reference_assurance_state: str,
    reference_set_hash: str | None,
    reference_contract_version: str | None,
    validation_assurance_state: str = VALIDATION_ASSURANCE_UNATTESTED,
    validation_evidence_set_hash: str | None = None,
    validation_evidence_contract_version: str | None = None,
) -> str:
    run_identity = {
        "case_hash": case_hash,
        "ruleset_version": RULESET_VERSION,
        "reference_assurance_state": reference_assurance_state,
        "reference_set_hash": reference_set_hash,
        "reference_contract_version": reference_contract_version,
        "validation_assurance_state": validation_assurance_state,
        "validation_evidence_set_hash": validation_evidence_set_hash,
        "validation_evidence_contract_version": validation_evidence_contract_version,
    }
    return hashlib.sha256(
        b"QualityCI/run-identity/v3\0"
        + canonical_hash(run_identity).encode("ascii")
    ).hexdigest()[:16]


def _run_id_for_current_identity(
    case_hash: str,
    *,
    case_source_assurance: CaseSourceAssurance,
    reference_assurance_state: str,
    reference_set_hash: str | None,
    reference_contract_version: str | None,
    validation_assurance_state: str = VALIDATION_ASSURANCE_UNATTESTED,
    validation_evidence_set_hash: str | None = None,
    validation_evidence_contract_version: str | None = None,
) -> str:
    if type(case_source_assurance) is not CaseSourceAssurance:
        raise TypeError("current Run identity requires exact CaseSourceAssurance")
    source_projection = validate_case_source_assurance_payload(
        case_source_assurance.to_dict()
    )
    run_identity = {
        "run_result_contract_version": RUN_RESULT_CONTRACT_VERSION,
        "run_identity_version": RUN_IDENTITY_VERSION,
        "case_hash": case_hash,
        "ruleset_version": RULESET_VERSION,
        **source_projection,
        "reference_assurance_state": reference_assurance_state,
        "reference_set_hash": reference_set_hash,
        "reference_contract_version": reference_contract_version,
        "validation_assurance_state": validation_assurance_state,
        "validation_evidence_set_hash": validation_evidence_set_hash,
        "validation_evidence_contract_version": validation_evidence_contract_version,
    }
    return hashlib.sha256(
        b"QualityCI/run-identity/v4\0"
        + _canonical_json_bytes(run_identity)
    ).hexdigest()[:16]


def _overall_status(statuses: list[CheckStatus]) -> CheckStatus:
    if CheckStatus.CONTRADICTED in statuses:
        return CheckStatus.CONTRADICTED
    if CheckStatus.UNVERIFIABLE in statuses:
        return CheckStatus.UNVERIFIABLE
    return CheckStatus.PASS


def _evaluate_case(
    case: dict[str, Any],
    reference_context: _ControlledReferenceContext | None,
    validation_context: _ValidationEvidenceContext | None = None,
) -> RunResult:
    # All entrypoints, including direct library calls, must fail closed on a
    # missing or unknown risk classification before the approval rule runs.
    case = prepare_case(case)
    plan = build_impact_plan(case)
    findings = tuple(
        rule(case, plan, reference_context)
        if rule is rule_inspection_current_references
        else rule(case, plan, validation_context)
        if rule is rule_validation_evidence
        else rule(case, plan)
        for rule in RULES
    )
    case_hash = canonical_hash(case)
    if reference_context is None:
        reference_assurance_state = UNATTESTED_REFERENCE_ASSURANCE
        reference_set_hash = None
        reference_contract_version = None
    else:
        reference_assurance_state = ATTESTED_REFERENCE_ASSURANCE
        reference_set_hash = reference_context.reference_set_hash
        reference_contract_version = reference_context.contract_version
    if _is_sealed_validation_context(validation_context):
        validation_assurance_state = VALIDATION_ASSURANCE_ATTESTED
        validation_evidence_set_hash = validation_context.evidence_set_hash
        validation_evidence_contract_version = validation_context.contract_version
    else:
        validation_assurance_state = VALIDATION_ASSURANCE_UNATTESTED
        validation_evidence_set_hash = None
        validation_evidence_contract_version = None
    case_source_assurance = unbound_case_source_assurance()
    run_id = _run_id_for_current_identity(
        case_hash,
        case_source_assurance=case_source_assurance,
        reference_assurance_state=reference_assurance_state,
        reference_set_hash=reference_set_hash,
        reference_contract_version=reference_contract_version,
        validation_assurance_state=validation_assurance_state,
        validation_evidence_set_hash=validation_evidence_set_hash,
        validation_evidence_contract_version=validation_evidence_contract_version,
    )
    return RunResult(
        run_id=run_id,
        case_id=case["case_id"],
        case_hash=case_hash,
        ruleset_version=RULESET_VERSION,
        run_result_contract_version=RUN_RESULT_CONTRACT_VERSION,
        run_identity_version=RUN_IDENTITY_VERSION,
        **case_source_assurance.to_dict(),
        reference_assurance_state=reference_assurance_state,
        reference_set_hash=reference_set_hash,
        reference_contract_version=reference_contract_version,
        validation_assurance_state=validation_assurance_state,
        validation_evidence_set_hash=validation_evidence_set_hash,
        validation_evidence_contract_version=validation_evidence_contract_version,
        overall_status=_overall_status([finding.status for finding in findings]),
        impact_plan=plan,
        findings=findings,
    )


_LEGACY_RUN_RESULT_KEYS = (
    "run_id",
    "case_id",
    "case_hash",
    "ruleset_version",
    "reference_assurance_state",
    "reference_set_hash",
    "reference_contract_version",
    "validation_assurance_state",
    "validation_evidence_set_hash",
    "validation_evidence_contract_version",
    "overall_status",
    "impact_plan",
    "findings",
)


def legacy_run_result_projection(result: RunResult) -> dict[str, Any]:
    """Return the frozen v3 payload only for an unbound current evaluation."""

    if type(result) is not RunResult:
        raise TypeError("legacy Run projection requires exact RunResult")
    if (
        result.run_result_contract_version != RUN_RESULT_CONTRACT_VERSION
        or result.run_identity_version != RUN_IDENTITY_VERSION
    ):
        raise ValueError("legacy Run projection requires a current RunResult")
    source = {
        key: getattr(result, key)
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
    validate_case_source_assurance_payload(source)
    if source != unbound_case_source_assurance().to_dict():
        raise ValueError("source-rooted RunResult cannot be projected as legacy")
    payload = result.to_dict()
    projected = {key: payload[key] for key in _LEGACY_RUN_RESULT_KEYS}
    projected["run_id"] = _run_id_for_identity(
        result.case_hash,
        reference_assurance_state=result.reference_assurance_state,
        reference_set_hash=result.reference_set_hash,
        reference_contract_version=result.reference_contract_version,
        validation_assurance_state=result.validation_assurance_state,
        validation_evidence_set_hash=result.validation_evidence_set_hash,
        validation_evidence_contract_version=(
            result.validation_evidence_contract_version
        ),
    )
    return projected


@dataclass(frozen=True, slots=True)
class _SourceAssuredEvaluation:
    _case_source_context: _CaseSourceContext
    run: RunResult

    def case(self) -> dict[str, Any]:
        return self._case_source_context.case()


def _evaluate_case_source_bundle(
    bundle: CaseSourceBundle,
    *,
    validation_bundle: ValidationEvidenceBundle | None = None,
    mutation_bundle: CaseMutationBundle | None = None,
) -> _SourceAssuredEvaluation:
    if type(bundle) is not CaseSourceBundle:
        raise TypeError("source-assured evaluation requires exact CaseSourceBundle")
    if validation_bundle is not None and type(validation_bundle) is not (
        ValidationEvidenceBundle
    ):
        raise TypeError("source-assured evaluation requires exact validation raw bytes")
    if mutation_bundle is not None and type(mutation_bundle) is not CaseMutationBundle:
        raise TypeError("source-assured evaluation requires exact mutation raw bytes")
    context = _prepare_case_source_context(bundle)
    if not _is_sealed_case_source_context(context):
        raise TypeError("source-assured evaluation requires a sealed source context")
    if mutation_bundle is not None:
        context = _derive_case_source_mutation(context, mutation_bundle)
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
    run = _evaluate_source_rooted_case(
        case,
        context._reference_context,
        validation_context,
        context,
    )
    expected_case_hash = (
        context.root_case_hash
        if not context.lineages
        else context.lineages[-1].output_case_hash
    )
    if run.case_hash != expected_case_hash:
        raise AssertionError("source-assured Run differs from rebuilt terminal Case")
    return _SourceAssuredEvaluation(context, run)


def _evaluate_source_rooted_case(
    case: dict[str, Any],
    reference_context: _ControlledReferenceContext,
    validation_context: _ValidationEvidenceContext | None,
    context: _CaseSourceContext,
    *,
    expected_validation_phase: str = "SOURCE",
) -> RunResult:
    """Evaluate only from one exact sealed raw-source context.

    ``CaseSourceAssurance`` is a public output value, not a construction
    capability.  This boundary derives the tuple from the sealed context and
    proves that the supplied Case/reference identities are that context's own
    terminal objects before using them in Run identity v4.
    """

    if not _is_sealed_case_source_context(context):
        raise TypeError("source-rooted Run requires a sealed source context")
    if type(case) is not dict or case != context.case():
        raise TypeError("source-rooted Run Case differs from sealed source bytes")
    if reference_context is not context._reference_context:
        raise TypeError("source-rooted Run reference context differs from source bytes")
    if type(expected_validation_phase) is not str or expected_validation_phase not in {
        "SOURCE",
        "RESOLVED",
    }:
        raise TypeError("source-rooted Run validation phase is unsupported")
    if validation_context is not None:
        if (
            not _is_sealed_validation_context(validation_context)
            or validation_context.phase != expected_validation_phase
            or validation_context.case_subject_hash
            != validation_case_subject_hash(case)
            or validation_context.scope_digest != validation_scope_digest(case)
        ):
            raise TypeError(
                "source-rooted Run validation context differs from terminal Case"
            )
    assurance = context.assurance()
    # Reuse the hardened rule evaluation, then replace only the U tuple and
    # identity with values derived inside this sealed boundary.
    unbound = _evaluate_case(case, reference_context, validation_context)
    run_id = _run_id_for_current_identity(
        unbound.case_hash,
        case_source_assurance=assurance,
        reference_assurance_state=unbound.reference_assurance_state,
        reference_set_hash=unbound.reference_set_hash,
        reference_contract_version=unbound.reference_contract_version,
        validation_assurance_state=unbound.validation_assurance_state,
        validation_evidence_set_hash=unbound.validation_evidence_set_hash,
        validation_evidence_contract_version=(
            unbound.validation_evidence_contract_version
        ),
    )
    return RunResult(
        run_id=run_id,
        case_id=unbound.case_id,
        case_hash=unbound.case_hash,
        ruleset_version=unbound.ruleset_version,
        run_result_contract_version=RUN_RESULT_CONTRACT_VERSION,
        run_identity_version=RUN_IDENTITY_VERSION,
        **assurance.to_dict(),
        reference_assurance_state=unbound.reference_assurance_state,
        reference_set_hash=unbound.reference_set_hash,
        reference_contract_version=unbound.reference_contract_version,
        validation_assurance_state=unbound.validation_assurance_state,
        validation_evidence_set_hash=unbound.validation_evidence_set_hash,
        validation_evidence_contract_version=(
            unbound.validation_evidence_contract_version
        ),
        overall_status=unbound.overall_status,
        impact_plan=unbound.impact_plan,
        findings=unbound.findings,
    )


def run_case_with_source_bundle(
    bundle: CaseSourceBundle,
    validation_bundle: ValidationEvidenceBundle | None = None,
) -> RunResult:
    """Evaluate one exact raw source bundle without accepting a Case object."""

    return _evaluate_case_source_bundle(
        bundle,
        validation_bundle=validation_bundle,
    ).run


def run_case_with_source_mutation_bundle(
    bundle: CaseSourceBundle,
    mutation_bundle: CaseMutationBundle,
    validation_bundle: ValidationEvidenceBundle | None = None,
) -> RunResult:
    """Apply one exact raw mutation and evaluate its source-rooted lineage."""

    return _evaluate_case_source_bundle(
        bundle,
        mutation_bundle=mutation_bundle,
        validation_bundle=validation_bundle,
    ).run


def run_case(case: dict[str, Any]) -> RunResult:
    """Run an untrusted JSON case.

    Controlled-reference PASS requires an internal raw-byte context and can
    therefore never be obtained by adding a marker or identity object to JSON.
    """

    return _evaluate_case(case, None)


def _run_case_with_reference_context(
    case: dict[str, Any],
    reference_context: _ControlledReferenceContext,
    validation_context: _ValidationEvidenceContext | None = None,
) -> RunResult:
    if not _is_sealed_reference_context(reference_context):
        raise TypeError("actual controlled-reference run requires an internal sealed context")
    if validation_context is not None and not _is_sealed_validation_context(
        validation_context
    ):
        raise TypeError("actual validation run requires an internal sealed context")
    return _evaluate_case(case, reference_context, validation_context)


def run_case_from_pack(
    manifest_path: str | Path,
    mutation_path: str | Path | None = None,
    validation_manifest_path: str | Path | None = None,
) -> RunResult:
    """Capture one controlled pack and run with its internally sealed context."""

    bundle = load_case_source_bundle(manifest_path)
    validation_bundle = (
        None
        if validation_manifest_path is None
        else load_validation_evidence_bundle(validation_manifest_path)
    )
    if mutation_path is None:
        return run_case_with_source_bundle(bundle, validation_bundle)
    return run_case_with_source_mutation_bundle(
        bundle,
        load_case_mutation_bundle(mutation_path),
        validation_bundle,
    )


def run_case_with_reference_bundle(
    case: dict[str, Any],
    reference_bundle: ControlledReferenceBundle,
) -> RunResult:
    """Rebuild a sealed context from supplied raw bytes inside this call."""

    if type(reference_bundle) is not ControlledReferenceBundle:
        raise TypeError("actual controlled-reference run requires a raw reference bundle")
    context = _prepare_controlled_reference_context(reference_bundle)
    return _run_case_with_reference_context(case, context)


def run_case_with_evidence_bundles(
    case: dict[str, Any],
    reference_bundle: ControlledReferenceBundle,
    validation_bundle: ValidationEvidenceBundle,
    *,
    validation_phase: str = "SOURCE",
) -> RunResult:
    """Rebuild both sealed contexts from immutable raw bytes in one call."""

    if type(reference_bundle) is not ControlledReferenceBundle:
        raise TypeError("actual run requires an exact controlled-reference bundle")
    if type(validation_bundle) is not ValidationEvidenceBundle:
        raise TypeError("actual run requires an exact raw validation bundle")
    prepared = prepare_case(case)
    reference_context = _prepare_controlled_reference_context(reference_bundle)
    validation_context = _prepare_validation_evidence_context(
        validation_bundle,
        prepared,
        expected_phase=validation_phase,
    )
    return _run_case_with_reference_context(
        prepared,
        reference_context,
        validation_context,
    )
