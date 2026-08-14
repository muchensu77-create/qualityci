from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .approval_subject import (
    validate_approval_assertions,
    validate_approval_subject,
)
from .authorization_records import load_authorization_record_bundle
from .authorization_authenticity import (
    AUTHORIZATION_AUTHENTICITY_PASS,
    load_authorization_trust_snapshot_bundle,
    prepare_authorization_authenticity_context,
    require_authenticated_assertion_records,
)
from .loader import load_case, load_json, strict_json_loads
from .case_source_assurance import (
    load_case_mutation_bundle,
    load_case_source_bundle,
)
from .controlled_references import (
    ControlledReferenceBundle,
    _ControlledReferenceContext,
    load_controlled_reference_bundle,
)
from .models import RunResult
from .orchestration import (
    agent_identity_manifest,
    run_agent_team,
    run_agent_team_with_source_bundle,
    _run_agent_team_with_reference_context,
)
from .revision_artifacts import RevisionArtifactBundle, load_revision_artifact_bundle
from .validation_evidence import (
    ValidationEvidenceBundle,
    _ValidationEvidenceContext,
    _prepare_validation_evidence_context,
    load_validation_evidence_bundle,
)
from .workflow import (
    ApprovalGateError,
    REQUIRED_APPROVAL_ROLES,
    native_resolution_approval_subject,
    preview_resolution,
    replay_with_native_approval,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_ROOT = PROJECT_ROOT / "datasets" / "qualityci-bench" / "tacoma_24v152"
STATIC_ROOT = PROJECT_ROOT / "apps" / "web_demo"
SOURCE_PACK_ROOT = PROJECT_ROOT / "tests" / "fixtures" / "case_builder"
CASE_PATH = DATA_ROOT / "baseline_v04.json"
REFERENCE_MANIFEST_PATH = DATA_ROOT / "reference_sources" / "manifest.json"
VALIDATION_MANIFEST_PATHS: dict[str, Path] = {
    "BASELINE": DATA_ROOT / "validation_sources" / "BASELINE" / "source" / "manifest.json",
    "M001_STALE_SOP_CONFLICT": DATA_ROOT / "validation_sources" / "R001" / "source" / "manifest.json",
}
RESOLVED_VALIDATION_MANIFEST_PATHS: dict[str, Path] = {
    "RES-SYN-001": DATA_ROOT / "validation_sources" / "R001" / "resolved" / "manifest.json",
}

# The browser can select only these repository-owned fixtures. File-system paths
# are never accepted from requests.
MUTATION_PATHS: dict[str, Path | None] = {
    "BASELINE": None,
    "M001_STALE_SOP_CONFLICT": DATA_ROOT / "mutations" / "M001_stale_sop_conflict.json",
    "M002_MISSING_VALIDATION": DATA_ROOT / "mutations" / "M002_missing_validation.json",
    "M003_MISSING_REACTION_PLAN": DATA_ROOT / "mutations" / "M003_missing_reaction_plan.json",
    "M004_MISSING_QUALITY_APPROVAL": DATA_ROOT / "mutations" / "M004_missing_quality_approval.json",
    "M005_INSPECTION_OLD_REFERENCE": DATA_ROOT / "mutations" / "M005_inspection_old_reference.json",
    "M006_MISSING_SOP_SPEC": DATA_ROOT / "mutations" / "M006_missing_sop_spec.json",
    "M007_PFMEA_MISSING_AFFECTED_STEP": DATA_ROOT / "mutations" / "M007_pfmea_missing_affected_step.json",
    "M008_CONTROL_PLAN_MISSING_AFFECTED_STEP": DATA_ROOT / "mutations" / "M008_control_plan_missing_affected_step.json",
    "M009_MISSING_AFFECTED_PROCESS_SCOPE": DATA_ROOT / "mutations" / "M009_missing_affected_process_scope.json",
    "M010_MISSING_AFFECTED_CHARACTERISTIC_SCOPE": DATA_ROOT / "mutations" / "M010_missing_affected_characteristic_scope.json",
    "M011_SOP_UNIT_CONFLICT": DATA_ROOT / "mutations" / "M011_sop_unit_conflict.json",
    "M012_INSPECTION_LIMIT_CONFLICT": DATA_ROOT / "mutations" / "M012_inspection_limit_conflict.json",
    "M013_CONTROL_PLAN_CHARACTERISTIC_ABSENT": DATA_ROOT / "mutations" / "M013_control_plan_characteristic_absent.json",
    "M014_MISSING_CONTROL_METHOD": DATA_ROOT / "mutations" / "M014_missing_control_method.json",
    "M015_MISSING_CONTROL_FREQUENCY": DATA_ROOT / "mutations" / "M015_missing_control_frequency.json",
    "M016_NON_SPECIAL_CHARACTERISTIC_BOUNDARY": DATA_ROOT / "mutations" / "M016_non_special_characteristic_boundary.json",
    "M017_MISSING_CHANGE_APPROVAL_DATE": DATA_ROOT / "mutations" / "M017_missing_change_approval_date.json",
    "M018_APPROVED_WAIVER_BOUNDARY": DATA_ROOT / "mutations" / "M018_approved_waiver_boundary.json",
    "M019_STALE_PROCESS_FLOW_WITHOUT_WAIVER": DATA_ROOT / "mutations" / "M019_stale_process_flow_without_waiver.json",
    "M020_STALE_SOP_DATE_CURRENT_REVISION": DATA_ROOT / "mutations" / "M020_stale_sop_date_current_revision.json",
    "M021_MISSING_INSPECTION_REFERENCES": DATA_ROOT / "mutations" / "M021_missing_inspection_references.json",
    "M022_INSPECTION_REFERENCE_EXTRA_DOCUMENT": DATA_ROOT / "mutations" / "M022_inspection_reference_extra_document.json",
    "M023_FAILED_VALIDATION_RESULT": DATA_ROOT / "mutations" / "M023_failed_validation_result.json",
    "M024_VALIDATION_MISSING_LOCATOR": DATA_ROOT / "mutations" / "M024_validation_missing_locator.json",
    "M025_MIXED_VALIDATION_BATCH": DATA_ROOT / "mutations" / "M025_mixed_validation_batch.json",
    "M026_MEDIUM_RISK_WITHOUT_APPROVALS_BOUNDARY": DATA_ROOT / "mutations" / "M026_medium_risk_without_approvals_boundary.json",
    "M027_HIGH_RISK_NO_APPROVALS": DATA_ROOT / "mutations" / "M027_high_risk_no_approvals.json",
    "M028_STALE_REVISION_APPROVALS": DATA_ROOT / "mutations" / "M028_stale_revision_approvals.json",
    "M029_APPROVAL_DATE_AFTER_ALL_DOCUMENTS": DATA_ROOT / "mutations" / "M029_approval_date_after_all_documents.json",
    "M030_MULTI_RULE_RELEASE_BLOCKER": DATA_ROOT / "mutations" / "M030_multi_rule_release_blocker.json",
}

RESOLUTION_PATHS: dict[str, Path] = {
    "RES-SYN-001": DATA_ROOT / "resolutions" / "R001_resolve_stale_sop_native.json",
    "RES-SYN-BLOCKED": DATA_ROOT / "resolutions" / "R002_unapproved_resolution.json",
}

APPROVAL_SOURCE_PATHS: dict[str, dict[str, Path]] = {
    "RES-SYN-001": {
        "subject": DATA_ROOT / "approval_sources" / "R001" / "approval_subject.json",
        "assertions": DATA_ROOT
        / "approval_sources"
        / "R001"
        / "approval_assertions.json",
        "authorization": DATA_ROOT
        / "approval_sources"
        / "R001"
        / "authorization_a06"
        / "manifest.json",
        "authorization_trust": DATA_ROOT
        / "approval_sources"
        / "R001"
        / "authorization_trust"
        / "snapshot.json",
    }
}

RESOLUTION_MUTATIONS: dict[str, str] = {
    "RES-SYN-001": "M001_STALE_SOP_CONFLICT",
    "RES-SYN-BLOCKED": "M001_STALE_SOP_CONFLICT",
}

REPLACEMENT_MANIFEST_PATHS: dict[str, Path] = {
    "RES-SYN-001": DATA_ROOT / "replacement_artifacts" / "R001" / "manifest.json",
}

# A request can select only these opaque identifiers.  The paths and every raw
# member remain server-owned; no client Case, path, member, context, marker, or
# digest is accepted as a substitute.  This synthetic pack intentionally does
# not share identifiers with the legacy Tacoma mutation/replay catalog.
SOURCE_PACK_PATHS: dict[str, Path] = {
    "CASE_BUILDER_SYNTHETIC": SOURCE_PACK_ROOT / "manifest.json",
}
SOURCE_PACK_VALIDATION_PATHS: dict[str, Path] = {
    "CASE_BUILDER_SYNTHETIC": SOURCE_PACK_ROOT / "validation_manifest.json",
}
SOURCE_PACK_MUTATION_PATHS: dict[str, dict[str, Path | None]] = {
    "CASE_BUILDER_SYNTHETIC": {"BASELINE": None},
}

STATIC_FILES: dict[str, tuple[Path, str]] = {
    "/": (STATIC_ROOT / "index.html", "text/html; charset=utf-8"),
    "/index.html": (STATIC_ROOT / "index.html", "text/html; charset=utf-8"),
    "/app.js": (STATIC_ROOT / "app.js", "text/javascript; charset=utf-8"),
    "/styles.css": (STATIC_ROOT / "styles.css", "text/css; charset=utf-8"),
}

MAX_REQUEST_BYTES = 16 * 1024
REQUEST_READ_TIMEOUT_SECONDS = 3.0
MAX_CONCURRENT_REQUESTS = 16
BUSY_REQUEST_DRAIN_TIMEOUT_SECONDS = 0.25
BUSY_REQUEST_DRAIN_MAX_BYTES = 64 * 1024
ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
SECURITY_HEADERS = (
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    (
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
        "form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
    ),
)


class DemoRequestError(ValueError):
    """A safe client-facing error for malformed or unsupported demo input."""

    def __init__(self, message: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


def _assert_predefined_file(path: Path, allowed_root: Path) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(allowed_root.resolve(strict=True))
    except ValueError as error:
        raise RuntimeError("demo catalog points outside its allowed repository directory") from error
    return resolved


def validate_demo_assets() -> None:
    """Fail fast if a hard-coded fixture or static asset is missing or mismatched."""

    _assert_predefined_file(CASE_PATH, DATA_ROOT)
    _assert_predefined_file(REFERENCE_MANIFEST_PATH, DATA_ROOT / "reference_sources")
    for path in (*VALIDATION_MANIFEST_PATHS.values(), *RESOLVED_VALIDATION_MANIFEST_PATHS.values()):
        _assert_predefined_file(path, DATA_ROOT / "validation_sources")
    for mutation_id, path in MUTATION_PATHS.items():
        if path is None:
            continue
        payload = load_json(_assert_predefined_file(path, DATA_ROOT / "mutations"))
        if payload.get("mutation_id") != mutation_id:
            raise RuntimeError(f"mutation catalog mismatch: {mutation_id}")
    for resolution_id, path in RESOLUTION_PATHS.items():
        payload = load_json(_assert_predefined_file(path, DATA_ROOT / "resolutions"))
        if payload.get("resolution_id") != resolution_id:
            raise RuntimeError(f"resolution catalog mismatch: {resolution_id}")
    for resolution_id, paths in APPROVAL_SOURCE_PATHS.items():
        if resolution_id not in RESOLUTION_PATHS:
            raise RuntimeError("approval sources are not bound to a resolution")
        for path in paths.values():
            _assert_predefined_file(path, DATA_ROOT / "approval_sources")
    for resolution_id, path in REPLACEMENT_MANIFEST_PATHS.items():
        if resolution_id not in RESOLUTION_PATHS:
            raise RuntimeError("replacement manifest is not bound to a resolution")
        _assert_predefined_file(path, DATA_ROOT / "replacement_artifacts")
    if set(SOURCE_PACK_PATHS) != set(SOURCE_PACK_VALIDATION_PATHS) or set(
        SOURCE_PACK_PATHS
    ) != set(SOURCE_PACK_MUTATION_PATHS):
        raise RuntimeError("source-pack allowlist identities disagree")
    for source_pack_id, path in SOURCE_PACK_PATHS.items():
        _assert_predefined_file(path, SOURCE_PACK_ROOT)
        _assert_predefined_file(
            SOURCE_PACK_VALIDATION_PATHS[source_pack_id],
            SOURCE_PACK_ROOT,
        )
        for mutation_path in SOURCE_PACK_MUTATION_PATHS[source_pack_id].values():
            if mutation_path is not None:
                _assert_predefined_file(mutation_path, SOURCE_PACK_ROOT)
    for path, _content_type in STATIC_FILES.values():
        _assert_predefined_file(path, STATIC_ROOT)


def _replacement_bundle(resolution_id: str) -> RevisionArtifactBundle | None:
    path = REPLACEMENT_MANIFEST_PATHS.get(resolution_id)
    return load_revision_artifact_bundle(path) if path is not None else None


def _reference_bundle() -> ControlledReferenceBundle:
    return load_controlled_reference_bundle(REFERENCE_MANIFEST_PATH)


def _validation_bundle_for_mutation(
    mutation_id: str,
) -> ValidationEvidenceBundle | None:
    path = VALIDATION_MANIFEST_PATHS.get(mutation_id)
    return load_validation_evidence_bundle(path) if path is not None else None


def _resolved_validation_bundle(resolution_id: str) -> ValidationEvidenceBundle:
    path = RESOLVED_VALIDATION_MANIFEST_PATHS.get(resolution_id)
    if path is None:
        raise ApprovalGateError(
            "resolution blocked; no predefined RESOLVED validation raw bundle"
        )
    return load_validation_evidence_bundle(path)


def _native_approval_material(
    resolution_id: str,
    resolution: dict[str, Any],
    case: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], Any, Any, Any] | None:
    paths = APPROVAL_SOURCE_PATHS.get(resolution_id)
    bundle = _replacement_bundle(resolution_id)
    if paths is None or bundle is None:
        return None
    subject = load_json(paths["subject"])
    assertion_document = load_json(paths["assertions"])
    if set(assertion_document) != {"assertions"} or type(
        assertion_document["assertions"]
    ) is not list:
        raise ApprovalGateError(
            "predefined approval assertion document has an invalid root"
        )
    assertions = assertion_document["assertions"]
    authorization_bundle = load_authorization_record_bundle(paths["authorization"])
    authorization_trust_bundle = load_authorization_trust_snapshot_bundle(
        paths["authorization_trust"]
    )
    expected_subject = native_resolution_approval_subject(
        resolution,
        case,
        execution_nonce=subject.get("execution_nonce", ""),
        artifact_bundle=bundle,
        reference_bundle=_reference_bundle(),
    )
    validate_approval_subject(subject, expected=expected_subject)
    authenticity_context = prepare_authorization_authenticity_context(
        authorization_bundle,
        authorization_trust_bundle,
    )
    if authenticity_context.state != AUTHORIZATION_AUTHENTICITY_PASS:
        raise ApprovalGateError(
            "authorization authenticity is not PASS: "
            f"{authenticity_context.state}"
        )
    validate_approval_assertions(
        subject,
        assertions,
        authenticity_context.record_context,
    )
    require_authenticated_assertion_records(assertions, authenticity_context)
    return (
        subject,
        assertions,
        authorization_bundle,
        authorization_trust_bundle,
        authenticity_context,
    )


def _approval_roles(
    resolution_id: str, resolution: dict[str, Any], case: dict[str, Any]
) -> set[str]:
    bundle = _replacement_bundle(str(resolution.get("resolution_id", "")))
    if bundle is None:
        return set()
    material = _native_approval_material(
        resolution_id, resolution, case
    )
    if material is None:
        return set()
    (
        subject,
        assertions,
        _authorization_bundle,
        _trust_bundle,
        authenticity_context,
    ) = material
    validation = validate_approval_assertions(
        subject,
        assertions,
        authenticity_context.record_context,
    )
    require_authenticated_assertion_records(assertions, authenticity_context)
    return set(validation.approved_roles)


def catalog_payload() -> dict[str, Any]:
    case = load_case(CASE_PATH)
    mutations: list[dict[str, Any]] = [
        {
            "mutation_id": "BASELINE",
            "description": "无故障注入：所有规则应通过。",
            "expected_rule_statuses": {},
        }
    ]
    for mutation_id, path in MUTATION_PATHS.items():
        if path is None:
            continue
        payload = load_json(path)
        mutations.append(
            {
                "mutation_id": mutation_id,
                "description": str(payload.get("description", "")),
                "expected_rule_statuses": payload.get("expected_rule_statuses", {}),
            }
        )

    resolutions: list[dict[str, Any]] = []
    for resolution_id, path in RESOLUTION_PATHS.items():
        payload = load_json(path)
        resolutions.append(
            {
                "resolution_id": resolution_id,
                "description": str(payload.get("description", "")),
                "approved_roles": [],
                "approval_ready": False,
                "trusted_replay_state": "BLOCKED_MISSING_A08_SOURCE_ROOT",
            }
        )

    return {
        "case": _case_summary(case),
        "default_mutation_id": "M001_STALE_SOP_CONFLICT",
        "mutations": mutations,
        "resolutions": resolutions,
        "guardrails": {
            "synthetic_only": True,
            "predefined_fixtures_only": True,
            "human_approval_required_for_high_risk": True,
            "approval_records": "PREDEFINED_NATIVE_BYTE_BOUND_RECORDS",
            "baseline_persistence": "DEMO_RESPONSE_ONLY",
            "agent_runtime": "LOCAL_DETERMINISTIC_CONTRACT",
            "agentteams_runtime": "NEXT",
            "legacy_catalog_trust": "EVALUATION_UNBOUND",
            "source_pack_ids": sorted(SOURCE_PACK_PATHS),
        },
    }


def _case_summary(case: dict[str, Any]) -> dict[str, Any]:
    event = case["event"]
    return {
        "case_id": case["case_id"],
        "title": case.get("title", ""),
        "synthetic_for_competition": case.get("synthetic_for_competition") is True,
        "event": {
            "event_id": event.get("event_id", ""),
            "event_type": event.get("event_type", ""),
            "revision": event.get("revision", ""),
            "risk_level": event.get("risk_level", ""),
            "change_summary": event.get("change_summary", ""),
            "affected_process_steps": event.get("affected_process_steps", []),
            "affected_characteristics": event.get("affected_characteristics", []),
        },
        "documents": [
            {
                "document_id": doc.get("document_id", ""),
                "document_type": doc.get("document_type", ""),
                "revision": doc.get("revision", ""),
                "owner": doc.get("owner", ""),
                "status": doc.get("status", ""),
            }
            for doc in case.get("documents", [])
        ],
    }


def _select_mutation(mutation_id: Any, *, allow_baseline: bool = True) -> Path | None:
    if not isinstance(mutation_id, str) or mutation_id not in MUTATION_PATHS:
        raise DemoRequestError("unknown mutation_id; select a predefined catalog item")
    if mutation_id == "BASELINE" and not allow_baseline:
        raise DemoRequestError("replay requires a predefined fault injection")
    return MUTATION_PATHS[mutation_id]


def _select_resolution(resolution_id: Any) -> Path:
    if not isinstance(resolution_id, str) or resolution_id not in RESOLUTION_PATHS:
        raise DemoRequestError("unknown resolution_id; select a predefined catalog item")
    return RESOLUTION_PATHS[resolution_id]


def _agent_team_payload(
    case: dict[str, Any],
    *,
    reference_bundle: ControlledReferenceBundle | None = None,
    reference_context: _ControlledReferenceContext | None = None,
    validation_bundle: ValidationEvidenceBundle | None = None,
    validation_context: _ValidationEvidenceContext | None = None,
) -> tuple[dict[str, Any], RunResult]:
    if reference_context is not None:
        team_run = _run_agent_team_with_reference_context(
            case, reference_context, validation_context
        )
    else:
        team_run = run_agent_team(
            case,
            reference_bundle=reference_bundle,
            validation_bundle=validation_bundle,
        )
    payload = team_run.to_dict()
    payload["agents"] = agent_identity_manifest()
    payload["runtime_next"] = "AgentTeams runtime Next"
    return payload, team_run.run


def run_payload(request: dict[str, Any]) -> dict[str, Any]:
    if type(request) is not dict:
        raise DemoRequestError(
            "run request must contain only mutation_id, or source_pack_id and "
            "mutation_id"
        )
    if set(request) == {"source_pack_id", "mutation_id"}:
        return _source_pack_run_payload(
            request["source_pack_id"],
            request["mutation_id"],
        )
    if set(request) != {"mutation_id"}:
        raise DemoRequestError(
            "run request must contain only mutation_id, or source_pack_id and "
            "mutation_id"
        )
    mutation_id = request["mutation_id"]
    mutation_path = _select_mutation(mutation_id)
    case = load_case(CASE_PATH, mutation_path)
    validation_bundle = _validation_bundle_for_mutation(mutation_id)
    agent_team, result = _agent_team_payload(
        case,
        reference_bundle=_reference_bundle(),
        validation_bundle=validation_bundle,
    )
    mutation = load_json(mutation_path) if mutation_path else {}
    return {
        "ok": True,
        "mode": "RUN_EVALUATION_UNBOUND",
        "trusted": False,
        "admission": "BLOCKED",
        "mutation_id": mutation_id,
        "mutation_description": mutation.get("description", "无故障注入：基线回归。"),
        "expected_rule_statuses": mutation.get("expected_rule_statuses", {}),
        "case": _case_summary(case),
        "result": result.to_dict(),
        "agent_team": agent_team,
    }


def _source_pack_run_payload(
    source_pack_id: Any,
    mutation_id: Any,
) -> dict[str, Any]:
    if type(source_pack_id) is not str or source_pack_id not in SOURCE_PACK_PATHS:
        raise DemoRequestError(
            "unknown source_pack_id; select a server-owned allowlisted pack"
        )
    mutation_catalog = SOURCE_PACK_MUTATION_PATHS[source_pack_id]
    if type(mutation_id) is not str or mutation_id not in mutation_catalog:
        raise DemoRequestError(
            "unknown source-pack mutation_id; select an allowlisted material"
        )
    manifest_path = _assert_predefined_file(
        SOURCE_PACK_PATHS[source_pack_id],
        SOURCE_PACK_ROOT,
    )
    validation_path = _assert_predefined_file(
        SOURCE_PACK_VALIDATION_PATHS[source_pack_id],
        SOURCE_PACK_ROOT,
    )
    mutation_path = mutation_catalog[mutation_id]
    mutation_bundle = (
        None
        if mutation_path is None
        else load_case_mutation_bundle(
            _assert_predefined_file(mutation_path, SOURCE_PACK_ROOT)
        )
    )
    source_bundle = load_case_source_bundle(manifest_path)
    validation_bundle = load_validation_evidence_bundle(validation_path)
    team_run = run_agent_team_with_source_bundle(
        source_bundle,
        mutation_bundle=mutation_bundle,
        validation_bundle=validation_bundle,
    )
    agent_team = team_run.to_dict()
    agent_team["agents"] = agent_identity_manifest()
    agent_team["runtime_next"] = "AgentTeams runtime Next"
    return {
        "ok": True,
        "mode": "SOURCE_ROOTED_RUN",
        "trusted": True,
        "source_pack_id": source_pack_id,
        "mutation_id": mutation_id,
        "result": team_run.run.to_dict(),
        "agent_team": agent_team,
    }


def replay_payload(request: dict[str, Any]) -> dict[str, Any]:
    if type(request) is not dict or set(request) != {
        "mutation_id",
        "resolution_id",
        "run_id",
    }:
        raise DemoRequestError(
            "replay request must contain only mutation_id, resolution_id, and run_id"
        )
    mutation_id = request.get("mutation_id")
    resolution_id = request.get("resolution_id")
    _select_mutation(mutation_id, allow_baseline=False)
    _select_resolution(resolution_id)
    if RESOLUTION_MUTATIONS[resolution_id] != mutation_id:
        raise DemoRequestError(
            "resolution is not bound to the selected mutation; rerun the supported scenario",
            HTTPStatus.CONFLICT,
        )
    raise ApprovalGateError(
        "A08_SOURCE_PACK_REQUIRED: the legacy Tacoma catalog has no matching "
        "whole-Case raw source pack, ApprovalSubject 0.2, and ordered lineage "
        "materials; replay and baseline are blocked"
    )


def preview_payload(request: dict[str, Any]) -> dict[str, Any]:
    if type(request) is not dict or set(request) != {
        "mutation_id",
        "resolution_id",
    }:
        raise DemoRequestError(
            "preview request must contain only mutation_id and resolution_id"
        )
    mutation_id = request["mutation_id"]
    resolution_id = request["resolution_id"]
    mutation_path = _select_mutation(mutation_id, allow_baseline=False)
    resolution_path = _select_resolution(resolution_id)
    case = load_case(CASE_PATH, mutation_path)
    preview = preview_resolution(case, load_json(resolution_path))
    return {
        "ok": True,
        "mode": "PROPOSAL_PREVIEW",
        "state": "PROPOSED_UNATTESTED",
        "trusted": False,
        "eligible_for_baseline": False,
        "notice": "Estimated findings are not an attested PASS or actual RunResult.",
        "preview": preview.to_dict(),
    }


class QualityCIDemoHandler(BaseHTTPRequestHandler):
    server_version = "QualityCIDemo/0.1"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.request_timeout_seconds)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Keep tests and live demos quiet. The page itself exposes run identifiers.
        return

    def _security_headers(self) -> None:
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)

    def end_headers(self) -> None:
        self._security_headers()
        super().end_headers()

    def _send_bytes(
        self,
        status: HTTPStatus,
        payload: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            # A browser tab can close or abort a request at any point. That is
            # expected demo traffic and must not produce a server traceback.
            return

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        self._send_bytes(status, encoded, "application/json; charset=utf-8")

    def _read_json_object(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise DemoRequestError("Content-Type must be application/json", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise DemoRequestError("Content-Length is required", HTTPStatus.LENGTH_REQUIRED)
        try:
            length = int(raw_length)
        except ValueError as error:
            raise DemoRequestError("invalid Content-Length") from error
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise DemoRequestError("request body exceeds demo limit", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                raise DemoRequestError("request body ended before Content-Length")
            payload = strict_json_loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise DemoRequestError("request body must be valid UTF-8 JSON") from error
        if not isinstance(payload, dict):
            raise DemoRequestError("request JSON must be an object")
        return payload

    def _validate_host(self) -> str:
        raw_host = self.headers.get("Host")
        if not raw_host:
            raise DemoRequestError("Host header is required")
        try:
            parsed = urlsplit(f"//{raw_host}")
            hostname = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port
        except ValueError as error:
            raise DemoRequestError("invalid Host header") from error
        if (
            hostname not in ALLOWED_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or (port is not None and port != self.server.server_address[1])
        ):
            raise DemoRequestError("Host header is not allowed", HTTPStatus.MISDIRECTED_REQUEST)
        return hostname

    def _validate_origin(self, request_hostname: str) -> None:
        origin = self.headers.get("Origin")
        if origin is None:
            return
        try:
            parsed = urlsplit(origin)
            hostname = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port if parsed.port is not None else 80
        except ValueError as error:
            raise DemoRequestError("invalid Origin header", HTTPStatus.FORBIDDEN) from error
        if (
            parsed.scheme != "http"
            or hostname not in ALLOWED_HOSTS
            or hostname != request_hostname
            or port != self.server.server_address[1]
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise DemoRequestError("cross-origin requests are not allowed", HTTPStatus.FORBIDDEN)

    def _validate_request_context(self, *, state_changing: bool = False) -> bool:
        try:
            request_hostname = self._validate_host()
            if state_changing:
                self._validate_origin(request_hostname)
        except DemoRequestError as error:
            self._send_json(error.status, {"ok": False, "error": str(error)})
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._validate_request_context():
            return
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._send_json(HTTPStatus.OK, {"ok": True, "service": "qualityci-web-demo"})
            return
        if path == "/api/catalog":
            self._send_json(HTTPStatus.OK, catalog_payload())
            return
        static = STATIC_FILES.get(path)
        if static is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "route not found"})
            return
        file_path, content_type = static
        try:
            safe_path = _assert_predefined_file(file_path, STATIC_ROOT)
            payload = safe_path.read_bytes()
        except (OSError, RuntimeError):
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "demo asset unavailable"})
            return
        self._send_bytes(HTTPStatus.OK, payload, content_type)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_OPTIONS(self) -> None:  # noqa: N802
        if not self._validate_request_context(state_changing=True):
            return
        self._send_bytes(
            HTTPStatus.NO_CONTENT,
            b"",
            "text/plain; charset=utf-8",
            {"Allow": "GET, HEAD, POST, OPTIONS"},
        )

    def do_POST(self) -> None:  # noqa: N802
        if not self._validate_request_context(state_changing=True):
            return
        path = urlsplit(self.path).path
        if path not in {"/api/run", "/api/replay", "/api/preview"}:
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "route not found"})
            return
        try:
            request = self._read_json_object()
            if path == "/api/run":
                self._send_json(HTTPStatus.OK, run_payload(request))
                return
            if path == "/api/preview":
                self._send_json(HTTPStatus.OK, preview_payload(request))
                return
            try:
                payload = replay_payload(request)
            except ApprovalGateError as error:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {
                        "ok": False,
                        "mode": "REPLAY",
                        "status": "BLOCKED",
                        "mutation_id": request.get("mutation_id"),
                        "resolution_id": request.get("resolution_id"),
                        "source_run_id": request.get("run_id"),
                        "approval_mode": "SOURCE_ROOTED_RAW_MATERIAL_REQUIRED",
                        "error": str(error),
                    },
                )
                return
            self._send_json(HTTPStatus.OK, payload)
        except DemoRequestError as error:
            self._send_json(error.status, {"ok": False, "error": str(error)})
        except (socket.timeout, TimeoutError):
            self._send_json(
                HTTPStatus.REQUEST_TIMEOUT,
                {"ok": False, "error": "request body read timed out"},
            )
        except (OSError, ValueError):
            # Avoid leaking repository paths or implementation details to the browser.
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error": "predefined demo data could not be processed"},
            )


class QualityCIDemoServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        request_timeout_seconds: float = REQUEST_READ_TIMEOUT_SECONDS,
        max_concurrent_requests: int = MAX_CONCURRENT_REQUESTS,
    ) -> None:
        if request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if max_concurrent_requests <= 0:
            raise ValueError("max_concurrent_requests must be positive")
        self.request_timeout_seconds = request_timeout_seconds
        self.max_concurrent_requests = max_concurrent_requests
        self._request_slots = threading.BoundedSemaphore(max_concurrent_requests)
        super().__init__(server_address, handler_class)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._request_slots.acquire(blocking=False):
            try:
                self._reject_busy(request)
            finally:
                # The busy path has already half-closed and drained the socket.
                # Calling shutdown_request() here would issue another shutdown
                # before close and can discard the response on Windows.
                self.close_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def _reject_busy(self, request: socket.socket) -> None:
        payload = b'{"ok":false,"error":"demo request capacity reached"}'
        headers = [
            "HTTP/1.0 503 Service Unavailable",
            "Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(payload)}",
            "Connection: close",
            *(f"{name}: {value}" for name, value in SECURITY_HEADERS),
            "",
            "",
        ]
        try:
            request.sendall("\r\n".join(headers).encode("ascii") + payload)
        except OSError:
            return
        try:
            request.shutdown(socket.SHUT_WR)
        except OSError:
            # A completed send may still be readable by the peer.  Continue
            # the bounded drain instead of turning this into an immediate
            # abort on platforms with stricter shutdown timing.
            pass

        deadline = time.monotonic() + BUSY_REQUEST_DRAIN_TIMEOUT_SECONDS
        bytes_left = BUSY_REQUEST_DRAIN_MAX_BYTES
        while bytes_left:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                break
            try:
                request.settimeout(timeout)
                chunk = request.recv(min(bytes_left, 8192))
            except (OSError, TimeoutError):
                break
            if not chunk:
                break
            bytes_left -= len(chunk)

    def handle_error(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout)):
            # Browser aborts are normal demo traffic, not application failures.
            return
        super().handle_error(request, client_address)


def make_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    request_timeout_seconds: float = REQUEST_READ_TIMEOUT_SECONDS,
    max_concurrent_requests: int = MAX_CONCURRENT_REQUESTS,
) -> QualityCIDemoServer:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("the local demo binds only to localhost")
    validate_demo_assets()
    return QualityCIDemoServer(
        (host, port),
        QualityCIDemoHandler,
        request_timeout_seconds=request_timeout_seconds,
        max_concurrent_requests=max_concurrent_requests,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local QualityCI competition demo")
    parser.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "localhost"))
    parser.add_argument("--port", type=int, default=8765)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    server = make_server(args.host, args.port)
    host, port = server.server_address[:2]
    print(f"QualityCI demo: http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
