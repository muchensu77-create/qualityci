from __future__ import annotations

import json
import socket
import threading
from http import HTTPStatus
from http.client import HTTPConnection
from typing import Any

import pytest

from qualityci.web_demo import SECURITY_HEADERS, make_server


@pytest.fixture()
def demo_address():
    server = make_server(port=0, request_timeout_seconds=0.25)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(
    address: tuple[str, int],
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    headers.update(extra_headers or {})
    connection = HTTPConnection(*address, timeout=3)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, dict(response.headers), response.read()
    finally:
        connection.close()


def post(address: tuple[str, int], path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    status, _headers, body = request(address, "POST", path, payload)
    return status, json.loads(body.decode("utf-8"))


def run_fixture(address: tuple[str, int], mutation_id: str = "M001_STALE_SOP_CONFLICT") -> dict[str, Any]:
    status, payload = post(address, "/api/run", {"mutation_id": mutation_id})
    assert status == HTTPStatus.OK
    return payload


def assert_security_headers(headers: dict[str, str]) -> None:
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "object-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"


def test_homepage_is_served_with_security_and_synthetic_label(demo_address):
    status, headers, body = request(demo_address, "GET", "/")
    page = body.decode("utf-8")
    assert status == HTTPStatus.OK
    assert "QualityCI" in page
    assert "合成数据" in page
    assert "预置合成批准记录" in page
    assert "LOCAL_DETERMINISTIC_CONTRACT" in page
    assert "AgentTeams runtime Next" in page
    assert_security_headers(headers)


def test_catalog_marks_legacy_resolutions_unready_and_lists_source_pack_allowlist(
    demo_address,
):
    status, _headers, body = request(demo_address, "GET", "/api/catalog")
    assert status == HTTPStatus.OK
    payload = json.loads(body)
    resolutions = {item["resolution_id"]: item for item in payload["resolutions"]}
    for resolution in resolutions.values():
        assert resolution["approval_ready"] is False
        assert resolution["approved_roles"] == []
        assert resolution["trusted_replay_state"] == (
            "BLOCKED_MISSING_A08_SOURCE_ROOT"
        )
    assert payload["guardrails"]["legacy_catalog_trust"] == (
        "EVALUATION_UNBOUND"
    )
    assert payload["guardrails"]["source_pack_ids"] == [
        "CASE_BUILDER_SYNTHETIC"
    ]


def test_frontend_declares_timeout_and_invalidates_stale_selection(demo_address):
    status, _headers, body = request(demo_address, "GET", "/app.js")
    source = body.decode("utf-8")
    assert status == HTTPStatus.OK
    assert "new AbortController()" in source
    assert "markSelectionPending" in source
    assert "state.currentRunId = null" in source
    assert "run_id: runId" in source
    assert "replayIsBound" in source


def test_run_api_returns_agent_trace_three_state_findings_and_evidence(demo_address):
    payload = run_fixture(demo_address)
    assert payload["ok"] is True
    assert payload["result"]["overall_status"] == "CONTRADICTED"
    assert payload["result"]["reference_assurance_state"] == "ATTESTED_REFERENCE_SET"
    assert len(payload["result"]["reference_set_hash"]) == 64
    assert (
        payload["result"]["reference_contract_version"]
        == "qualityci-controlled-reference-0.1"
    )
    findings = payload["result"]["findings"]
    assert len(findings) >= 7
    assert len(findings) == len(payload["result"]["impact_plan"]["selected_rule_ids"])
    assert {item["status"] for item in findings} <= {"PASS", "CONTRADICTED", "UNVERIFIABLE"}
    contradicted = [item for item in findings if item["status"] == "CONTRADICTED"]
    assert contradicted
    assert all(item["evidence"] for item in contradicted)
    assert any(item["rule_id"] == "QCI-R002" for item in contradicted)

    team = payload["agent_team"]
    assert team["runtime_mode"] == "LOCAL_DETERMINISTIC_CONTRACT"
    assert team["runtime_next"] == "AgentTeams runtime Next"
    assert len(team["agents"]) == 4
    assert [item["agent_id"] for item in team["trace"]] == [
        "QCI-MANAGER",
        "QCI-IMPACT",
        "QCI-EVIDENCE",
        "QCI-GATEKEEPER",
    ]
    assert team["run"]["run_id"] == payload["result"]["run_id"]
    assert team["run"]["reference_set_hash"] == payload["result"]["reference_set_hash"]


def test_legacy_replay_blocks_before_client_run_id_can_confer_trust(demo_address):
    run = run_fixture(demo_address)
    run_id = run["result"]["run_id"]

    status, payload = post(
        demo_address,
        "/api/replay",
        {
            "mutation_id": "M001_STALE_SOP_CONFLICT",
            "resolution_id": "RES-SYN-001",
            "run_id": "stale-run-id",
        },
    )
    assert status == HTTPStatus.CONFLICT
    assert payload["status"] == "BLOCKED"
    assert payload["source_run_id"] == "stale-run-id"
    assert payload["approval_mode"] == "SOURCE_ROOTED_RAW_MATERIAL_REQUIRED"
    assert "A08_SOURCE_PACK_REQUIRED" in payload["error"]
    assert "replay" not in payload

    status, payload = post(
        demo_address,
        "/api/replay",
        {
            "mutation_id": "M002_MISSING_VALIDATION",
            "resolution_id": "RES-SYN-001",
            "run_id": run_id,
        },
    )
    assert status == HTTPStatus.CONFLICT
    assert payload["error"].startswith("resolution is not bound")


def test_unapproved_synthetic_resolution_is_blocked_by_api(demo_address):
    run = run_fixture(demo_address)
    status, _headers, body = request(
        demo_address,
        "POST",
        "/api/replay",
        {
            "mutation_id": "M001_STALE_SOP_CONFLICT",
            "resolution_id": "RES-SYN-BLOCKED",
            "run_id": run["result"]["run_id"],
        },
    )
    assert status == HTTPStatus.CONFLICT
    payload = json.loads(body.decode("utf-8"))
    assert payload["status"] == "BLOCKED"
    assert payload["approval_mode"] == "SOURCE_ROOTED_RAW_MATERIAL_REQUIRED"
    assert "A08_SOURCE_PACK_REQUIRED" in payload["error"]
    assert "replay" not in payload


def test_previously_approved_legacy_resolution_cannot_create_a08_baseline(
    demo_address,
):
    run = run_fixture(demo_address)
    status, payload = post(
        demo_address,
        "/api/replay",
        {
            "mutation_id": "M001_STALE_SOP_CONFLICT",
            "resolution_id": "RES-SYN-001",
            "run_id": run["result"]["run_id"],
        },
    )
    assert status == HTTPStatus.CONFLICT
    assert payload["status"] == "BLOCKED"
    assert payload["approval_mode"] == "SOURCE_ROOTED_RAW_MATERIAL_REQUIRED"
    assert "A08_SOURCE_PACK_REQUIRED" in payload["error"]
    assert "baseline_persisted" not in payload
    assert "replay" not in payload


def test_unknown_fixture_id_is_rejected_without_path_access(demo_address):
    status, _headers, body = request(
        demo_address,
        "POST",
        "/api/run",
        {"mutation_id": "../../private/customer.json"},
    )
    assert status == HTTPStatus.BAD_REQUEST
    payload = json.loads(body.decode("utf-8"))
    assert payload == {"ok": False, "error": "unknown mutation_id; select a predefined catalog item"}


@pytest.mark.parametrize(
    "raw_body",
    [
        b'{"mutation_id":"BASELINE","mutation_id":"M001_STALE_SOP_CONFLICT"}',
        b'{"mutation_id":NaN}',
        b'{"mutation_id":1e999}',
    ],
)
def test_web_api_rejects_ambiguous_or_non_finite_json(demo_address, raw_body):
    connection = HTTPConnection(*demo_address, timeout=3)
    try:
        connection.request(
            "POST",
            "/api/run",
            body=raw_body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(raw_body))},
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
    finally:
        connection.close()
    assert response.status == HTTPStatus.BAD_REQUEST
    assert payload == {"ok": False, "error": "request body must be valid UTF-8 JSON"}


def test_host_and_origin_are_restricted_to_bound_loopback(demo_address):
    status, headers, body = request(
        demo_address,
        "GET",
        "/api/health",
        extra_headers={"Host": "attacker.example"},
    )
    assert status == HTTPStatus.MISDIRECTED_REQUEST
    assert json.loads(body)["error"] == "Host header is not allowed"
    assert_security_headers(headers)

    status, _headers, body = request(
        demo_address,
        "POST",
        "/api/run",
        {"mutation_id": "BASELINE"},
        extra_headers={"Origin": "https://attacker.example"},
    )
    assert status == HTTPStatus.FORBIDDEN
    assert json.loads(body)["error"] == "cross-origin requests are not allowed"

    host, port = demo_address
    status, _headers, body = request(
        demo_address,
        "POST",
        "/api/run",
        {"mutation_id": "BASELINE"},
        extra_headers={"Origin": f"http://localhost:{port}"},
    )
    assert status == HTTPStatus.FORBIDDEN
    assert json.loads(body)["error"] == "cross-origin requests are not allowed"

    status, payload = post_with_headers(
        demo_address,
        "/api/run",
        {"mutation_id": "BASELINE"},
        {"Origin": f"http://{host}:{port}"},
    )
    assert status == HTTPStatus.OK
    assert payload["result"]["overall_status"] == "PASS"


def post_with_headers(
    address: tuple[str, int],
    path: str,
    payload: dict[str, Any],
    headers: dict[str, str],
) -> tuple[int, dict[str, Any]]:
    status, _headers, body = request(address, "POST", path, payload, extra_headers=headers)
    return status, json.loads(body)


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("HEAD", "/", HTTPStatus.OK),
        ("HEAD", "/api/catalog", HTTPStatus.OK),
        ("OPTIONS", "/api/run", HTTPStatus.NO_CONTENT),
        ("TRACE", "/", HTTPStatus.NOT_IMPLEMENTED),
    ],
)
def test_head_options_and_base_errors_share_security_headers(demo_address, method, path, expected):
    status, headers, body = request(demo_address, method, path)
    assert status == expected
    assert_security_headers(headers)
    if method == "HEAD":
        assert body == b""
    if method == "OPTIONS":
        assert headers["Allow"] == "GET, HEAD, POST, OPTIONS"


def test_incomplete_body_times_out_with_safe_response(demo_address):
    host, port = demo_address
    with socket.create_connection(demo_address, timeout=2) as client:
        client.settimeout(2)
        request_head = (
            f"POST /api/run HTTP/1.0\r\nHost: {host}:{port}\r\n"
            "Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{"
        )
        client.sendall(request_head.encode("ascii"))
        response = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
    assert b"408 Request Timeout" in response
    assert b"request body read timed out" in response
    assert b"X-Content-Type-Options: nosniff" in response


def test_concurrency_limit_rejects_excess_slow_request_without_traceback(capsys):
    server = make_server(port=0, request_timeout_seconds=1.0, max_concurrent_requests=1)
    worker_entered = threading.Event()
    release_worker = threading.Event()
    worker_finished = threading.Event()
    original_process_request_thread = server.process_request_thread

    def gated_process_request_thread(
        request_socket: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        worker_entered.set()
        try:
            if not release_worker.wait(timeout=2):
                raise TimeoutError("test did not release the occupied request slot")
            original_process_request_thread(request_socket, client_address)
        finally:
            worker_finished.set()

    server.process_request_thread = gated_process_request_thread  # type: ignore[method-assign]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    occupied = socket.create_connection((host, port), timeout=2)
    try:
        occupied.sendall(
            (
                f"POST /api/run HTTP/1.0\r\nHost: {host}:{port}\r\n"
                "Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{"
            ).encode("ascii")
        )
        assert worker_entered.wait(timeout=2), "first request did not occupy the request slot"
        for method, path, payload in (
            ("GET", "/api/health", None),
            ("POST", "/api/run", {"mutation_id": "BASELINE"}),
        ):
            status, headers, body = request((host, port), method, path, payload)
            assert status == HTTPStatus.SERVICE_UNAVAILABLE
            assert body == b'{"ok":false,"error":"demo request capacity reached"}'
            assert headers["Content-Type"] == "application/json; charset=utf-8"
            assert headers["Content-Length"] == str(len(body))
            assert headers["Connection"] == "close"
            assert {name: headers[name] for name, _value in SECURITY_HEADERS} == dict(
                SECURITY_HEADERS
            )
            assert_security_headers(headers)
    finally:
        release_worker.set()
        occupied.close()
        worker_exited = worker_finished.wait(timeout=2)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert worker_exited, "occupied request worker did not finish cleanly"
    assert capsys.readouterr().err == ""
