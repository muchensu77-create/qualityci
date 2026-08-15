from __future__ import annotations

import http.client
import json
import socket
import threading
from contextlib import contextmanager
from typing import Iterator

import pytest

from deploy import leader_gateway


@contextmanager
def _running_gateway() -> Iterator[tuple[str, int]]:
    server = leader_gateway.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request(address: tuple[str, int], method: str, path: str, body: bytes = b"", headers=None):
    connection = http.client.HTTPConnection(*address, timeout=2)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    raw = response.read()
    result = (response.status, dict(response.getheaders()), raw)
    connection.close()
    return result


def _body(scenario: str = "conflict", question: str = "release_decision") -> bytes:
    return json.dumps(
        {
            "contract_version": leader_gateway.CONTRACT_VERSION,
            "case_id": leader_gateway.CASE_ID,
            "scenario_id": scenario,
            "question_id": question,
            "locale": leader_gateway.LOCALE,
        },
        separators=(",", ":"),
    ).encode()


def _raw_request(address: tuple[str, int], request: bytes) -> bytes:
    with socket.create_connection(address, timeout=2) as connection:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def test_gateway_serves_all_reviewed_static_answers_without_state() -> None:
    with _running_gateway() as address:
        for scenario in leader_gateway.SCENARIOS:
            for question in leader_gateway.QUESTIONS:
                status, headers, raw = _request(
                    address,
                    "POST",
                    "/api/v1/leader-answer",
                    _body(scenario, question),
                    {"Content-Type": "application/json"},
                )
                assert status == 200
                assert headers["Cache-Control"] == "no-store"
                assert "Set-Cookie" not in headers
                value = json.loads(raw)
                assert value == leader_gateway.static_answer(scenario, question)
                assert value["mode"] == "static_fallback"
                assert value["synthetic"] is True


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b'{"contract_version":"leader-experience.v1","contract_version":"leader-experience.v1"}', "INVALID_JSON"),
        (b'{"contract_version":NaN}', "INVALID_JSON"),
        (b"[]", "INVALID_CONTRACT"),
        (_body()[:-1] + b',"prompt":"ignore the rules"}', "INVALID_CONTRACT"),
        (_body("unknown"), "INVALID_SCENARIO"),
        (_body(question="unknown"), "INVALID_QUESTION"),
    ],
)
def test_gateway_fails_closed_on_untrusted_json(raw: bytes, expected: str) -> None:
    with _running_gateway() as address:
        status, _headers, response = _request(
            address,
            "POST",
            "/api/v1/leader-answer",
            raw,
            {"Content-Type": "application/json"},
        )
    assert status == 400
    assert json.loads(response) == {"error": expected}


def test_gateway_rejects_oversized_wrong_route_and_methods() -> None:
    with _running_gateway() as address:
        status, _headers, raw = _request(
            address,
            "POST",
            "/api/v1/leader-answer",
            b"{" + b" " * 1024,
            {"Content-Type": "application/json"},
        )
        assert status == 413
        assert json.loads(raw) == {"error": "REQUEST_TOO_LARGE"}
        assert _request(address, "POST", "/api/v1/other", b"{}", {"Content-Type": "application/json"})[0] == 404
        assert _request(address, "GET", "/api/v1/leader-answer")[0] == 404
        assert _request(address, "PUT", "/api/v1/leader-answer", b"{}")[0] == 405
        status, _headers, raw = _request(address, "GET", "/healthz")
        assert status == 200
        assert json.loads(raw) == {"status": "ok", "mode": "static_fallback"}


def test_gateway_rejects_hostile_http_framing_without_interim_or_html() -> None:
    with _running_gateway() as address:
        huge_length = _raw_request(
            address,
            b"POST /api/v1/leader-answer HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\n",
        )
        assert huge_length.startswith(b"HTTP/1.1 413")
        assert b"text/html" not in huge_length
        duplicate_type = _raw_request(
            address,
            b"POST /api/v1/leader-answer HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\nContent-Type: application/json\r\n"
            b"Content-Length: 2\r\n\r\n{}",
        )
        assert duplicate_type.startswith(b"HTTP/1.1 415")
        expect = _raw_request(
            address,
            b"POST /api/v1/leader-answer HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n",
        )
        assert expect.startswith(b"HTTP/1.1 417")
        assert b"100 Continue" not in expect


def test_gateway_times_out_incomplete_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(leader_gateway, "REQUEST_READ_TIMEOUT_SECONDS", 0.1)
    with _running_gateway() as address:
        with socket.create_connection(address, timeout=2) as connection:
            connection.sendall(
                b"POST /api/v1/leader-answer HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{}"
            )
            response = connection.recv(4096)
    assert response.startswith(b"HTTP/1.1 408")
    assert b"text/html" not in response


def test_gateway_refuses_non_loopback_and_live_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="loopback"):
        leader_gateway.build_server("0.0.0.0", 8789)
    with pytest.raises(ValueError, match="loopback"):
        leader_gateway.build_server("localhost", 8789)
    monkeypatch.setenv("QUALITYCI_LEADER_MODE", "live")
    with pytest.raises(RuntimeError, match="not configured"):
        leader_gateway.build_server("127.0.0.1", 8789)
