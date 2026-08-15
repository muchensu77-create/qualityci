#!/usr/bin/env python3
"""Fail-closed loopback gateway for the public QualityCI leader experience.

This build deliberately serves only reviewed static answers.  A live model provider
must be implemented and reviewed separately; setting live mode therefore fails at
startup instead of silently sending data to an unverified endpoint.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


CONTRACT_VERSION = "leader-experience.v1"
CASE_ID = "qualityci-public-walkthrough-0.1"
PROMPT_VERSION = "leader-zh-v1"
LOCALE = "zh-CN"
MAX_REQUEST_BYTES = 1024
REQUEST_READ_TIMEOUT_SECONDS = 3.0
SCENARIOS = ("conflict", "blocked", "ready")
QUESTIONS = ("release_decision", "blocking_reason", "required_evidence", "next_action")
REQUEST_KEYS = frozenset(
    {"contract_version", "case_id", "scenario_id", "question_id", "locale"}
)
BOUNDARIES = (
    "模型解释不能修改确定性规则结果、来源状态或准入结论",
    "模型解释不能批准工艺参数，也不能自动放行产品",
)
EVIDENCE = {
    "conflict": ("M001_RUN_SUMMARY", "M001_RULE_COUNTS", "M001_SOURCE_ROOT"),
    "blocked": ("M001_REPLAY_REQUEST", "M001_APPROVAL_MODE", "M001_A08_GATE"),
    "ready": ("BOUND_RUN_SUMMARY", "BOUND_SOURCE_ASSURANCE", "BOUND_HUMAN_REVIEW"),
}

_ANSWERS: dict[str, dict[str, tuple[str, tuple[str, ...]]]] = {
    "conflict": {
        "release_decision": (
            "当前不能进入可信放行评审。M001 仍处于 RUN_EVALUATION_UNBOUND，且 7 条规则中有 3 条为 CONTRADICTED；系统准入保持 BLOCKED。",
            ("规则已定位跨文档版本冲突", "来源根尚未闭合", "不写可信结果，也不建立候选基线"),
        ),
        "blocking_reason": (
            "阻断不只来自三条规则冲突，更来自缺少匹配的整体原始源根；当前结果只能用于定位问题，不能取得可信持久化权限。",
            ("控制计划、SOP 与检验记录存在版本失配", "运行状态为 EVALUATION_UNBOUND", "来源未闭合时 fail closed"),
        ),
        "required_evidence": (
            "需要补齐与本次 M001 工程变更匹配的原始源包、成员哈希与来源谱系，再以同一规则集重新运行。",
            ("完整原始源根", "受控成员与哈希清单", "可复算的来源谱系与规则版本"),
        ),
        "next_action": (
            "由资料责任人先补齐原始源包，质量工程师确认三处版本冲突的修订范围；随后重新运行，质量经理只审阅新的来源绑定结果。",
            ("资料责任人：闭合源包", "质量工程师：修订三处失配", "质量经理：审阅新结果，不复用旧评估"),
        ),
    },
    "blocked": {
        "release_decision": (
            "不能进入放行评审。复跑请求被 A08 来源门禁以 HTTP 409 阻断，没有生成 replay 或 baseline。",
            ("批准材料不是原始源根", "服务端明确返回 A08_SOURCE_PACK_REQUIRED", "响应不包含可信复跑产物"),
        ),
        "blocking_reason": (
            "最关键的阻断原因是输入仍是旧批准材料，而 A08 只接受与案例一致的 source-rooted raw material。批准记录不能替代来源证明。",
            ("approval_mode 不满足当前入口", "缺少匹配的原始成员集合", "门禁在执行前拒绝"),
        ),
        "required_evidence": (
            "需要提交案例对应的原始 source pack、成员清单、哈希与验证证据；旧批准记录可作为辅助证据，但不能单独放行。",
            ("source pack", "成员与哈希清单", "验证证据和来源绑定"),
        ),
        "next_action": (
            "由案例资料所有者导出受控 source pack，系统管理员从白名单入口提交；质量经理随后审阅来源绑定复跑，而不是重试旧批准路径。",
            ("停止重复旧 replay 请求", "准备受控 source pack", "从来源绑定入口重新运行"),
        ),
    },
    "ready": {
        "release_decision": (
            "可以进入人工放行评审，但不能自动放行。当前来源已绑定、7 条规则通过，系统状态仅为 READY_FOR_HUMAN_RELEASE_REVIEW。",
            ("trusted=true 代表来源契约闭合", "7 条确定性规则当前一致", "最终参数批准和产品放行仍由人负责"),
        ),
        "blocking_reason": (
            "系统层面的来源与规则阻断已经解除；剩余门槛是质量经理和工艺专家的专业评审，而不是继续自动计算。",
            ("没有 CONTRADICTED 规则", "来源保证已经闭合", "人工责任边界仍然存在"),
        ),
        "required_evidence": (
            "自动检查所需证据已经齐备。人工评审仍应核对变更授权、工艺参数依据、例外接受条件和实际放行责任。",
            ("变更授权", "工艺参数专业依据", "人工签批与放行记录"),
        ),
        "next_action": (
            "由质量经理召集工艺专家审阅候选结果与证据索引；确认参数和例外后，再由既有签批系统完成放行。",
            ("审阅来源绑定候选", "核对专业参数和例外", "在既有签批系统完成人工放行"),
        ),
    },
}


class ProtocolError(ValueError):
    def __init__(self, status: HTTPStatus, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProtocolError(HTTPStatus.BAD_REQUEST, "INVALID_JSON")
        value[key] = item
    return value


def _reject_constant(_value: str) -> Any:
    raise ProtocolError(HTTPStatus.BAD_REQUEST, "INVALID_JSON")


def parse_request(raw: bytes) -> tuple[str, str]:
    try:
        decoded = raw.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(HTTPStatus.BAD_REQUEST, "INVALID_JSON") from exc
    if type(value) is not dict or frozenset(value) != REQUEST_KEYS:
        raise ProtocolError(HTTPStatus.BAD_REQUEST, "INVALID_CONTRACT")
    expected_literals = {
        "contract_version": CONTRACT_VERSION,
        "case_id": CASE_ID,
        "locale": LOCALE,
    }
    if any(type(value[key]) is not str or value[key] != expected for key, expected in expected_literals.items()):
        raise ProtocolError(HTTPStatus.BAD_REQUEST, "INVALID_CONTRACT")
    scenario_id = value["scenario_id"]
    question_id = value["question_id"]
    if type(scenario_id) is not str or scenario_id not in SCENARIOS:
        raise ProtocolError(HTTPStatus.BAD_REQUEST, "INVALID_SCENARIO")
    if type(question_id) is not str or question_id not in QUESTIONS:
        raise ProtocolError(HTTPStatus.BAD_REQUEST, "INVALID_QUESTION")
    return scenario_id, question_id


def static_answer(scenario_id: str, question_id: str) -> dict[str, Any]:
    summary, key_points = _ANSWERS[scenario_id][question_id]
    return {
        "contract_version": CONTRACT_VERSION,
        "mode": "static_fallback",
        "synthetic": True,
        "scenario_id": scenario_id,
        "question_id": question_id,
        "summary": summary,
        "key_points": list(key_points),
        "evidence_ids": list(EVIDENCE[scenario_id]),
        "boundaries": list(BOUNDARIES),
        "prompt_version": PROMPT_VERSION,
    }


class LeaderGatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "QualityCI-Leader-Gateway"
    sys_version = ""

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _write_json(self, status: HTTPStatus, value: dict[str, Any], *, send_body: bool = True) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.end_headers()
        if send_body:
            self.wfile.write(body)
        self.close_connection = True

    def _error(self, error: ProtocolError) -> None:
        self._write_json(error.status, {"error": error.code})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/healthz":
            self._write_json(HTTPStatus.OK, {"status": "ok", "mode": "static_fallback"})
        else:
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._write_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": "METHOD_NOT_ALLOWED"},
            send_body=False,
        )

    def handle_expect_100(self) -> bool:
        self._write_json(HTTPStatus.EXPECTATION_FAILED, {"error": "EXPECTATION_NOT_SUPPORTED"})
        return False

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/api/v1/leader-answer":
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
            return
        try:
            if self.headers.get("Transfer-Encoding") is not None or self.headers.get("Expect") is not None:
                raise ProtocolError(HTTPStatus.BAD_REQUEST, "INVALID_HTTP_FRAMING")
            lengths = self.headers.get_all("Content-Length", failobj=[])
            if len(lengths) != 1 or re.fullmatch(r"[0-9]+", lengths[0]) is None:
                raise ProtocolError(HTTPStatus.LENGTH_REQUIRED, "CONTENT_LENGTH_REQUIRED")
            if len(lengths[0]) > 4:
                raise ProtocolError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "REQUEST_TOO_LARGE")
            length = int(lengths[0])
            if length < 2 or length > MAX_REQUEST_BYTES:
                raise ProtocolError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "REQUEST_TOO_LARGE")
            content_types = self.headers.get_all("Content-Type", failobj=[])
            if len(content_types) != 1:
                raise ProtocolError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "JSON_REQUIRED")
            media_type = content_types[0].lower().replace(" ", "")
            if media_type not in {"application/json", "application/json;charset=utf-8"}:
                raise ProtocolError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "JSON_REQUIRED")
            self.connection.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
            try:
                raw = self.rfile.read(length)
            except (TimeoutError, socket.timeout) as exc:
                raise ProtocolError(HTTPStatus.REQUEST_TIMEOUT, "REQUEST_TIMEOUT") from exc
            if len(raw) != length:
                raise ProtocolError(HTTPStatus.BAD_REQUEST, "TRUNCATED_BODY")
            scenario_id, question_id = parse_request(raw)
        except ProtocolError as error:
            self._error(error)
            return
        self._write_json(HTTPStatus.OK, static_answer(scenario_id, question_id))

    def do_PUT(self) -> None:  # noqa: N802
        self._write_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "METHOD_NOT_ALLOWED"})

    do_PATCH = do_PUT
    do_DELETE = do_PUT
    do_OPTIONS = do_PUT
    do_TRACE = do_PUT
    do_CONNECT = do_PUT


class LoopbackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 8


def build_server(host: str, port: int) -> LoopbackServer:
    if host != "127.0.0.1":
        raise ValueError("leader gateway must bind to the IPv4 loopback literal")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("invalid port")
    mode = os.environ.get("QUALITYCI_LEADER_MODE", "static_fallback")
    if mode != "static_fallback":
        raise RuntimeError("live provider is not configured in this reviewed build")
    return LoopbackServer((host, port), LeaderGatewayHandler)


def main() -> int:
    parser = argparse.ArgumentParser(description="QualityCI leader experience loopback gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8789)
    args = parser.parse_args()
    server = build_server(args.host, args.port)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
