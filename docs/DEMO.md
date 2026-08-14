# QualityCI 本地 Web Demo

## 用途

这是 GOAI 2026 初赛主案例的本地演示层。Web 服务器本身使用 Python
标准库；QualityCI 核心包仍按 `pyproject.toml` 安装其运行依赖。A08 将页面上的证据明确分开：

- 工程变更影响分析；
- 当前规则集中的确定性质量回归规则；
- `PASS / CONTRADICTED / UNVERIFIABLE` 三态判定；
- 文档、版本、定位符和摘要组成的证据卡；
- `CASE_BUILDER_SYNTHETIC` 是服务端白名单的整体原始源包，连同原始验证报告运行，可作为 A08 Actual Run 证据；
- 旧 Tacoma 序列化 Case 目录只能做 `EVALUATION_UNBOUND` 回归；其 replay 始终 `409 A08_SOURCE_PACK_REQUIRED`，不生成、不保存基线；
- 四 Agent 本地确定性协同契约的逐步 Trace。

页面与 API 只使用仓库内显著标注的合成案例，不会读取企业数据。

公开网站使用 `site/` 下依据公共入口字段整理的静态契约示意，不是原始运行日志，
也不调用这里的 Python API。
本地服务的 loopback 限制是安全边界，不能为公网部署而放宽。

> 口径边界：页面展示的是 `LOCAL_DETERMINISTIC_CONTRACT`（本地确定性协同契约）。`AgentTeams runtime Next` 是下一阶段适配目标，当前不宣称已接入 AgentTeams runtime。

## 启动

在仓库根目录执行：

```bash
PYTHONPATH=src python3 -m qualityci.web_demo
```

默认地址：

```text
http://127.0.0.1:8765
```

可修改本地端口：

```bash
PYTHONPATH=src python3 -m qualityci.web_demo --port 9000
```

服务器只允许绑定 `127.0.0.1` 或 `localhost`，避免将初赛原型误暴露到局域网或公网。

## 推荐演示流程（3–4分钟）

1. 先点击“运行 `CASE_BUILDER_SYNTHETIC` Actual”。展示 `BOUND_RAW_SOURCE_CASE`、`ATTESTED_VALIDATION_SET`、RunResult `0.2`、identity `v4` 和 Team `0.2` 共用 source tuple。
2. 展开 `QCI-R002`，展示同一特性在 Control Plan、SOP 与 Inspection Record 中的定位证据；展开 `QCI-R006` 查看原始验证报告锚点。
3. 指出“四 Agent 协同 Trace”中的 Manager → Impact → Evidence → Gatekeeper 四步与证据哈希。同时明确这是本地确定性契约，AgentTeams runtime 仍为 Next。
4. 运行默认 `M001_STALE_SOP_CONFLICT`，说明这是旧 Tacoma `EVALUATION_UNBOUND` 回归，不具有 Actual 或审批权限。
5. 分别点击两个旧审批记录按钮；两者都应展示 `409 A08_SOURCE_PACK_REQUIRED`、“未生成、未保存基线”。批准角色数量不能替代 A08 原始源根。
6. 切换其他故障注入。页面会立即清除旧的 active mutation/run 绑定并禁用 replay 按钮，直到新场景完成回归。

## API

| 方法 | 路由 | 用途 |
|---|---|---|
| `GET` | `/api/health` | 本地服务健康检查 |
| `GET` | `/api/catalog` | 返回固定案例、故障注入和修订方案的 ID 目录 |
| `POST` | `/api/run` | `{mutation_id}` 执行旧评估；`{source_pack_id, mutation_id}` 执行白名单 A08 source-rooted Actual |
| `POST` | `/api/preview` | 生成结构上独立的 `PROPOSED_UNATTESTED` 估算，不得审批、保存或建基线 |
| `POST` | `/api/replay` | 旧 Tacoma replay 负控；当前始终返回 `409 A08_SOURCE_PACK_REQUIRED` |

API 仅接收 `application/json`，请求体不得超过 16 KiB。浏览器提供的文件路径或未知 ID 会直接被拒绝。A08 Actual `/api/run` 只接受服务端白名单 opaque ID，所有原始成员路径仍由服务端控制。`/api/replay` 不信任客户端自述 hash/provenance/attestation；旧 Tacoma 目录没有匹配的整体原始源包、ApprovalSubject 0.2 与有序派生材料，因此不进入复跑权限路径。

`/api/run` 响应中的 `agent_team` 包含四个 Agent 身份、四步 Trace、输入/输出哈希和最终门禁状态。其 `runtime_mode` 固定为 `LOCAL_DETERMINISTIC_CONTRACT`。

## 安全与数据边界

- HTTP 路由是固定白名单，静态文件与数据 fixture 都在启动时校验为仓库内路径。
- 服务仅绑定 loopback，并校验 `Host`；带 `Origin` 的 POST/OPTIONS 请求必须与当前 loopback 端口同源。
- 请求体读取超时默认为 3 秒，服务同时最多处理 16 个请求；超额请求返回 `503`，断开连接不打印 BrokenPipe 堆栈。
- 前端每次 API 请求使用 `AbortController`，8 秒未完成即取消并提示。
- 前端动态内容全部用 `textContent` 写入，不将数据当作 HTML 解析。
- 所有响应（包括 `HEAD`、`OPTIONS` 和默认错误）统一设置 CSP、`nosniff`、`DENY` frame、COOP、CORP、Permissions Policy 和 `no-store` 响应头。
- 服务器不提供上传、任意文件读取、任意补丁或产线控制功能。
- 页面中的“通过”只表示预置回归规则通过，不代表认定工艺参数或产品可自动放行。
- 预置 legacy resolution JSON 不是 A08 ApprovalSubject 0.2 的替代品；即使包含双角色合成批准，也不获得 replay/baseline 权限。
- 真实系统还需要可验证身份、签名和外部审计适配。

## 测试

```bash
python3 -m pytest tests/test_web_demo.py
```

测试覆盖首页与统一安全头、四 Agent Trace、白名单 source Actual Run、legacy `EVALUATION_UNBOUND` Run、两种旧 replay 的 409 阻断、任意路径式 ID 拒绝、Host/Origin 限制、HEAD/OPTIONS、慢请求超时和并发上限。
