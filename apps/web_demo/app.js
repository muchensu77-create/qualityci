"use strict";

const REQUEST_TIMEOUT_MS = 8000;
const REPLAY_MUTATION_ID = "M001_STALE_SOP_CONFLICT";
const state = {
  catalog: null,
  currentMutationId: null,
  currentRunId: null,
  busy: false,
};

const byId = (id) => document.getElementById(id);

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}

function statusClass(status) {
  const token = String(status || "").toLowerCase();
  return ["pass", "contradicted", "unverifiable"].includes(token) ? token : "neutral";
}

async function requestJSON(url, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  if (options.signal) {
    options.signal.addEventListener("abort", () => controller.abort(), { once: true });
  }
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    let payload;
    try {
      payload = await response.json();
    } catch (_error) {
      throw new Error(`HTTP ${response.status}: 服务器未返回 JSON`);
    }
    if (!response.ok) {
      const error = new Error(payload.error || `HTTP ${response.status}`);
      error.payload = payload;
      throw error;
    }
    return payload;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(`请求超过 ${REQUEST_TIMEOUT_MS / 1000} 秒，已在浏览器端取消`);
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

function replayIsBound() {
  return (
    !state.busy
    && state.currentMutationId === REPLAY_MUTATION_ID
    && state.currentMutationId === byId("mutation-select").value
    && typeof state.currentRunId === "string"
    && state.currentRunId.length > 0
  );
}

function syncActionState() {
  byId("mutation-select").disabled = state.busy;
  byId("run-button").disabled = state.busy;
  byId("baseline-button").disabled = state.busy;
  byId("source-button").disabled = state.busy;
  byId("blocked-button").disabled = !replayIsBound();
  byId("approved-button").disabled = !replayIsBound();
}

function setBusy(busy) {
  state.busy = busy;
  byId("result-panel").setAttribute("aria-busy", String(busy));
  syncActionState();
}

function notify(message, kind = "") {
  const box = byId("notification");
  box.className = `notification${kind ? ` ${kind}` : ""}`;
  box.textContent = message;
}

function clearNotification() {
  const box = byId("notification");
  box.className = "notification hidden";
  box.textContent = "";
}

function populateCatalog(catalog) {
  state.catalog = catalog;
  const select = byId("mutation-select");
  select.replaceChildren();
  catalog.mutations.forEach((mutation) => {
    const option = node("option", "", mutation.mutation_id === "BASELINE" ? "干净基线" : mutation.mutation_id);
    option.value = mutation.mutation_id;
    select.append(option);
  });
  select.value = catalog.default_mutation_id;
  markSelectionPending(false);
}

function updateMutationDescription() {
  if (!state.catalog) return;
  const selected = state.catalog.mutations.find((item) => item.mutation_id === byId("mutation-select").value);
  byId("mutation-description").textContent = selected ? selected.description : "";
}

function renderAgentTrace(agentTeam) {
  const container = byId("agent-trace");
  container.replaceChildren();
  if (!agentTeam || !Array.isArray(agentTeam.trace)) {
    container.append(node("li", "agent-trace-empty", "暂无与当前运行绑定的 Agent Trace。"));
    byId("agent-runtime").textContent = "LOCAL_DETERMINISTIC_CONTRACT";
    return;
  }
  byId("agent-runtime").textContent = agentTeam.runtime_mode || "LOCAL_DETERMINISTIC_CONTRACT";
  const identities = new Map((agentTeam.agents || []).map((item) => [item.agent_id, item]));
  agentTeam.trace.forEach((event) => {
    const identity = identities.get(event.agent_id) || {};
    const item = node("li", "agent-trace-item");
    const top = node("div", "agent-trace-top");
    top.append(
      node("span", "agent-sequence", String(event.sequence).padStart(2, "0")),
      node("strong", "", identity.role || event.agent_id),
      node("code", "", event.agent_id),
    );
    const transition = node("p", "agent-transition", `${event.state_from} → ${event.state_to}`);
    const skill = node("p", "agent-skill", `SKILL · ${event.skill_id}`);
    const evidence = Array.isArray(event.evidence) && event.evidence.length
      ? event.evidence.join(" · ")
      : "无证据锚点";
    const detail = node("p", "agent-evidence", evidence);
    item.append(top, transition, skill, detail);
    container.append(item);
  });
}

function markSelectionPending(announce = true) {
  updateMutationDescription();
  state.currentMutationId = null;
  state.currentRunId = null;
  const selected = byId("mutation-select").value;
  byId("case-title").textContent = `已选择 ${selected}，等待运行`;
  byId("case-summary").textContent = "场景切换已清除旧的 mutation/run 绑定；完成新一次回归前不能进入审批复跑。";
  const status = byId("overall-status");
  status.className = "status-pill neutral";
  status.textContent = "WAITING";
  byId("run-id").textContent = `SELECTED ${selected} · NO ACTIVE RUN`;
  ["metric-total", "metric-pass", "metric-contradicted", "metric-unverifiable"].forEach((id) => {
    byId(id).textContent = "—";
  });
  byId("impact-grid").replaceChildren();
  byId("reasoning-path").replaceChildren();
  byId("findings").replaceChildren();
  renderAgentTrace(null);
  if (announce) notify("场景已切换：旧运行与审批绑定已清除，请先运行质量回归。");
  else clearNotification();
  syncActionState();
}

function renderImpact(plan) {
  const grid = byId("impact-grid");
  grid.replaceChildren();
  const items = [
    ["受影响工序", plan.affected_process_steps.join(" · ") || "未提供"],
    ["受影响特性", plan.affected_characteristics.join(" · ") || "未提供"],
    ["必需文档", plan.required_document_types.join(" · ")],
  ];
  items.forEach(([label, value]) => {
    const card = node("article", "impact-card");
    card.append(node("small", "", label), node("p", "", value));
    grid.append(card);
  });
  const reasoning = byId("reasoning-path");
  reasoning.replaceChildren();
  plan.reasoning_path.forEach((item) => reasoning.append(node("li", "", item)));
}

function renderEvidence(evidence) {
  const list = node("div", "evidence-list");
  evidence.forEach((item) => {
    const card = node("article", "evidence-card");
    const heading = `${item.document_id} · rev ${item.revision} · ${item.locator}`;
    card.append(node("strong", "", heading), node("code", "", item.excerpt));
    list.append(card);
  });
  if (!evidence.length) list.append(node("p", "", "本条结果暂无可定位证据。"));
  return list;
}

function renderFindings(findings) {
  const container = byId("findings");
  container.replaceChildren();
  findings.forEach((finding, index) => {
    const details = node("details", "finding");
    if (finding.status !== "PASS" || index === 0) details.open = true;
    const summary = node("summary");
    const title = node("span", "finding-title");
    title.append(node("strong", "", finding.title), node("small", "", finding.summary));
    const stateBox = node("span", "finding-state");
    stateBox.append(
      node("span", `mini-pill ${statusClass(finding.status)}`, finding.status),
      node("span", "severity", `SEVERITY · ${finding.severity}`),
    );
    summary.append(node("span", "rule-id", finding.rule_id), title, stateBox);

    const body = node("div", "finding-body");
    body.append(node("h4", "", "证据锚点"), renderEvidence(finding.evidence || []));
    if (finding.remediation) {
      body.append(node("h4", "", "修订建议"), node("p", "", finding.remediation));
    }
    if (finding.acceptance_conditions && finding.acceptance_conditions.length) {
      body.append(node("h4", "", "验收条件"));
      const list = node("ul");
      finding.acceptance_conditions.forEach((item) => list.append(node("li", "", item)));
      body.append(list);
    }
    details.append(summary, body);
    container.append(details);
  });
}

function renderRun(payload, message = "", options = {}) {
  const result = payload.result;
  const caseData = payload.case;
  const resolved = options.resolved === true;
  byId("mutation-select").value = payload.mutation_id;
  updateMutationDescription();
  state.currentMutationId = resolved ? null : payload.mutation_id;
  state.currentRunId = resolved ? null : result.run_id;
  byId("case-title").textContent = caseData.title;
  byId("case-summary").textContent = `${caseData.event.event_id} · ${caseData.event.risk_level} RISK · ${caseData.event.change_summary}`;
  const status = byId("overall-status");
  status.className = `status-pill ${statusClass(result.overall_status)}`;
  status.textContent = result.overall_status;
  byId("run-id").textContent = resolved
    ? `RESOLVED FROM ${payload.mutation_id} · RUN ${result.run_id} · NO ACTIVE REPLAY`
    : `ACTIVE MUTATION ${payload.mutation_id} · RUN ${result.run_id} · RULESET ${result.ruleset_version}`;

  const counts = { PASS: 0, CONTRADICTED: 0, UNVERIFIABLE: 0 };
  result.findings.forEach((finding) => { counts[finding.status] = (counts[finding.status] || 0) + 1; });
  byId("metric-total").textContent = result.findings.length;
  byId("metric-pass").textContent = counts.PASS;
  byId("metric-contradicted").textContent = counts.CONTRADICTED;
  byId("metric-unverifiable").textContent = counts.UNVERIFIABLE;
  renderImpact(result.impact_plan);
  renderAgentTrace(payload.agent_team);
  renderFindings(result.findings);
  if (message) notify(message, result.overall_status === "PASS" ? "success" : "");
  else clearNotification();
  syncActionState();
}

async function runSelected(mutationId = byId("mutation-select").value) {
  byId("mutation-select").value = mutationId;
  markSelectionPending(false);
  setBusy(true);
  try {
    const payload = await requestJSON("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mutation_id: mutationId }),
    });
    renderRun(payload);
  } catch (error) {
    notify(`运行失败：${error.message}`, "blocked");
  } finally {
    setBusy(false);
  }
}

async function runSourceActual() {
  state.currentMutationId = null;
  state.currentRunId = null;
  setBusy(true);
  clearNotification();
  try {
    const payload = await requestJSON("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source_pack_id: "CASE_BUILDER_SYNTHETIC",
        mutation_id: "BASELINE",
      }),
    });
    const result = payload.result;
    byId("case-title").textContent = `${payload.source_pack_id} · A08 Actual`;
    byId("case-summary").textContent = `${result.case_id} · ${result.case_source_assurance_state} · ${result.validation_assurance_state}`;
    const status = byId("overall-status");
    status.className = `status-pill ${statusClass(result.overall_status)}`;
    status.textContent = result.overall_status;
    byId("run-id").textContent = `SOURCE-ROOTED RUN ${result.run_id} · ${result.run_identity_version} · TEAM 0.2`;
    const counts = { PASS: 0, CONTRADICTED: 0, UNVERIFIABLE: 0 };
    result.findings.forEach((finding) => { counts[finding.status] = (counts[finding.status] || 0) + 1; });
    byId("metric-total").textContent = result.findings.length;
    byId("metric-pass").textContent = counts.PASS;
    byId("metric-contradicted").textContent = counts.CONTRADICTED;
    byId("metric-unverifiable").textContent = counts.UNVERIFIABLE;
    renderImpact(result.impact_plan);
    renderAgentTrace(payload.agent_team);
    renderFindings(result.findings);
    notify(
      `A08 Actual：原始源包与验证包已闭合，${result.run_result_contract_version} / ${result.run_identity_version} / Team 0.2 均通过。`,
      "success",
    );
  } catch (error) {
    notify(`A08 源包运行失败：${error.message}`, "blocked");
  } finally {
    setBusy(false);
  }
}

async function replay(resolutionId) {
  const mutationId = state.currentMutationId;
  const runId = state.currentRunId;
  if (!replayIsBound()) {
    notify("审批复跑必须绑定当前 M001 场景及其最新 run；请先重新运行。", "blocked");
    return;
  }
  setBusy(true);
  clearNotification();
  try {
    await requestJSON("/api/replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mutation_id: mutationId, resolution_id: resolutionId, run_id: runId }),
    });
    notify("安全错误：旧 Tacoma replay 不得返回成功。", "blocked");
  } catch (error) {
    const payload = error.payload || {};
    if (payload.status === "BLOCKED") {
      notify(`409 门禁符合 A08 预期：${payload.error}；未生成、未保存基线。`, "blocked");
    } else {
      notify(`复跑失败：${error.message}`, "blocked");
    }
  } finally {
    setBusy(false);
  }
}

async function start() {
  setBusy(true);
  try {
    const catalog = await requestJSON("/api/catalog");
    populateCatalog(catalog);
    await runSelected(catalog.default_mutation_id);
  } catch (error) {
    notify(`启动失败：${error.message}`, "blocked");
    setBusy(false);
  }
}

byId("mutation-select").addEventListener("change", () => markSelectionPending());
byId("run-button").addEventListener("click", () => runSelected());
byId("baseline-button").addEventListener("click", () => runSelected("BASELINE"));
byId("source-button").addEventListener("click", () => runSourceActual());
byId("blocked-button").addEventListener("click", () => replay("RES-SYN-BLOCKED"));
byId("approved-button").addEventListener("click", () => replay("RES-SYN-001"));

start();
