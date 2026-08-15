"use strict";

document.documentElement.classList.add("js");

const CONTRACT_VERSION = "leader-experience.v1";
const CASE_ID = "qualityci-public-walkthrough-0.1";
const PROMPT_VERSION = "leader-zh-v1";
const ENDPOINT = "/api/v1/leader-answer";
const QUESTION_IDS = ["release_decision", "blocking_reason", "required_evidence", "next_action"];
const RESPONSE_KEYS = [
  "boundaries",
  "contract_version",
  "evidence_ids",
  "key_points",
  "mode",
  "prompt_version",
  "question_id",
  "scenario_id",
  "summary",
  "synthetic",
];
const BOUNDARIES = [
  "模型解释不能修改确定性规则结果、来源状态或准入结论",
  "模型解释不能批准工艺参数，也不能自动放行产品",
];

const SCENARIOS = {
  conflict: {
    status: "CONTRADICTED",
    title: "旧版 SOP 冲突被发现，但当前路径只能评估",
    facts: [
      "RUN_EVALUATION_UNBOUND",
      "4 PASS／3 CONTRADICTED／7 TOTAL",
      "admission BLOCKED／不写可信结果",
      "旧目录缺少匹配的整体原始源根",
    ],
    factLabels: ["运行模式", "规则结果", "当前处置", "来源边界"],
    evidence: {
      M001_RUN_SUMMARY: "M001 静态运行摘要",
      M001_RULE_COUNTS: "七条规则计数",
      M001_SOURCE_ROOT: "来源根边界",
    },
  },
  blocked: {
    status: "REPLAY BLOCKED",
    title: "旧批准材料不能替代 A08 原始源根",
    facts: [
      "SOURCE_ROOTED_RAW_MATERIAL_REQUIRED",
      "HTTP 409／A08_SOURCE_PACK_REQUIRED",
      "replay BLOCKED／不返回 baseline",
      "批准记录存在，但没有匹配的原始源包",
    ],
    factLabels: ["批准材料模式", "门禁响应", "当前处置", "来源边界"],
    evidence: {
      M001_REPLAY_REQUEST: "复跑请求摘要",
      M001_APPROVAL_MODE: "批准材料模式",
      M001_A08_GATE: "A08 来源门禁",
    },
  },
  ready: {
    status: "READY FOR REVIEW",
    title: "来源绑定回归通过，进入人工放行评审",
    facts: [
      "SOURCE_ROOTED_RUN／trusted true",
      "PASS／BOUND_RAW_SOURCE_CASE",
      "READY_FOR_HUMAN_RELEASE_REVIEW",
      "CASE_BUILDER_SYNTHETIC／BASELINE",
    ],
    factLabels: ["运行模式", "总体状态", "当前处置", "来源边界"],
    evidence: {
      BOUND_RUN_SUMMARY: "来源绑定运行摘要",
      BOUND_SOURCE_ASSURANCE: "源包与谱系保证",
      BOUND_HUMAN_REVIEW: "人工放行门",
    },
  },
};

const QUESTION_LABELS = {
  release_decision: "现在能否进入放行评审",
  blocking_reason: "最关键的阻断原因是什么",
  required_evidence: "解除阻断还缺什么证据",
  next_action: "下一步应由谁做什么",
};

function staticAnswer(scenarioId, questionId) {
  const scenario = SCENARIOS[scenarioId];
  const allEvidence = Object.keys(scenario.evidence);
  const answers = {
    conflict: {
      release_decision: [
        "当前不能进入可信放行评审。M001 仍处于 RUN_EVALUATION_UNBOUND，且 7 条规则中有 3 条为 CONTRADICTED；系统准入保持 BLOCKED。",
        ["规则已定位跨文档版本冲突", "来源根尚未闭合", "不写可信结果，也不建立候选基线"],
      ],
      blocking_reason: [
        "阻断不只来自三条规则冲突，更来自缺少匹配的整体原始源根；当前结果只能用于定位问题，不能取得可信持久化权限。",
        ["控制计划、SOP 与检验记录存在版本失配", "运行状态为 EVALUATION_UNBOUND", "来源未闭合时 fail closed"],
      ],
      required_evidence: [
        "需要补齐与本次 M001 工程变更匹配的原始源包、成员哈希与来源谱系，再以同一规则集重新运行。",
        ["完整原始源根", "受控成员与哈希清单", "可复算的来源谱系与规则版本"],
      ],
      next_action: [
        "由资料责任人先补齐原始源包，质量工程师确认三处版本冲突的修订范围；随后重新运行，质量经理只审阅新的来源绑定结果。",
        ["资料责任人：闭合源包", "质量工程师：修订三处失配", "质量经理：审阅新结果，不复用旧评估"],
      ],
    },
    blocked: {
      release_decision: [
        "不能进入放行评审。复跑请求被 A08 来源门禁以 HTTP 409 阻断，没有生成 replay 或 baseline。",
        ["批准材料不是原始源根", "服务端明确返回 A08_SOURCE_PACK_REQUIRED", "响应不包含可信复跑产物"],
      ],
      blocking_reason: [
        "最关键的阻断原因是输入仍是旧批准材料，而 A08 只接受与案例一致的 source-rooted raw material。批准记录不能替代来源证明。",
        ["approval_mode 不满足当前入口", "缺少匹配的原始成员集合", "门禁在执行前拒绝"],
      ],
      required_evidence: [
        "需要提交案例对应的原始 source pack、成员清单、哈希与验证证据；旧批准记录可作为辅助证据，但不能单独放行。",
        ["source pack", "成员与哈希清单", "验证证据和来源绑定"],
      ],
      next_action: [
        "由案例资料所有者导出受控 source pack，系统管理员从白名单入口提交；质量经理随后审阅来源绑定复跑，而不是重试旧批准路径。",
        ["停止重复旧 replay 请求", "准备受控 source pack", "从来源绑定入口重新运行"],
      ],
    },
    ready: {
      release_decision: [
        "可以进入人工放行评审，但不能自动放行。当前来源已绑定、7 条规则通过，系统状态仅为 READY_FOR_HUMAN_RELEASE_REVIEW。",
        ["trusted=true 代表来源契约闭合", "7 条确定性规则当前一致", "最终参数批准和产品放行仍由人负责"],
      ],
      blocking_reason: [
        "系统层面的来源与规则阻断已经解除；剩余门槛是质量经理和工艺专家的专业评审，而不是继续自动计算。",
        ["没有 CONTRADICTED 规则", "来源保证已经闭合", "人工责任边界仍然存在"],
      ],
      required_evidence: [
        "自动检查所需证据已经齐备。人工评审仍应核对变更授权、工艺参数依据、例外接受条件和实际放行责任。",
        ["变更授权", "工艺参数专业依据", "人工签批与放行记录"],
      ],
      next_action: [
        "由质量经理召集工艺专家审阅候选结果与证据索引；确认参数和例外后，再由既有签批系统完成放行。",
        ["审阅来源绑定候选", "核对专业参数和例外", "在既有签批系统完成人工放行"],
      ],
    },
  };
  const [summary, keyPoints] = answers[scenarioId][questionId];
  return {
    contract_version: CONTRACT_VERSION,
    mode: "static_fallback",
    synthetic: true,
    scenario_id: scenarioId,
    question_id: questionId,
    summary,
    key_points: keyPoints,
    evidence_ids: allEvidence,
    boundaries: BOUNDARIES,
    prompt_version: PROMPT_VERSION,
  };
}

const scenarioButtons = [...document.querySelectorAll("[data-scenario]")];
const questionButtons = [...document.querySelectorAll("[data-question]")];
const answerSheet = document.querySelector(".answer-sheet");
const loading = document.querySelector("[data-answer-loading]");
const retryButton = document.querySelector("[data-retry]");
let selectedScenario = "conflict";
let selectedQuestion = "release_decision";
let requestOwner = 0;
let activeDeadline = null;

function exactKeys(value, expected) {
  return value && typeof value === "object" && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function textWithin(value, max) {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function validateResponse(value, scenarioId, questionId) {
  if (!exactKeys(value, RESPONSE_KEYS)) return false;
  if (value.contract_version !== CONTRACT_VERSION || value.prompt_version !== PROMPT_VERSION) return false;
  if (!['live', 'static_fallback'].includes(value.mode) || value.synthetic !== true) return false;
  if (value.scenario_id !== scenarioId || value.question_id !== questionId) return false;
  if (!textWithin(value.summary, 800)) return false;
  if (!Array.isArray(value.key_points) || value.key_points.length < 1 || value.key_points.length > 5
    || value.key_points.some((item) => !textWithin(item, 220))) return false;
  const allowedEvidence = Object.keys(SCENARIOS[scenarioId].evidence);
  if (!Array.isArray(value.evidence_ids) || value.evidence_ids.length < 1
    || value.evidence_ids.length > allowedEvidence.length
    || new Set(value.evidence_ids).size !== value.evidence_ids.length
    || value.evidence_ids.some((item) => !allowedEvidence.includes(item))) return false;
  return Array.isArray(value.boundaries)
    && value.boundaries.length === BOUNDARIES.length
    && value.boundaries.every((item, index) => item === BOUNDARIES[index]);
}

function replaceTextList(target, values, formatter) {
  const nodes = values.map((value) => {
    const item = document.createElement("li");
    formatter(item, value);
    return item;
  });
  target.replaceChildren(...nodes);
}

function renderScenario() {
  const scenario = SCENARIOS[selectedScenario];
  document.querySelector("[data-scenario-status]").textContent = scenario.status;
  document.querySelector("[data-scenario-title]").textContent = scenario.title;
  ["mode", "result", "action", "source"].forEach((key, index) => {
    document.querySelector(`[data-fact-label="${key}"]`).textContent = scenario.factLabels[index];
    document.querySelector(`[data-fact-${key}]`).textContent = scenario.facts[index];
  });
  const panel = document.querySelector("#scenario-facts");
  const active = scenarioButtons.find((button) => button.dataset.scenario === selectedScenario);
  panel.setAttribute("aria-labelledby", active.id);
  scenarioButtons.forEach((button) => {
    const isActive = button === active;
    button.setAttribute("aria-selected", String(isActive));
    button.tabIndex = isActive ? 0 : -1;
  });
}

function renderAnswer(answer, note = "页面内预审答案") {
  document.querySelector("#answer-heading").textContent = QUESTION_LABELS[answer.question_id];
  document.querySelector("[data-answer-mode]").textContent = answer.mode;
  document.querySelector("[data-answer-mode]").dataset.mode = answer.mode;
  document.querySelector("[data-answer-note]").textContent = note;
  document.querySelector("[data-answer-summary]").textContent = answer.summary;
  replaceTextList(document.querySelector("[data-answer-points]"), answer.key_points, (item, value) => {
    item.textContent = value;
  });
  replaceTextList(document.querySelector("[data-answer-evidence]"), answer.evidence_ids, (item, value) => {
    const code = document.createElement("code");
    const label = document.createElement("span");
    code.textContent = value;
    label.textContent = SCENARIOS[answer.scenario_id].evidence[value];
    item.append(code, label);
  });
  replaceTextList(document.querySelector("[data-answer-boundaries]"), answer.boundaries, (item, value) => {
    item.textContent = value;
  });
  document.querySelector("[data-answer-contract]").textContent =
    `${answer.contract_version}／${answer.prompt_version}／synthetic true`;
}

function abortAfter(milliseconds) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), milliseconds);
  return {
    signal: controller.signal,
    abort: () => controller.abort(),
    clear: () => window.clearTimeout(timer),
  };
}

async function requestAnswer() {
  activeDeadline?.abort();
  const owner = ++requestOwner;
  const scenarioId = selectedScenario;
  const questionId = selectedQuestion;
  const fallback = staticAnswer(scenarioId, questionId);
  renderAnswer(fallback);
  answerSheet.setAttribute("aria-busy", "true");
  loading.hidden = false;
  retryButton.hidden = true;
  const deadline = abortAfter(10000);
  activeDeadline = deadline;
  try {
    const response = await fetch(ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({
        contract_version: CONTRACT_VERSION,
        case_id: CASE_ID,
        scenario_id: scenarioId,
        question_id: questionId,
        locale: "zh-CN",
      }),
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: deadline.signal,
    });
    if (!response.ok || !(response.headers.get("content-type") || "").toLowerCase().startsWith("application/json")) {
      throw new Error("leader endpoint unavailable");
    }
    const raw = await response.text();
    if (raw.length > 8000) throw new Error("leader response too large");
    const value = JSON.parse(raw);
    if (!validateResponse(value, scenarioId, questionId)) throw new Error("leader response invalid");
    if (owner === requestOwner) {
      renderAnswer(value, value.mode === "live" ? "受控模型解释" : "服务端预审答案");
      document.querySelector("[data-answer-announcer]").textContent =
        `回答已更新：${QUESTION_LABELS[questionId]}，模式 ${value.mode}`;
      retryButton.hidden = value.mode !== "static_fallback";
    }
  } catch (_error) {
    if (owner === requestOwner) {
      renderAnswer(fallback, "服务不可用，已安全降级");
      document.querySelector("[data-answer-announcer]").textContent =
        `同源服务不可用，已显示预审静态答案：${QUESTION_LABELS[questionId]}`;
      retryButton.hidden = false;
    }
  } finally {
    deadline.clear();
    if (owner === requestOwner) {
      activeDeadline = null;
      answerSheet.setAttribute("aria-busy", "false");
      loading.hidden = true;
    }
  }
}

scenarioButtons.forEach((button, index) => {
  button.addEventListener("click", () => {
    selectedScenario = button.dataset.scenario;
    renderScenario();
    requestAnswer();
  });
  button.addEventListener("keydown", (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const nextIndex = event.key === 'Home' ? 0 : event.key === 'End' ? scenarioButtons.length - 1
      : (index + (event.key === 'ArrowRight' ? 1 : -1) + scenarioButtons.length) % scenarioButtons.length;
    scenarioButtons[nextIndex].focus();
    scenarioButtons[nextIndex].click();
  });
});

questionButtons.forEach((button) => {
  button.addEventListener("click", () => {
    selectedQuestion = button.dataset.question;
    questionButtons.forEach((candidate) => {
      candidate.setAttribute("aria-pressed", String(candidate === button));
    });
    requestAnswer();
  });
});

retryButton.addEventListener("click", requestAnswer);
renderScenario();
requestAnswer();
