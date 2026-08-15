"use strict";

document.documentElement.classList.add("js");

const PAGE_ORDER = Object.freeze(["overview", "method", "case", "proof"]);
const PAGE_HASH_ALIASES = Object.freeze({
  top: "overview",
  problem: "overview",
  system: "method",
  demo: "case",
  evidence: "proof",
});
const SCENARIO_KEYS = new Set(["conflict", "blocked", "ready"]);
const EXPECTED_SCENARIOS = Object.freeze({
  conflict: Object.freeze({
    status: "CONTRADICTED",
    statusClass: "is-conflict",
    result: Object.freeze({
      mode: "RUN_EVALUATION_UNBOUND",
      trusted: false,
      admission: "BLOCKED",
      overall_status: "CONTRADICTED",
      rules: 7,
      pass: 4,
      contradicted: 3,
    }),
  }),
  blocked: Object.freeze({
    status: "REPLAY BLOCKED",
    statusClass: "is-blocked",
    result: Object.freeze({
      http_status: 409,
      status: "BLOCKED",
      approval_mode: "SOURCE_ROOTED_RAW_MATERIAL_REQUIRED",
      error: "A08_SOURCE_PACK_REQUIRED",
    }),
  }),
  ready: Object.freeze({
    status: "READY FOR HUMAN REVIEW",
    statusClass: "is-ready",
    result: Object.freeze({
      mode: "SOURCE_ROOTED_RUN",
      trusted: true,
      overall_status: "PASS",
      case_source_assurance_state: "BOUND_RAW_SOURCE_CASE",
      team_state: "READY_FOR_HUMAN_RELEASE_REVIEW",
    }),
  }),
});
const motionPreference = matchMedia("(prefers-reduced-motion: reduce)");

const nav = document.querySelector("#site-nav");
const navToggle = document.querySelector(".nav-toggle");
const navToggleLabel = navToggle?.querySelector(".sr-only");
const pageRoot = document.querySelector("main");
const pages = new Map(
  PAGE_ORDER.map((key) => [key, document.querySelector(`[data-page="${key}"]`)]).filter(
    ([, page]) => page,
  ),
);
const pageTargets = Array.from(document.querySelectorAll("[data-page-target]"));
const pagePreviousControls = Array.from(document.querySelectorAll("[data-page-prev]"));
const pageNextControls = Array.from(document.querySelectorAll("[data-page-next]"));
const pageNumbers = Array.from(document.querySelectorAll("[data-page-number]"));
const pageProgress = Array.from(document.querySelectorAll("[data-page-progress]"));
const pageAnnouncers = Array.from(document.querySelectorAll("[data-page-announcer]"));
const evidenceLinks = Array.from(document.querySelectorAll("[data-open-evidence]"));
const caseSummary = document.querySelector("[data-case-summary]");
const caseDetail = document.querySelector("[data-case-detail]");

const tabs = Array.from(document.querySelectorAll("[data-scenario]"));
const status = document.querySelector("[data-story-status]");
const title = document.querySelector("[data-story-title]");
const copy = document.querySelector("[data-story-copy]");
const points = document.querySelector("[data-story-points]");
const code = document.querySelector("[data-story-code]");
const hashStatus = document.querySelector("[data-hash-status]");
const sequence = document.querySelector("[data-regression-sequence]");
const sequenceSteps = Array.from(document.querySelectorAll("[data-sequence-step]"));
const sequenceStage = document.querySelector("[data-sequence-stage]");

let manifestPromise;
let selectionRequest = 0;
let pageRequest = 0;
let currentPageKey;
let pendingPageKey;
let activeViewTransition;
let pageTransitionOwner;
let storyTransitionOwner;
let touchStart;

function prefersReducedMotion() {
  return motionPreference.matches;
}

function getPageKeyFromHash(hash = location.hash) {
  let key;
  try {
    key = decodeURIComponent(hash.replace(/^#/, "")).trim().toLowerCase();
  } catch {
    return undefined;
  }
  key = PAGE_HASH_ALIASES[key] ?? key;
  return pages.has(key) ? key : undefined;
}

function getPageIndex(key) {
  return PAGE_ORDER.indexOf(key);
}

function getPageHeading(key) {
  return pages.get(key)?.querySelector("[data-page-title], h1, h2");
}

function getPageLabel(key) {
  const page = pages.get(key);
  const heading = getPageHeading(key);
  return page?.dataset.pageLabel || heading?.textContent?.replace(/\s+/g, " ").trim() || key;
}

function setControlDisabled(control, disabled, label) {
  if ("disabled" in control) control.disabled = disabled;
  control.setAttribute("aria-disabled", String(disabled));
  if (label) control.setAttribute("aria-label", label);
}

function updatePageChrome(key) {
  const index = getPageIndex(key);
  if (index < 0) return;

  for (const target of pageTargets) {
    const selected = target.dataset.pageTarget === key;
    target.classList.toggle("is-active", selected);
    if (target instanceof HTMLAnchorElement) {
      if (selected) target.setAttribute("aria-current", "page");
      else target.removeAttribute("aria-current");
    } else if (target instanceof HTMLButtonElement) {
      target.setAttribute("aria-pressed", String(selected));
    }
  }

  const previousKey = PAGE_ORDER[index - 1];
  const nextKey = PAGE_ORDER[index + 1];
  for (const control of pagePreviousControls) {
    setControlDisabled(
      control,
      !previousKey,
      previousKey ? `上一章：${getPageLabel(previousKey)}` : "已经是第一章",
    );
  }
  for (const control of pageNextControls) {
    setControlDisabled(
      control,
      !nextKey,
      nextKey ? `下一章：${getPageLabel(nextKey)}` : "已经是最后一章",
    );
  }

  const position = index + 1;
  const ratio = position / PAGE_ORDER.length;
  const pageNumber = String(position).padStart(2, "0");
  for (const number of pageNumbers) number.textContent = pageNumber;
  for (const progress of pageProgress) {
    progress.style.setProperty("--page-progress", String(ratio));
    progress.setAttribute("aria-valuemin", "1");
    progress.setAttribute("aria-valuemax", String(PAGE_ORDER.length));
    progress.setAttribute("aria-valuenow", String(position));
    progress.setAttribute("aria-valuetext", `第 ${position} 章，共 ${PAGE_ORDER.length} 章`);
    if (progress instanceof HTMLProgressElement) {
      progress.max = PAGE_ORDER.length;
      progress.value = position;
    }
  }
}

function announcePage(key) {
  const index = getPageIndex(key);
  if (index < 0) return;
  const message = `第 ${index + 1} 章，共 ${PAGE_ORDER.length} 章：${getPageLabel(key)}`;
  for (const announcer of pageAnnouncers) announcer.textContent = message;
}

function applyPageState(key) {
  currentPageKey = key;
  pendingPageKey = undefined;
  document.documentElement.dataset.page = key;
  for (const [pageKey, page] of pages) {
    const selected = pageKey === key;
    page.hidden = !selected;
    page.classList.toggle("is-active", selected);
    if (selected) page.removeAttribute("aria-hidden");
    else page.setAttribute("aria-hidden", "true");
  }
  updatePageChrome(key);
}

function writePageHistory(key, mode) {
  if (mode === "none") return;
  const hash = `#${key}`;
  const state = { qualityciPage: key };
  if (mode === "push" && location.hash !== hash) history.pushState(state, "", hash);
  else history.replaceState(state, "", hash);
}

function resetPageScroll(key) {
  const page = pages.get(key);
  if (page) page.scrollTop = 0;
  if (document.scrollingElement) document.scrollingElement.scrollTop = 0;
}

function focusPage(key) {
  const heading = getPageHeading(key);
  if (!(heading instanceof HTMLElement)) return;
  if (!heading.hasAttribute("tabindex")) heading.setAttribute("tabindex", "-1");
  heading.focus({ preventScroll: true });
}

function clearPageTransitionMarkers() {
  for (const page of pages.values()) page.removeAttribute("data-vt-page");
  caseSummary?.removeAttribute("data-vt-case");
  caseDetail?.removeAttribute("data-vt-case");
}

function finishPageChange(key, request, shouldFocus, shouldAnnounce) {
  if (request !== pageRequest || currentPageKey !== key) return;
  resetPageScroll(key);
  if (shouldFocus) focusPage(key);
  if (shouldAnnounce) announcePage(key);
}

function goToPage(
  key,
  {
    historyMode = "push",
    focus = true,
    announce = true,
    direction,
    sharedCase = false,
  } = {},
) {
  if (!pages.has(key)) return false;
  if (pendingPageKey === key) return true;

  const request = ++pageRequest;
  pendingPageKey = key;
  const previousKey = currentPageKey;
  const previousIndex = getPageIndex(previousKey);
  const nextIndex = getPageIndex(key);
  const pageDirection = direction || (nextIndex >= previousIndex ? "forward" : "backward");

  if (previousKey === key) {
    pendingPageKey = undefined;
    writePageHistory(key, historyMode === "push" ? "replace" : historyMode);
    updatePageChrome(key);
    finishPageChange(key, request, focus, announce);
    return true;
  }

  const previousPage = pages.get(previousKey);
  const nextPage = pages.get(key);
  const useSharedCase =
    sharedCase && previousKey === "overview" && key === "case" && caseSummary && caseDetail;
  const commit = () => {
    if (request !== pageRequest) return false;
    applyPageState(key);
    writePageHistory(key, historyMode);
    return true;
  };

  activeViewTransition?.skipTransition();
  clearPageTransitionMarkers();

  if (prefersReducedMotion() || typeof document.startViewTransition !== "function") {
    delete document.documentElement.dataset.pageDirection;
    commit();
    finishPageChange(key, request, focus, announce);
    return true;
  }

  document.documentElement.dataset.pageDirection = pageDirection;
  previousPage?.setAttribute("data-vt-page", "");
  if (useSharedCase) caseSummary.setAttribute("data-vt-case", "");

  const transition = document.startViewTransition(() => {
    if (request !== pageRequest) return;
    previousPage?.removeAttribute("data-vt-page");
    if (useSharedCase) caseSummary.removeAttribute("data-vt-case");
    commit();
    nextPage?.setAttribute("data-vt-page", "");
    if (useSharedCase) caseDetail.setAttribute("data-vt-case", "");
  });

  activeViewTransition = transition;
  pageTransitionOwner = transition;
  transition.updateCallbackDone.then(
    () => finishPageChange(key, request, focus, announce),
    () => finishPageChange(key, request, focus, announce),
  );
  transition.finished.finally(() => {
    if (pageTransitionOwner === transition) {
      clearPageTransitionMarkers();
      delete document.documentElement.dataset.pageDirection;
      pageTransitionOwner = undefined;
    }
    if (pendingPageKey === key && currentPageKey !== key) pendingPageKey = undefined;
    if (activeViewTransition === transition) activeViewTransition = undefined;
  });
  return true;
}

function movePage(offset, options = {}) {
  const currentIndex = getPageIndex(pendingPageKey ?? currentPageKey);
  const nextKey = PAGE_ORDER[currentIndex + offset];
  if (!nextKey) return false;
  return goToPage(nextKey, {
    ...options,
    direction: offset > 0 ? "forward" : "backward",
  });
}

function isInteractiveTarget(target) {
  if (!(target instanceof Element)) return false;
  return Boolean(
    target.closest(
      'a, button, input, select, textarea, summary, pre, code, [contenteditable="true"], [role="tab"], [role="button"], [role="textbox"], [role="combobox"], [role="listbox"], [role="slider"], [role="spinbutton"], [data-page-keys="ignore"]',
    ),
  );
}

function closeNavigation({ restoreFocus = false } = {}) {
  if (!nav?.classList.contains("is-open")) return false;
  nav.classList.remove("is-open");
  navToggle?.setAttribute("aria-expanded", "false");
  if (navToggleLabel) navToggleLabel.textContent = "打开导航";
  if (restoreFocus) navToggle?.focus();
  return true;
}

navToggle?.addEventListener("click", () => {
  const open = nav?.classList.toggle("is-open") ?? false;
  navToggle.setAttribute("aria-expanded", String(open));
  if (navToggleLabel) navToggleLabel.textContent = open ? "关闭导航" : "打开导航";
});

nav?.addEventListener("click", (event) => {
  if (!(event.target instanceof Element) || !event.target.closest("a")) return;
  closeNavigation();
});

document.querySelector(".skip-link")?.addEventListener("click", (event) => {
  event.preventDefault();
  focusPage(currentPageKey);
});

const deckNavigationTargets = Array.from(new Set([...pageTargets, ...evidenceLinks]));
for (const target of deckNavigationTargets) {
  target.addEventListener("click", (event) => {
    if (target.getAttribute("aria-disabled") === "true") {
      event.preventDefault();
      return;
    }
    const isEvidenceLink = target.hasAttribute("data-open-evidence");
    const key = isEvidenceLink ? "case" : target.dataset.pageTarget;
    if (!pages.has(key)) return;
    event.preventDefault();
    closeNavigation();
    goToPage(key, { sharedCase: isEvidenceLink });
  });
}

for (const control of pagePreviousControls) {
  control.addEventListener("click", (event) => {
    event.preventDefault();
    if (control.getAttribute("aria-disabled") !== "true") movePage(-1);
  });
}

for (const control of pageNextControls) {
  control.addEventListener("click", (event) => {
    event.preventDefault();
    if (control.getAttribute("aria-disabled") !== "true") movePage(1);
  });
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && closeNavigation({ restoreFocus: true })) {
    event.preventDefault();
    return;
  }
  if (
    event.defaultPrevented ||
    event.isComposing ||
    event.repeat ||
    event.altKey ||
    event.ctrlKey ||
    event.metaKey ||
    event.shiftKey ||
    isInteractiveTarget(event.target)
  ) {
    return;
  }

  let handled = false;
  if (event.key === "PageUp") handled = movePage(-1);
  else if (event.key === "PageDown") handled = movePage(1);
  else if (event.key === "Home" && currentPageKey !== PAGE_ORDER[0]) {
    handled = goToPage(PAGE_ORDER[0], { direction: "backward" });
  } else if (event.key === "End" && currentPageKey !== PAGE_ORDER.at(-1)) {
    handled = goToPage(PAGE_ORDER.at(-1), { direction: "forward" });
  }
  if (handled) event.preventDefault();
});

pageRoot?.addEventListener(
  "touchstart",
  (event) => {
    if (event.touches.length !== 1 || isInteractiveTarget(event.target)) {
      touchStart = undefined;
      return;
    }
    const touch = event.touches[0];
    touchStart = { x: touch.clientX, y: touch.clientY, time: performance.now() };
  },
  { passive: true },
);

pageRoot?.addEventListener(
  "touchend",
  (event) => {
    if (!touchStart || event.changedTouches.length !== 1) {
      touchStart = undefined;
      return;
    }
    const touch = event.changedTouches[0];
    const deltaX = touch.clientX - touchStart.x;
    const deltaY = touch.clientY - touchStart.y;
    const elapsed = performance.now() - touchStart.time;
    touchStart = undefined;
    if (elapsed > 800 || Math.abs(deltaX) < 56 || Math.abs(deltaX) < Math.abs(deltaY) * 1.35) {
      return;
    }
    movePage(deltaX < 0 ? 1 : -1);
  },
  { passive: true },
);

pageRoot?.addEventListener("touchcancel", () => {
  touchStart = undefined;
});

function syncPageFromLocation() {
  const key = getPageKeyFromHash();
  if (key && key !== currentPageKey && key !== pendingPageKey) {
    goToPage(key, { historyMode: "none" });
  }
}

window.addEventListener("popstate", syncPageFromLocation);
window.addEventListener("hashchange", syncPageFromLocation);

motionPreference.addEventListener?.("change", (event) => {
  if (event.matches) activeViewTransition?.skipTransition();
});

if (pages.size > 0) {
  const initialPage = getPageKeyFromHash() || PAGE_ORDER.find((key) => pages.has(key));
  if (initialPage) {
    applyPageState(initialPage);
    writePageHistory(initialPage, "replace");
    resetPageScroll(initialPage);
  }
}

// Browsers may perform their native hash scroll after deferred scripts run.
// The active chapter already owns the viewport, so keep its first frame below
// the sticky header instead of letting the anchor hide it.
window.addEventListener("load", () => resetPageScroll(currentPageKey), { once: true });

function setHashStatus(message, state) {
  if (!hashStatus) return;
  hashStatus.textContent = message;
  hashStatus.dataset.state = state;
  if (state === "matched" && !prefersReducedMotion()) {
    hashStatus.animate(
      [
        { opacity: 0.35, transform: "translateY(3px)" },
        { opacity: 1, transform: "translateY(0)" },
      ],
      { duration: 180, easing: "cubic-bezier(.2,.8,.2,1)" },
    );
  }
}

function setSequencePhase(phase) {
  if (!sequence || !sequenceStage) return;
  const next = Math.min(sequenceSteps.length - 1, Math.max(0, phase));
  sequenceStage.dataset.phase = String(next);
  sequence.style.setProperty("--sequence-progress", String((next + 1) / sequenceSteps.length));
  sequenceSteps.forEach((step, index) => {
    const selected = index === next;
    step.setAttribute("aria-pressed", String(selected));
    step.closest("li")?.classList.toggle("is-active", selected);
  });
}

for (const step of sequenceSteps) {
  step.addEventListener("click", () => setSequencePhase(Number(step.dataset.sequencePhase)));
}

setSequencePhase(0);

async function loadManifest() {
  manifestPromise ??= fetch("./demo-data/manifest.json", {
    cache: "no-store",
    credentials: "same-origin",
  }).then(async (response) => {
    if (!response.ok) throw new Error(`manifest HTTP ${response.status}`);
    const manifest = await response.json();
    if (
      manifest?.synthetic !== true ||
      manifest?.runtime_mode !== "STATIC_CONTRACT_WALKTHROUGH" ||
      typeof manifest?.scenarios !== "object" ||
      typeof manifest?.scenario_sha256 !== "object"
    ) {
      throw new Error("invalid replay manifest");
    }
    return manifest;
  });
  return manifestPromise;
}

async function loadScenario(key) {
  if (!SCENARIO_KEYS.has(key)) throw new Error("unknown replay scenario");
  const manifest = await loadManifest();
  const relativePath = manifest.scenarios[key];
  const expectedSha256 = manifest.scenario_sha256[key];
  if (typeof relativePath !== "string" || !/^[a-z0-9-]+\.json$/.test(relativePath)) {
    throw new Error("unknown replay scenario");
  }
  if (typeof expectedSha256 !== "string" || !/^[0-9a-f]{64}$/.test(expectedSha256)) {
    throw new Error("invalid replay digest");
  }
  const response = await fetch(`./demo-data/${relativePath}`, {
    cache: "no-store",
    credentials: "same-origin",
  });
  if (!response.ok) throw new Error(`scenario HTTP ${response.status}`);
  const raw = await response.arrayBuffer();
  const actualSha256 = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", raw)))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  if (actualSha256 !== expectedSha256) throw new Error("replay digest mismatch");
  const scenario = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  const expected = EXPECTED_SCENARIOS[key];
  const resultKeys =
    scenario?.result && typeof scenario.result === "object" && !Array.isArray(scenario.result)
      ? Object.keys(scenario.result)
      : [];
  const expectedResultKeys = Object.keys(expected.result);
  if (
    scenario?.synthetic !== true ||
    scenario?.scenario_id !== key ||
    scenario?.status !== expected.status ||
    scenario?.status_class !== expected.statusClass ||
    typeof scenario?.title !== "string" ||
    typeof scenario?.copy !== "string" ||
    !Array.isArray(scenario?.points) ||
    !scenario.points.every((point) => typeof point === "string") ||
    resultKeys.length !== expectedResultKeys.length ||
    !expectedResultKeys.every(
      (resultKey) =>
        Object.hasOwn(scenario.result, resultKey) &&
        scenario.result[resultKey] === expected.result[resultKey],
    )
  ) {
    throw new Error("invalid replay scenario");
  }
  return scenario;
}

function renderScenario(key, scenario) {
  if (!status || !title || !copy || !points || !code) return;

  for (const tab of tabs) {
    const selected = tab.dataset.scenario === key;
    tab.setAttribute("aria-selected", String(selected));
    tab.setAttribute("tabindex", selected ? "0" : "-1");
  }
  document.querySelector("[data-story]")?.setAttribute("aria-labelledby", `tab-${key}`);

  status.textContent = scenario.status;
  status.className = `story-status ${scenario.status_class}`;
  title.textContent = scenario.title;
  copy.textContent = scenario.copy;
  points.replaceChildren(
    ...scenario.points.map((point) => {
      const item = document.createElement("li");
      item.textContent = point;
      return item;
    }),
  );
  code.textContent = JSON.stringify(scenario.result, null, 2);
}

function renderScenarioWithFeedback(key, scenario) {
  const story = document.querySelector("[data-story]");
  const storyPage = story?.closest("[data-page]");
  if (
    !story ||
    storyPage?.hidden ||
    pageTransitionOwner ||
    prefersReducedMotion() ||
    typeof document.startViewTransition !== "function"
  ) {
    renderScenario(key, scenario);
    return Promise.resolve();
  }

  story.setAttribute("data-vt-story", "");
  activeViewTransition?.skipTransition();
  const transition = document.startViewTransition(() => renderScenario(key, scenario));
  activeViewTransition = transition;
  storyTransitionOwner = transition;
  transition.finished.finally(() => {
    if (storyTransitionOwner === transition) {
      story.removeAttribute("data-vt-story");
      storyTransitionOwner = undefined;
    }
    if (activeViewTransition === transition) activeViewTransition = undefined;
  });
  return transition.updateCallbackDone;
}

async function selectScenario(key, selectedTab) {
  if (!SCENARIO_KEYS.has(key)) return;
  const request = ++selectionRequest;
  for (const tab of tabs) tab.removeAttribute("aria-busy");
  selectedTab?.setAttribute("aria-busy", "true");
  setHashStatus("正在校验摘要", "checking");
  try {
    const scenario = await loadScenario(key);
    if (request === selectionRequest) {
      await renderScenarioWithFeedback(key, scenario);
      if (request === selectionRequest) {
        setHashStatus("本次浏览器校验已匹配", "matched");
      }
    }
  } catch {
    if (request === selectionRequest && code) {
      code.textContent = "静态契约示意暂时无法读取，请稍后刷新页面。";
      setHashStatus("摘要校验失败", "failed");
    }
  } finally {
    if (request === selectionRequest) selectedTab?.removeAttribute("aria-busy");
  }
}

for (const tab of tabs) {
  tab.addEventListener("click", () => selectScenario(tab.dataset.scenario, tab));
  tab.addEventListener("keydown", (event) => {
    if (!new Set(["ArrowLeft", "ArrowRight", "Home", "End"]).has(event.key)) return;
    event.preventDefault();
    const current = tabs.indexOf(tab);
    const next =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? tabs.length - 1
          : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].focus();
    selectScenario(tabs[next].dataset.scenario, tabs[next]);
  });
}

const initialTab = tabs.find((tab) => tab.dataset.scenario === "conflict");
if (initialTab) selectScenario("conflict", initialTab);
