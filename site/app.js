"use strict";

document.documentElement.classList.add("js");

const header = document.querySelector("[data-header]");
const nav = document.querySelector("#site-nav");
const navToggle = document.querySelector(".nav-toggle");
const navToggleLabel = navToggle?.querySelector(".sr-only");
const tabs = Array.from(document.querySelectorAll("[data-scenario]"));
const status = document.querySelector("[data-story-status]");
const title = document.querySelector("[data-story-title]");
const copy = document.querySelector("[data-story-copy]");
const points = document.querySelector("[data-story-points]");
const code = document.querySelector("[data-story-code]");

let manifestPromise;
let selectionRequest = 0;

function updateHeader() {
  header?.classList.toggle("is-scrolled", window.scrollY > 24);
}

window.addEventListener("scroll", updateHeader, { passive: true });
updateHeader();

navToggle?.addEventListener("click", () => {
  const open = nav?.classList.toggle("is-open") ?? false;
  navToggle.setAttribute("aria-expanded", String(open));
  if (navToggleLabel) navToggleLabel.textContent = open ? "关闭导航" : "打开导航";
});

nav?.addEventListener("click", (event) => {
  if (!(event.target instanceof HTMLAnchorElement)) return;
  nav.classList.remove("is-open");
  navToggle?.setAttribute("aria-expanded", "false");
  if (navToggleLabel) navToggleLabel.textContent = "打开导航";
});

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
      typeof manifest?.scenarios !== "object"
    ) {
      throw new Error("invalid replay manifest");
    }
    return manifest;
  });
  return manifestPromise;
}

async function loadScenario(key) {
  const manifest = await loadManifest();
  const relativePath = manifest.scenarios[key];
  const expectedSha256 = manifest.scenario_sha256?.[key];
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
  if (scenario?.synthetic !== true || scenario?.scenario_id !== key) {
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

async function selectScenario(key, selectedTab) {
  const request = ++selectionRequest;
  selectedTab?.setAttribute("aria-busy", "true");
  try {
    const scenario = await loadScenario(key);
    if (request === selectionRequest) renderScenario(key, scenario);
  } catch {
    if (request === selectionRequest && code) {
      code.textContent = "静态契约示意暂时无法读取，请稍后刷新页面。";
    }
  } finally {
    selectedTab?.removeAttribute("aria-busy");
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
