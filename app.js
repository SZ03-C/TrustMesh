const API = "/api/scans";

const form = document.querySelector("#scanForm");
const domainInput = document.querySelector("#domainInput");
const terminalBody = document.querySelector("#terminalBody");
const passport = document.querySelector("#passport");
const passportDomain = document.querySelector("#passportDomain");
const passportDecision = document.querySelector("#passportDecision");
const scoreValue = document.querySelector("#scoreValue");
const domainScore = document.querySelector("#domainScore");
const emailScore = document.querySelector("#emailScore");
const exposureScore = document.querySelector("#exposureScore");
const developerScore = document.querySelector("#developerScore");
const riskList = document.querySelector("#riskList");
const decisionStatus = document.querySelector("#decisionStatus");
const decisionText = document.querySelector("#decisionText");
const timelineList = document.querySelector("#timelineList");
const remediationList = document.querySelector("#remediationList");
const policyList = document.querySelector("#policyList");
const passportTags = document.querySelector("#passportTags");
const copyLink = document.querySelector("#copyLink");
const moduleStack = document.querySelector("#moduleStack");
const scoreRing = document.querySelector("#scoreRing");
const scanAnother = document.querySelector("#scanAnother");

function sanitizeDomain(value) {
  return value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
}

function writeTerminal(lines) {
  if (!terminalBody) return;
  terminalBody.innerHTML = lines.map((l) => `<p>${l}</p>`).join("");
}

function setModuleState(name, state) {
  if (!moduleStack) return;
  const el = moduleStack.querySelector(`[data-module="${name}"]`);
  if (!el) return;
  el.className = state;
  el.querySelector("span").textContent = state;
}

function resetModules() {
  if (!moduleStack) return;
  moduleStack.querySelectorAll("div").forEach((el) => {
    el.className = "";
    el.querySelector("span").textContent = "idle";
  });
}

function renderPassport(domain, data) {
  const s = data.scores;
  const d = data.decision;

  passportDomain.textContent = domain;
  passportDecision.textContent = d.label;
  scoreValue.textContent = s.total;

  domainScore.textContent = s.domain;
  emailScore.textContent = s.email;
  exposureScore.textContent = s.exposure;
  developerScore.textContent = s.developer;

  decisionStatus.textContent = d.status;
  decisionStatus.className = "decision-status " + (d.statusClass || "");
  decisionText.textContent = d.text || "Review findings below.";

  passportTags.innerHTML = ["live scan", "passive checks", "real evidence"].map((t) => `<span>${t}</span>`).join("");
  policyList.innerHTML = (d.policies || ["Review findings before sharing data"]).map((p) => `<div><span></span>${p}</div>`).join("");

  const severityColor = (sev) => {
    if (sev === "high" || sev === "critical") return "var(--red)";
    if (sev === "medium") return "var(--amber)";
    return "var(--cyan)";
  };

  riskList.innerHTML = data.findings
    .filter((f) => f.severity !== "info")
    .slice(0, 6)
    .map((f) => `
      <article class="risk-item">
        <span class="risk-color" style="background:${severityColor(f.severity)}"></span>
        <div>
          <div class="risk-title-row"><strong>${f.title}</strong><small>${f.severity}</small></div>
          <span>${f.description}</span>
        </div>
      </article>
    `).join("") || "<p style='color:var(--muted)'>No significant risks identified.</p>";

  timelineList.innerHTML = data.findings
    .slice(0, 6)
    .map((f) => `<div><strong>${f.category}</strong><span>${f.title}</span></div>`)
    .join("");

  const remediationItems = data.findings.filter((f) => f.severity !== "info").slice(0, 4);
  remediationList.innerHTML = remediationItems.length
    ? remediationItems.map((f, i) => `
      <article>
        <strong>${String(i + 1).padStart(2, "0")}</strong>
        <div>
          <span>${f.title}</span>
          <small>${f.category} / ${f.severity}</small>
        </div>
      </article>
    `).join("")
    : "<p style='color:var(--muted)'>No remediation needed.</p>";

  passport.classList.remove("hidden");
  passport.scrollIntoView({ behavior: "smooth", block: "start" });

  requestAnimationFrame(() => {
    scoreRing.style.setProperty("--score-deg", `${(s.total / 100) * 360}deg`);
  });
}

async function runScan(domain) {
  passport.classList.add("hidden");
  scoreRing.style.setProperty("--score-deg", "0deg");
  resetModules();

  const lines = [`target: ${domain}`, "mode: live scan", "connecting to scanner service..."];
  writeTerminal(lines);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server returned ${res.status}`);
    }

    const data = await res.json();

    for (const log of data.logs) {
      setModuleState(log.module, "running");
      await new Promise((r) => setTimeout(r, 300));
      setModuleState(log.module, "complete");
      lines.push(`ok: ${log.message}`);
      writeTerminal(lines);
    }

    lines.push(`passport generated for ${domain}`);
    writeTerminal(lines);
    renderPassport(domain, data);
  } catch (err) {
    if (err.name === "AbortError") {
      writeTerminal(["error: scan timed out. Is the server running?"]);
    } else {
      writeTerminal([`error: ${err.message}`]);
    }
    resetModules();
  }
}

if (form) {
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const domain = sanitizeDomain(domainInput.value);
    if (!domain || !domain.includes(".")) {
      writeTerminal(["error: enter a valid domain, e.g. example.com"]);
      return;
    }
    runScan(domain);
  });
}

if (scanAnother) {
  scanAnother.addEventListener("click", () => {
    passport.classList.add("hidden");
    domainInput.value = "";
    domainInput.focus();
    scoreRing.style.setProperty("--score-deg", "0deg");
    resetModules();
    writeTerminal(["waiting for domain input..."]);
  });
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && domainInput) domainInput.focus();
});

if (copyLink) {
  copyLink.addEventListener("click", async () => {
    const domain = sanitizeDomain(passportDomain.textContent);
    const link = `${window.location.href.split("#")[0]}#passport-${domain}`;
    try {
      await navigator.clipboard.writeText(link);
      copyLink.textContent = "Copied";
    } catch {
      copyLink.textContent = "Link ready";
    }
    setTimeout(() => { copyLink.textContent = "Copy passport link"; }, 1400);
  });
}
