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

const scanSteps = [
  ["Domain", "verifying domain identity and HTTPS posture..."],
  ["Email", "checking SPF, DKIM, DMARC, and spoofing exposure..."],
  ["Exposure", "mapping passive public exposure signals..."],
  ["Developer", "reviewing developer trust indicators..."],
  ["Decision", "building collaboration decision and passport evidence..."]
];

const modules = [
  ["Domain", "HTTPS reachable, certificate valid, security headers partially configured"],
  ["Email", "SPF present, DMARC policy should move toward enforcement"],
  ["Exposure", "No critical admin panel found in simulated passive review"],
  ["Developer", "Security policy and workflow permissions need review"],
  ["Decision", "Restricted collaboration recommended until priority fixes close"]
];

const riskTemplates = [
  { title: "DMARC policy is not strict enough", body: "Attackers may spoof this domain in phishing campaigns. Move toward quarantine or reject after testing.", severity: "High", color: "var(--amber)" },
  { title: "Security headers are incomplete", body: "Missing browser-side protections can increase exposure to clickjacking, content injection, or downgrade issues.", severity: "Medium", color: "var(--cyan)" },
  { title: "Developer trust evidence is limited", body: "Missing SECURITY.md or weak repository governance makes responsible disclosure harder.", severity: "Medium", color: "var(--cyan)" },
  { title: "Collaboration should be restricted", body: "Share low-risk information first. Avoid production credentials until evidence improves.", severity: "Policy", color: "var(--red)" },
  { title: "Continuous monitoring is not enabled", body: "Trust can change after onboarding. Recheck this passport before major data-sharing decisions.", severity: "Low", color: "var(--green)" }
];

const remediationTemplates = [
  ["01", "Publish a DMARC enforcement roadmap", "Email owners", "High"],
  ["02", "Add missing security headers", "Web platform", "Medium"],
  ["03", "Create SECURITY.md and disclosure contact", "Engineering", "Medium"],
  ["04", "Review GitHub Actions workflow permissions", "DevOps", "Medium"]
];

function sanitizeDomain(value) {
  return value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
}

function scoreFromDomain(domain) {
  const seed = Array.from(domain).reduce((total, char) => total + char.charCodeAt(0), 0);
  return {
    total: 62 + (seed % 26),
    domain: 70 + (seed % 22),
    email: 56 + (seed % 31),
    exposure: 64 + (seed % 25),
    developer: 58 + (seed % 33)
  };
}

function decisionForScore(score) {
  if (score >= 82) {
    return {
      label: "Safe to collaborate",
      status: "Verified",
      statusClass: "verified",
      text: "This organization is suitable for normal collaboration. Review detailed evidence before sharing highly sensitive data.",
      policies: ["Approve standard SaaS access", "Require evidence for regulated data", "Monitor every 30 days"]
    };
  }
  if (score >= 68) {
    return {
      label: "Collaborate with restrictions",
      status: "Restricted",
      statusClass: "restricted",
      text: "Safe for low-risk collaboration. Avoid sharing production credentials or sensitive customer data until high-priority fixes are complete.",
      policies: ["Share only low-risk data", "Block production secrets", "Request remediation proof"]
    };
  }
  return {
    label: "Do not share sensitive data yet",
    status: "High Risk",
    statusClass: "high-risk",
    text: "This organization needs remediation before sensitive data, privileged access, or production integrations should be approved.",
    policies: ["Deny privileged access", "Require owner verification", "Recheck after fixes"]
  };
}

function writeTerminal(lines) {
  if (!terminalBody) return;
  terminalBody.innerHTML = lines.map((line) => `<p>${line}</p>`).join("");
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

function renderPassport(domain) {
  const scores = scoreFromDomain(domain);
  const decision = decisionForScore(scores.total);

  passportDomain.textContent = domain;
  passportDecision.textContent = decision.label;
  scoreValue.textContent = scores.total;
  domainScore.textContent = scores.domain;
  emailScore.textContent = scores.email;
  exposureScore.textContent = scores.exposure;
  developerScore.textContent = scores.developer;
  decisionStatus.textContent = decision.status;
  decisionStatus.className = `decision-status ${decision.statusClass}`;
  decisionText.textContent = decision.text;

  passportTags.innerHTML = ["generated passport", "passive scan", "prototype evidence"].map((t) => `<span>${t}</span>`).join("");
  policyList.innerHTML = decision.policies.map((p) => `<div><span></span>${p}</div>`).join("");

  riskList.innerHTML = riskTemplates.map((r) => `
    <article class="risk-item">
      <span class="risk-color" style="background:${r.color}"></span>
      <div>
        <div class="risk-title-row"><strong>${r.title}</strong><small>${r.severity}</small></div>
        <span>${r.body}</span>
      </div>
    </article>
  `).join("");

  timelineList.innerHTML = modules.map(([name, evidence]) => `<div><strong>${name}</strong><span>${evidence}</span></div>`).join("");
  remediationList.innerHTML = remediationTemplates.map(([num, title, owner, priority]) => `
    <article><strong>${num}</strong><div><span>${title}</span><small>${owner} / ${priority}</small></div></article>
  `).join("");

  passport.classList.remove("hidden");
  passport.scrollIntoView({ behavior: "smooth", block: "start" });

  requestAnimationFrame(() => {
    scoreRing.style.setProperty("--score-deg", `${(scores.total / 100) * 360}deg`);
  });
}

async function runScan(domain) {
  passport.classList.add("hidden");
  scoreRing.style.setProperty("--score-deg", "0deg");
  resetModules();

  const lines = [`target: ${domain}`, "mode: prototype simulation", "scan type: passive trust review"];
  writeTerminal(lines);

  for (const [moduleName, step] of scanSteps) {
    setModuleState(moduleName, "running");
    await new Promise((resolve) => setTimeout(resolve, 430));
    setModuleState(moduleName, "complete");
    lines.push(`ok: ${step}`);
    writeTerminal(lines);
  }

  lines.push("passport generated.");
  writeTerminal(lines);
  renderPassport(domain);
}

if (form) {
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const domain = sanitizeDomain(domainInput.value);
    if (!domain || !domain.includes(".")) {
      writeTerminal(["error: enter a valid organization domain, for example trustmesh.io"]);
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
