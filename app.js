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
const copyLink = document.querySelector("#copyLink");

const scanSteps = [
  "verifying domain identity...",
  "checking TLS and security headers...",
  "evaluating SPF, DKIM, and DMARC posture...",
  "mapping public exposure signals...",
  "reviewing developer trust indicators...",
  "building cyber trust passport..."
];

const modules = [
  ["Domain", "HTTPS reachable, certificate valid, headers partially configured"],
  ["Email", "SPF present, DMARC policy needs stronger enforcement"],
  ["Exposure", "No critical admin panel found in simulated passive scan"],
  ["GitHub", "Security policy missing, workflow permissions need review"]
];

const riskTemplates = [
  {
    title: "DMARC policy is not strict enough",
    body: "Attackers may spoof this domain in phishing campaigns. Move toward quarantine or reject after testing.",
    color: "var(--amber)"
  },
  {
    title: "Security headers are incomplete",
    body: "Missing browser-side protections can increase exposure to clickjacking, content injection, or downgrade issues.",
    color: "var(--amber)"
  },
  {
    title: "Developer trust evidence is limited",
    body: "A missing SECURITY.md or weak repository governance makes responsible disclosure and code ownership harder.",
    color: "var(--cyan)"
  },
  {
    title: "Collaboration should be restricted",
    body: "Share low-risk information first. Avoid production credentials until evidence improves.",
    color: "var(--red)"
  },
  {
    title: "Continuous monitoring is not enabled",
    body: "Trust can change after onboarding. Recheck this passport before major data-sharing decisions.",
    color: "var(--green)"
  }
];

function sanitizeDomain(value) {
  return value
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
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
      text: "This organization is suitable for normal collaboration. Review detailed evidence before sharing highly sensitive data."
    };
  }

  if (score >= 68) {
    return {
      label: "Collaborate with restrictions",
      status: "Restricted",
      text: "Safe for low-risk collaboration. Avoid sharing production credentials or sensitive customer data until high-priority fixes are complete."
    };
  }

  return {
    label: "Do not share sensitive data yet",
    status: "High Risk",
    text: "This organization needs remediation before sensitive data, privileged access, or production integrations should be approved."
  };
}

function writeTerminal(lines) {
  terminalBody.innerHTML = lines.map((line) => `<p>${line}</p>`).join("");
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
  decisionText.textContent = decision.text;

  riskList.innerHTML = riskTemplates
    .map((risk) => `
      <article class="risk-item">
        <span class="risk-color" style="background:${risk.color}"></span>
        <div>
          <strong>${risk.title}</strong>
          <span>${risk.body}</span>
        </div>
      </article>
    `)
    .join("");

  timelineList.innerHTML = modules
    .map(([name, evidence]) => `
      <div>
        <strong>${name}</strong>
        <span>${evidence}</span>
      </div>
    `)
    .join("");

  passport.classList.remove("hidden");
  passport.scrollIntoView({ behavior: "smooth", block: "start" });

  const ring = document.querySelector("#scoreRing");
  requestAnimationFrame(() => {
    ring.style.setProperty("--score-deg", `${(scores.total / 100) * 360}deg`);
  });
}

async function runScan(domain) {
  passport.classList.add("hidden");
  const lines = [`target: ${domain}`, "mode: prototype simulation"];
  writeTerminal(lines);

  for (const step of scanSteps) {
    await new Promise((resolve) => setTimeout(resolve, 420));
    lines.push(`ok: ${step}`);
    writeTerminal(lines);
  }

  lines.push("passport generated.");
  writeTerminal(lines);
  renderPassport(domain);
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const domain = sanitizeDomain(domainInput.value);

  if (!domain || !domain.includes(".")) {
    writeTerminal(["error: enter a valid organization domain, for example trustmesh.io"]);
    return;
  }

  runScan(domain);
});

document.querySelector("#scanAnother").addEventListener("click", () => {
  passport.classList.add("hidden");
  domainInput.value = "";
  domainInput.focus();
  const ring = document.querySelector("#scoreRing");
  ring.style.setProperty("--score-deg", "0deg");
  writeTerminal(["waiting for domain input..."]);
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    domainInput.focus();
  }
});

copyLink.addEventListener("click", async () => {
  const domain = sanitizeDomain(passportDomain.textContent);
  const link = `${window.location.href.split("#")[0]}#passport-${domain}`;

  try {
    await navigator.clipboard.writeText(link);
    copyLink.textContent = "Copied";
  } catch {
    copyLink.textContent = "Link ready";
  }

  setTimeout(() => {
    copyLink.textContent = "Copy passport link";
  }, 1400);
});
