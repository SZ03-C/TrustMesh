const form = document.querySelector("#scanForm");
const domainInput = document.querySelector("#domainInput");
const terminalBody = document.querySelector("#terminalBody");
const passport = document.querySelector("#passport");
const passportDomain = document.querySelector("#passportDomain");
const passportDecision = document.querySelector("#passportDecision");
const scoreValue = document.querySelector("#scoreValue");
const adminDetails = document.querySelector("#adminDetails");
const loginPrompt = document.querySelector("#loginPrompt");
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

function getToken() { return localStorage.getItem("tm_token"); }
function getUser() { return JSON.parse(localStorage.getItem("tm_user") || "null"); }

function writeTerminal(lines) {
  if (!terminalBody) return;
  terminalBody.innerHTML = lines.map(function(line) { return "<p>" + line + "</p>"; }).join("");
  terminalBody.scrollTop = terminalBody.scrollHeight;
}

function setModuleState(name, state) {
  if (!moduleStack) return;
  var el = moduleStack.querySelector("[data-module=\"" + name + "\"]");
  if (!el) return;
  el.className = state;
  el.querySelector("span").textContent = state;
}

function resetModules() {
  if (!moduleStack) return;
  moduleStack.querySelectorAll("div").forEach(function(el) {
    el.className = "";
    el.querySelector("span").textContent = "idle";
  });
}

function renderPassport(data) {
  passportDomain.textContent = data.domain;
  passportDecision.textContent = data.decision.label;
  scoreValue.textContent = data.scores.total;
  decisionStatus.textContent = data.decision.status;
  decisionStatus.className = "decision-status " + data.decision.statusClass;

  passportTags.innerHTML = data.tags.map(function(t) { return "<span>" + t + "</span>"; }).join("");

  passport.classList.remove("hidden");
  passport.scrollIntoView({ behavior: "smooth", block: "start" });

  requestAnimationFrame(function() {
    scoreRing.style.setProperty("--score-deg", (data.scores.total / 100 * 360) + "deg");
  });

  adminDetails.style.display = "";
  loginPrompt.style.display = "none";

  domainScore.textContent = data.scores.domain;
  emailScore.textContent = data.scores.email;
  exposureScore.textContent = data.scores.exposure;
  developerScore.textContent = data.scores.developer;
  decisionText.textContent = data.decision.text;

  policyList.innerHTML = data.decision.policies.map(function(p) { return "<div><span></span>" + p + "</div>"; }).join("");

  riskList.innerHTML = data.risks.map(function(r) {
    return '<article class="risk-item"><span class="risk-color" style="background:' + r.color + '"></span><div><div class="risk-title-row"><strong>' + r.title + '</strong><small>' + r.severity + '</small></div><span>' + r.body + '</span></div></article>';
  }).join("");

  timelineList.innerHTML = data.evidence.map(function(e) {
    return "<div><strong>" + e[0] + "</strong><span>" + e[1] + "</span></div>";
  }).join("");

  remediationList.innerHTML = data.remediation.map(function(r) {
    return '<article><strong>' + r[0] + '</strong><div><span>' + r[1] + '</span><small>' + r[2] + ' / ' + r[3] + '</small></div></article>';
  }).join("");
}

function saveScan(data) {
  localStorage.setItem("tm_lastScan", JSON.stringify(data));
}

window.renderPassportFromData = function(data) {
  renderPassport(data);
};

async function runScan(domain) {
  passport.classList.add("hidden");
  scoreRing.style.setProperty("--score-deg", "0deg");
  resetModules();

  var lines = ["target: " + domain, "mode: live scan", "connecting to TrustMesh backend..."];
  writeTerminal(lines);

  var moduleNames = ["Domain", "Email", "Exposure", "Developer", "Decision"];
  var currentModule = 0;

  var progressInterval = setInterval(function() {
    if (currentModule < moduleNames.length) {
      setModuleState(moduleNames[currentModule], "running");
    }
  }, 600);

  try {
    var headers = { "Content-Type": "application/json" };
    var token = getToken();
    if (token) headers["Authorization"] = "Bearer " + token;

    var resp = await fetch("/api/scan", {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ domain: domain })
    });

    clearInterval(progressInterval);

    if (!resp.ok) {
      var err = await resp.json();
      lines.push("error: " + (err.error || "scan failed"));
      writeTerminal(lines);
      return;
    }

    var data = await resp.json();

    if (data.lines) {
      data.lines.forEach(function(line) {
        lines.push(line);
        writeTerminal(lines);
      });
    }

    moduleNames.forEach(function(n) { setModuleState(n, "complete"); });

    lines.push("passport generated - score " + data.scores.total + "/100");
    if (token) {
      var user = getUser();
      if (user && user.role === "admin") {
        lines.push("access: admin - full details unlocked");
      } else {
        lines.push("access: authenticated - category scores only");
      }
    } else {
      lines.push("access: public - score + decision only");
      lines.push("tip: login as admin for full vulnerability details");
    }
    writeTerminal(lines);

    renderPassport(data);
    saveScan(data);
  } catch (err) {
    clearInterval(progressInterval);
    lines.push("error: connection failed - " + err.message);
    writeTerminal(lines);
  }
}

if (form) {
  form.addEventListener("submit", function(e) {
    e.preventDefault();
    var domain = sanitizeDomain(domainInput.value);
    if (!domain || !domain.includes(".")) {
      writeTerminal(["error: enter a valid organization domain, for example trustmesh.io"]);
      return;
    }
    runScan(domain);
  });
}

if (scanAnother) {
  scanAnother.addEventListener("click", function() {
    passport.classList.add("hidden");
    domainInput.value = "";
    domainInput.focus();
    scoreRing.style.setProperty("--score-deg", "0deg");
    resetModules();
    writeTerminal(["waiting for domain input..."]);
  });
}

document.addEventListener("keydown", function(e) {
  if (e.key === "Escape" && domainInput) domainInput.focus();
});

if (copyLink) {
  copyLink.addEventListener("click", async function() {
    var domain = sanitizeDomain(passportDomain.textContent);
    var link = window.location.origin + "/scanner.html?domain=" + domain;
    try {
      await navigator.clipboard.writeText(link);
      copyLink.textContent = "Copied!";
    } catch (e) {
      copyLink.textContent = "Link ready";
    }
    setTimeout(function() { copyLink.textContent = "Copy score link"; }, 1400);
  });
}

var urlParams = new URLSearchParams(window.location.search);
var prefillDomain = urlParams.get("domain");
if (prefillDomain && domainInput) {
  domainInput.value = prefillDomain;
  runScan(sanitizeDomain(prefillDomain));
}

(function() {
  var user = getUser();
  var navUser = document.getElementById("navUser");
  if (user && navUser) {
    navUser.textContent = user.name || user.email;
    if (user.role === "admin") navUser.textContent += " (admin)";
    navUser.style.cursor = "pointer";
    navUser.addEventListener("click", function() {
      localStorage.removeItem("tm_token");
      localStorage.removeItem("tm_user");
      window.location.reload();
    });
  }
})();
