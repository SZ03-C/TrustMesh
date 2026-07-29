const fetch = require("node-fetch");

async function scanDomain(domain) {
  const evidence = { https: false, hsts: false, csp: false, xfo: false, xct: false, referrer: false, permissions: false, cors: false };
  const lines = [];
  let score = 50;

  try {
    const resp = await fetch(`https://${domain}`, { method: "HEAD", timeout: 8000, redirect: "follow" });
    evidence.https = true;
    score += 15;
    lines.push(`ok: ${domain} reachable via HTTPS (status ${resp.status})`);

    const headers = [
      { name: "strict-transport-security", key: "hsts", boost: 8 },
      { name: "content-security-policy", key: "csp", boost: 7 },
      { name: "x-frame-options", key: "xfo", boost: 5 },
      { name: "x-content-type-options", key: "xct", boost: 4 },
      { name: "referrer-policy", key: "referrer", boost: 3 },
      { name: "permissions-policy", key: "permissions", boost: 3 },
      { name: "access-control-allow-origin", key: "cors", boost: 2 }
    ];

    for (const h of headers) {
      const val = resp.headers.get(h.name);
      if (val) {
        evidence[h.key] = true;
        score += h.boost;
        lines.push(`ok: ${h.name} present`);
      } else {
        lines.push(`warn: ${h.name} missing`);
      }
    }
  } catch (err) {
    lines.push(`warn: HTTPS check failed — ${err.message}`);

    try {
      await fetch(`http://${domain}`, { method: "HEAD", timeout: 8000 });
      lines.push(`warn: ${domain} reachable via HTTP only`);
      score -= 10;
    } catch {
      lines.push(`warn: ${domain} may not be reachable`);
    }
  }

  const parts = domain.split(".");
  if (parts.length > 2) {
    lines.push(`info: subdomain detected: ${parts[0]}`);
    score += 3;
  }

  try {
    const dohResp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
      headers: { "Accept": "application/dns-json" },
      timeout: 5000
    });
    const dohData = await dohResp.json();
    if (dohData.Answer && dohData.Answer.length > 0) {
      const ips = dohData.Answer.filter(a => a.type === 1).map(a => a.data);
      lines.push(`ok: DNS resolves to ${ips.join(", ")}`);
      score += 5;
    } else {
      lines.push("warn: no DNS A records found");
    }
  } catch {
    lines.push("info: DNS-over-HTTPS check skipped");
  }

  return { score: Math.min(Math.max(score, 20), 100), evidence, lines };
}

async function scanHTTPS(domain) {
  const lines = [];
  let score = 60;

  try {
    const start = Date.now();
    const resp = await fetch(`https://${domain}`, { method: "HEAD", timeout: 8000 });
    const latency = Date.now() - start;
    lines.push(`ok: response time ${latency}ms`);
    if (latency < 1000) score += 10;
    else if (latency < 3000) score += 5;
  } catch (err) {
    lines.push(`warn: HTTPS latency check failed — ${err.message}`);
  }

  return { score: Math.min(score, 100), lines };
}

async function scanHeaders(domain) {
  try {
    const resp = await fetch(`https://${domain}`, { method: "HEAD", timeout: 8000 });
    const headers = {};
    resp.headers.forEach((value, name) => { headers[name.toLowerCase()] = value; });
    return { headers, score: Object.keys(headers).length > 5 ? 80 : 60 };
  } catch {
    return { headers: {}, score: 40 };
  }
}

module.exports = { scanDomain, scanHTTPS, scanHeaders };
