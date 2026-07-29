const fetch = require("node-fetch");

async function scanGitHub(domain) {
  const lines = [];
  let score = 50;
  const data = { repoCount: 0, hasSecurityMd: false, hasReadme: false, orgName: null, repos: [], languages: [] };

  let githubOrg = null;
  const knownOrgs = {
    "google.com": "google", "microsoft.com": "microsoft", "github.com": "github",
    "facebook.com": "facebook", "apple.com": "apple", "amazon.com": "aws",
    "netflix.com": "Netflix", "twitter.com": "twitter", "openai.com": "openai"
  };

  for (const [key, org] of Object.entries(knownOrgs)) {
    if (domain.includes(key.replace(".com", ""))) {
      githubOrg = org;
      break;
    }
  }

  if (!githubOrg) {
    const parts = domain.split(".");
    if (parts.length >= 2) {
      githubOrg = parts[parts.length - 2];
    }
  }

  if (!githubOrg) {
    lines.push("info: could not determine GitHub organization from domain");
    return { score: 50, lines, data };
  }

  const headers = { "Accept": "application/vnd.github.v3+json" };
  if (process.env.GITHUB_TOKEN) {
    headers["Authorization"] = `token ${process.env.GITHUB_TOKEN}`;
  }

  try {
    const orgResp = await fetch(`https://api.github.com/orgs/${githubOrg}`, { headers, timeout: 8000 });
    if (orgResp.ok) {
      const org = await orgResp.json();
      data.orgName = org.login;
      lines.push(`ok: GitHub org found — ${org.login} (${org.public_repos} public repos)`);
      score += 10;
    } else {
      lines.push(`warn: GitHub org "${githubOrg}" not found (status ${orgResp.status})`);
    }
  } catch (err) {
    lines.push(`warn: GitHub API error — ${err.message}`);
  }

  if (data.orgName) {
    try {
      const reposResp = await fetch(`https://api.github.com/orgs/${githubOrg}/repos?per_page=10&sort=updated`, { headers, timeout: 8000 });
      if (reposResp.ok) {
        const repos = await reposResp.json();
        data.repoCount = repos.length;
        data.repos = repos.map(r => ({ name: r.name, language: r.language, stars: r.stargazers_count, updated: r.updated_at }));
        data.languages = [...new Set(repos.map(r => r.language).filter(Boolean))];
        lines.push(`ok: ${repos.length} recent repos analyzed`);

        const hasSecMd = repos.some(r => r.name.toLowerCase().includes("security"));
        data.hasSecurityMd = hasSecMd;
        if (hasSecMd) {
          score += 8;
          lines.push("ok: security-related repo found");
        } else {
          lines.push("warn: no SECURITY.md or security repo detected");
        }

        const hasReadme = repos.some(r => r.name.toLowerCase().includes("readme") || r.description);
        data.hasReadme = hasReadme;
        if (hasReadme) score += 3;
      }
    } catch (err) {
      lines.push(`warn: repo fetch failed — ${err.message}`);
    }

    try {
      const secResp = await fetch(`https://api.github.com/repos/${githubOrg}/.github/contents/SECURITY.md`, { headers, timeout: 5000 });
      if (secResp.ok) {
        data.hasSecurityMd = true;
        score += 5;
        lines.push("ok: SECURITY.md found in .github repo");
      }
    } catch {}
  }

  return { score: Math.min(score, 100), lines, data };
}

module.exports = { scanGitHub };
