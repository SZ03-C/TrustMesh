# TrustMesh — Cyber Trust Passport

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-prototype-yellow)

**TrustMesh** is a cybersecurity trust passport for organizations. It helps you decide whether another organization is safe enough to collaborate with, share data with, connect APIs to, or onboard as a vendor.

> Unlike traditional scanners that produce technical findings, TrustMesh turns security signals into a **living trust decision** that business and security teams can understand.

## Features

- **Domain Trust** — SSL/TLS status, HTTPS availability, security headers, DNS posture
- **Email Trust** — SPF, DKIM, DMARC validation with spoofing risk assessment
- **Public Exposure** — Exposed services, risky ports, subdomain discovery
- **Developer Trust** — GitHub hygiene, SECURITY.md, branch protection, exposed configs
- **Trust Passport** — 0–100 score, category breakdown, collaboration decision, top risks, evidence timeline
- **Shareable** — One-click passport link copying

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla HTML, CSS, JavaScript |
| Database (future) | PostgreSQL |
| Backend (future) | Node.js / FastAPI |
| Scanners (future) | DNS, TLS, security headers, GitHub API |

## Getting Started

No dependencies required. Open `index.html` in a browser:

```bash
open index.html
# or
start index.html
```

Enter any domain (e.g., `example.com`) to see a simulated trust passport.

## Project Structure

```
trustmesh/
├── index.html          # Main application page
├── styles.css          # Dark cyber-themed styling
├── app.js              # Application logic & simulated scanners
├── schema.sql          # PostgreSQL database schema
├── REQUIREMENTS.md     # Full product requirements
└── README.md           # This file
```

## Roadmap

- [x] Static prototype with simulated scan results
- [ ] Real DNS / TLS / headers scanners
- [ ] GitHub API integration
- [ ] Node.js / FastAPI backend
- [ ] PostgreSQL database
- [ ] User authentication & org profiles
- [ ] Background scan workers
- [ ] PDF report generation
- [ ] Org-to-org trust requests

## Ethical Boundaries

TrustMesh only performs **safe, passive checks**:
- DNS queries
- HTTPS checks
- Security headers inspection
- Certificate inspection
- GitHub public metadata
- Approved third-party intelligence APIs

No intrusive scanning without explicit authorization.

## License

[MIT](LICENSE)
