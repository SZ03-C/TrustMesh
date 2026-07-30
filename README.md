# TrustMesh — Cyber Trust Passport

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-prototype-yellow)]()

**TrustMesh** evaluates an organization's security posture and produces a **Trust Passport** — a 0–100 score with category breakdowns, risk analysis, and a collaboration decision. Enter any domain and get a data-driven answer: *is this organization safe to work with?* It helps a company decide whether another organization is safe enough to collaborate with, share data with, connect APIs to, or onboard as a vendor.

Unlike traditional vulnerability scanners that produce technical findings, TrustMesh turns security signals into a **living trust decision** that business and security teams can understand.

The product is not just a scanner. Scanners produce technical findings. TrustMesh turns those findings into a living trust decision that business and security teams can understand.


## MVP Goal

Build a fast, engaging web experience where a user enters an organization domain and receives a Cyber Trust Passport with:

- a trust score
- key security signals
- top risks
- plain-English impact
- remediation steps
- a collaboration decision
- a shareable passport view

## Target Users

- startup founders checking vendors
- security teams reviewing partners
- procurement teams onboarding suppliers
- agencies handling client accounts
- SaaS teams proving basic security hygiene to customers
- students and project evaluators who need a meaningful cybersecurity product

## Version 1 Scope

### Domain Trust

- domain identity summary
- SSL/TLS certificate status
- HTTPS availability
- security headers
- DNS posture summary

### Email Trust

- SPF status
- DKIM status
- DMARC status
- spoofing risk level
- recommended DMARC policy improvement

### Public Exposure

- exposed service summary
- risky port category warnings
- subdomain exposure summary
- admin panel exposure warning

### Developer Trust

- GitHub organization or public repository hygiene
- public repo count
- missing `SECURITY.md`
- missing branch protection signal
- exposed config file warning
- risky GitHub Actions permissions warning

### Trust Passport

- total score from 0 to 100
- category scores
- collaboration decision:
  - Safe to collaborate
  - Collaborate with restrictions
  - Do not share sensitive data yet
- top 5 risks
- evidence timeline
- export-ready layout

## Prototype Rules

The first prototype uses simulated scan results. It should clearly communicate the product experience before connecting real scanning APIs.

The first code version must:

- run without installing dependencies
- feel fast and interactive
- use a premium hacker-inspired visual style
- avoid scary fake claims about real domains
- label demo scan output as simulated
- be structured so real scan modules can replace simulated data later

## Future Backend Requirements

### Scanner Services

- DNS scanner
- email security scanner
- TLS scanner
- security headers scanner
- subdomain discovery
- safe external exposure scanner
- GitHub API scanner
- report generator

### Platform Services

- user authentication
- organization profiles
- passport access controls
- org-to-org trust requests
- scan history
- background jobs
- notifications
- audit log

### Performance Requirements

- first screen should load quickly
- scans should run asynchronously
- partial results should appear as soon as available
- previous scan results should be cached
- heavy report sections should lazy-load
- scanner workers should be separate from the web request path

## Ethical and Legal Boundaries

TrustMesh must only perform safe and authorized checks. It should avoid intrusive scanning unless the organization owns the domain or grants permission.

Default checks should be passive or low-risk:

- DNS queries
- HTTPS checks
- security headers
- certificate inspection
- GitHub public metadata
- approved third-party intelligence APIs


## Features

- **Domain Trust Scan** — SSL/TLS status, HTTPS availability, security headers (HSTS, CSP, XFO, etc.), DNS-over-HTTPS resolution
- **Email Trust Assessment** — SPF/DKIM/DMARC posture with spoofing risk evaluation
- **Public Exposure Estimate** — Passive exposure signals and risk indicators
- **Developer Trust Scan** — GitHub organization lookup, repo analysis, SECURITY.md detection
- **Trust Passport** — 0–100 weighted score, category breakdown, collaboration decision, top risks, remediation steps, evidence timeline
- **User Authentication** — Signup/login with JWT, role-based access (user / admin)
- **Trust Requests** — Submit org-to-org trust requests with access levels
- **Admin Dashboard** — Manage scans, users, trust requests, and feedback
- **Scan History** — Saved scan results per user with full passport drill-down
- **Live Stats** — Public dashboard with platform-wide metrics
- **Feedback System** — Submit feedback via AI-powered chat interface
- **Copy & Share** — One-click passport link copying

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla HTML, CSS, JavaScript |
| Backend | Node.js, Express |
| Database | SQLite (via sql.js / better-sqlite3) |
| Auth | bcryptjs + JSON Web Tokens |
| DNS | DNS-over-HTTPS (Cloudflare) |
| GitHub | GitHub REST API v3 |
| Headers | Live HTTP security headers inspection |

## Project Structure

```
trustmesh/
├── server.js              # Express backend — API routes, scan orchestration
├── app.js                 # Frontend application logic & UI controllers
├── db.js                  # SQLite database layer (init, query, persist)
├── auth.js                # Authentication middleware & route handlers
├── scanner-domain.js      # Domain scanner — HTTPS, headers, DNS
├── scanner-github.js      # GitHub scanner — org/repo analysis
├── index.html             # Main landing page with live stats
├── passport.html          # Trust passport result view
├── scanner.html           # Domain scan input & results
├── requests.html          # Trust request submission & listing
├── admin.html             # Admin login page
├── admin-dashboard.html   # Admin panel — users, scans, requests, feedback
├── register.html          # User registration page
├── contact.html           # AI chat / feedback interface
├── styles.css             # Dark cyber-themed stylesheet
├── schema.sql             # PostgreSQL schema (reference)
├── .env                   # Environment variables (PORT, JWT_SECRET, GITHUB_TOKEN)
├── package.json           # Node.js dependencies
└── trustmesh.db           # SQLite database (auto-created)
```

## Getting Started

### Prerequisites

- Node.js 18+

### Install & Run

```bash
git clone https://github.com/SZ03-C/TrustMesh.git
cd TrustMesh
npm install
cp .env.example .env     # configure your secrets
npm start
```

Open `http://localhost:3000` in your browser. Enter any domain (e.g., `example.com`) to see a live trust passport.

### Configuration

Create a `.env` file:

```
PORT=3000
JWT_SECRET=your-secret-key-change-this
GITHUB_TOKEN=your-github-token-optional
```

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/signup` | — | Register a new user |
| POST | `/api/auth/login` | — | Login, returns JWT |
| GET | `/api/auth/me` | JWT | Get current user profile |
| POST | `/api/scan` | optional | Run trust scan on a domain |
| GET | `/api/scans` | JWT | Get user's scan history |
| POST | `/api/requests` | — | Submit a trust request |
| GET | `/api/requests` | — | List public trust requests |
| GET | `/api/stats` | — | Platform-wide statistics |
| POST | `/api/feedback` | — | Submit feedback |
| GET | `/api/admin/scans` | Admin | List all scans |
| GET | `/api/admin/scan/:id` | Admin | Get full scan details |
| GET | `/api/admin/users` | Admin | List all users |
| GET | `/api/admin/requests` | Admin | List all trust requests |
| PUT | `/api/admin/requests/:id` | Admin | Approve/deny request |
| GET | `/api/admin/feedback` | Admin | List all feedback |

## Scoring System

The overall trust score (0–100) is a weighted average:

| Category | Weight | What it measures |
|---|---|---|
| Domain Trust | 30% | HTTPS, security headers, DNS |
| Email Trust | 20% | SPF/DKIM/DMARC posture |
| Exposure | 25% | Passive exposure signals |
| Developer Trust | 25% | GitHub hygiene, SECURITY.md |

### Decision Thresholds

| Score | Verdict |
|---|---|
| 82–100 | Safe to collaborate |
| 68–81 | Collaborate with restrictions |
| 0–67 | Do not share sensitive data |

## Roadmap

- [x] Static prototype with simulated scan results
- [x] Real DNS / TLS / headers scanners
- [x] GitHub API integration
- [x] Node.js backend with SQLite
- [x] User authentication & org profiles
- [x] Admin dashboard
- [x] Trust request workflow
- [ ] PostgreSQL migration
- [ ] Background scan workers
- [ ] PDF report generation
- [ ] Org-to-org trust networks
- [ ] Continuous monitoring & webhooks

## Ethical Boundaries

TrustMesh only performs **safe, passive checks**:
- DNS queries via DNS-over-HTTPS
- HTTPS availability & security headers inspection
- GitHub public metadata
- No intrusive scanning without explicit authorization

## License

[MIT](LICENSE)
