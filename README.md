# TrustMesh — Cyber Trust Passport

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-prototype-yellow)]()

**TrustMesh** evaluates an organization's security posture and produces a **Trust Passport** — a 0–100 score with category breakdowns, risk analysis, and a collaboration decision. Enter any domain and get a data-driven answer: *is this organization safe to work with?*

Unlike traditional vulnerability scanners that produce technical findings, TrustMesh turns security signals into a **living trust decision** that business and security teams can understand.

---

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
