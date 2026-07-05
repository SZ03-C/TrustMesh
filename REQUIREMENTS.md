# TrustMesh Requirements

## Product Positioning

TrustMesh is a cybersecurity trust passport for organizations. It helps a company decide whether another organization is safe enough to collaborate with, share data with, connect APIs to, or onboard as a vendor.

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

## First Technical Direction

Start with a static prototype:

- `index.html`
- `styles.css`
- `app.js`

Then evolve into:

- Next.js frontend
- FastAPI or Node.js backend
- PostgreSQL database
- background scan workers
- queue system
- PDF report generation
