CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  domain TEXT NOT NULL UNIQUE,
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  overall_score INT,
  decision TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scan_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_run_id UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence_json JSONB,
  remediation TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS score_breakdowns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_run_id UUID NOT NULL UNIQUE REFERENCES scan_runs(id) ON DELETE CASCADE,
  domain_score INT,
  email_score INT,
  exposure_score INT,
  developer_score INT,
  ai_saas_score INT,
  data_sharing_score INT
);

CREATE TABLE IF NOT EXISTS trust_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending',
  access_level TEXT NOT NULL DEFAULT 'summary',
  purpose TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_organizations_domain ON organizations(domain);
CREATE INDEX IF NOT EXISTS idx_scan_runs_organization_id ON scan_runs(organization_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_run_id ON scan_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_trust_requests_requester_org_id ON trust_requests(requester_org_id);
CREATE INDEX IF NOT EXISTS idx_trust_requests_target_org_id ON trust_requests(target_org_id);
