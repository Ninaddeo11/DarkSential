// REST response shapes (backend/app/api/*). The live event payloads are
// generated from the backend schema: see ../generated/events.ts.
import type { CpeGuess, Contribution } from "../generated/events";

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type Role = "viewer" | "operator";

export interface Service {
  port: number;
  proto?: string;
  port_proto: string;
  name?: string | null;
  product?: string | null;
  version?: string | null;
}

export interface Device {
  node_id: string;
  trust: "unknown" | "known" | "approved";
  vendor: string | null;
  oui: string | null;
  randomized_mac: boolean;
  ip: string | null;
  hostname: string | null;
  services: Service[];
  cpes: CpeGuess[];
  sources: string[];
  attributes: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
}

export interface PathStep {
  node_id: string;
  label: string;
  name: string | null;
  via: string | null;
}

export interface Evidence {
  kind: string;
  summary: string;
  value: number;
  detail?: Record<string, unknown> | null;
  path?: PathStep[] | null;
}

export interface Factor {
  name: string;
  value: number;
  summary: string;
  evidence: Evidence[];
}

export interface MlExplanation {
  model: string;
  probability: number;
  base_value: number;
  shap: Record<string, number>;
  features: Record<string, number>;
}

export interface RiskDecision {
  id: number;
  node_id: string;
  ts: string;
  score: number;
  level: RiskLevel;
  action: string;
  contributions: Contribution[];
  factors: Factor[];
  explanation: string;
  evidence_paths: PathStep[][];
  ml: MlExplanation | null;
  trigger: string;
}

export interface RiskDetail {
  node_id: string;
  latest: RiskDecision | null;
  history: RiskDecision[];
}

export interface Quarantine {
  id: number;
  node_id: string;
  ip: string;
  status: "active" | "released" | "failed";
  reason: string;
  actor: string;
  driver: string;
  dry_run: boolean;
  started_at: string;
  expires_at: string;
  released_at: string | null;
  released_by: string | null;
}

export interface FeedStatus {
  name: string;
  enabled: boolean;
  mode: string;
  interval_minutes: number;
  running: boolean;
  next_run_at: string | null;
  last_run: {
    status: string;
    started_at: string;
    finished_at: string | null;
    objects: number;
    rejected: number;
    error: string | null;
  } | null;
  last_success_at: string | null;
  requires?: string | null;
}

export interface FeedsStatus {
  scheduler: string;
  graph_backend?: string;
  feeds: FeedStatus[];
}

export interface Liveness {
  status: "ok";
  version: string;
  env: string;
  deployment: "lab" | "hosted";
  dry_run: boolean;
  offline_mode: boolean;
}

export interface Me {
  sub: string;
  role: Role;
  source: string;
  reads_require_auth: boolean;
  login_enabled: boolean;
  oidc_issuer: string | null;
}

export interface Session {
  access_token: string;
  role: Role;
  expires_at: string;
}

export interface RelatedThreat {
  threat_id: string;
  label: string;
  name: string | null;
  external_id: string | null;
  hops: number;
  confidence: number | null;
  sources: string[];
  indicator_id: string | null;
  indicator_stale: boolean;
  path: PathStep[];
}

export interface CveMatch {
  cve: string;
  vulnerability_id: string;
  cvss_score: number | null;
  cvss_severity: string | null;
  kev: boolean;
  kev_ransomware: boolean;
  kev_due_date: string | null;
  criteria: string;
  match: string;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string;
  action: string;
  node_id: string | null;
  outcome: string;
  details: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface AuditVerify {
  ok: boolean;
  entries: number;
  head: string;
  first_bad_id: number | null;
}

export interface Detection {
  id: number;
  node_id: string;
  ts: string;
  kind: "anomaly" | "rule";
  rule_id: string | null;
  severity: string;
  score: number;
  techniques: string[];
  summary: string;
}

export interface Rule {
  id: string;
  title: string;
  severity: string;
  techniques: string[];
  rationale: string;
  source: string;
}
