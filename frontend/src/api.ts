// Typed mirrors of backend/app/api/health.py. Phase 6 replaces hand-written
// types with a schema shared between backend and frontend.

export type CheckStatus = "ok" | "degraded" | "error" | "not_configured";

export interface CheckResult {
  status: CheckStatus;
  detail: string | null;
  latency_ms: number | null;
}

export interface Liveness {
  status: "ok";
  version: string;
  env: string;
  dry_run: boolean;
  offline_mode: boolean;
}

export interface Readiness {
  status: "ready" | "not_ready";
  checks: Record<string, CheckResult>;
}

async function getJson<T>(path: string, accept503 = false): Promise<T> {
  const resp = await fetch(path, { headers: { Accept: "application/json" } });
  if (!resp.ok && !(accept503 && resp.status === 503)) {
    throw new Error(`${path}: HTTP ${resp.status}`);
  }
  return (await resp.json()) as T;
}

export const fetchLiveness = (): Promise<Liveness> => getJson<Liveness>("/api/health");
export const fetchReadiness = (): Promise<Readiness> =>
  getJson<Readiness>("/api/health/ready", true);
