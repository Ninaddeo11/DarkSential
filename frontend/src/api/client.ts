import type {
  AuditEntry,
  AuditVerify,
  CveMatch,
  Detection,
  Device,
  FeedsStatus,
  Liveness,
  Me,
  Quarantine,
  RiskDecision,
  RiskLevel,
  RelatedThreat,
  RiskDetail,
  Rule,
  Session,
} from "./types";
import type { DsnEvent } from "../generated/events";
import { scenarioFor } from "../sim/generate";
import { SIM_IOC, simulatedCounts } from "../sim/scenario";

// Hosted (Vercel) deployments have no lab: the device, risk, response and intel
// endpoints answer 503 there. Those reads resolve to empty data without a
// request, and the intel graph is the simulated scenario.
let hosted = false;
let modeKnown!: () => void;
// Settles once the deployment mode is known, so first-render reads don't race it.
const modeReady = new Promise<void>((resolve) => (modeKnown = resolve));

export function setHostedMode(on: boolean): void {
  hosted = on;
  modeKnown();
}

export function isHostedMode(): boolean {
  return hosted;
}

async function lab<T>(call: () => Promise<T>, fallback: T): Promise<T> {
  await modeReady;
  return hosted ? fallback : call();
}

// Session token: sessionStorage (dies with the tab) wrapped so a blocked storage
// (private mode, sandboxed iframe) degrades to in-memory instead of crashing.
let memoryToken: string | null = null;

export function getToken(): string | null {
  try {
    return sessionStorage.getItem("dsn.token") ?? memoryToken;
  } catch {
    return memoryToken;
  }
}

export function setToken(token: string | null): void {
  memoryToken = token;
  try {
    if (token) sessionStorage.setItem("dsn.token", token);
    else sessionStorage.removeItem("dsn.token");
  } catch {
    /* storage unavailable: memory only */
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}, accept503 = false): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = { Accept: "application/json" };
  if (init.body) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  const resp = await fetch(path, { ...init, headers: { ...headers, ...(init.headers ?? {}) } });
  if (!resp.ok && !(accept503 && resp.status === 503)) {
    let detail = `HTTP ${resp.status}`;
    try {
      const body = (await resp.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(resp.status, detail);
  }
  return (await resp.json()) as T;
}

export const api = {
  health: () => request<Liveness>("/api/health"),
  me: () => request<Me>("/api/auth/me"),
  login: (secret: string) =>
    request<Session>("/api/auth/login", { method: "POST", body: JSON.stringify({ secret }) }),
  devices: () => lab(() => request<Device[]>("/api/devices"), []),
  risks: () => lab(() => request<RiskDecision[]>("/api/risk"), []),
  risk: (nodeId: string) => request<RiskDetail>(`/api/risk/${encodeURIComponent(nodeId)}`),
  quarantines: () => lab(() => request<Quarantine[]>("/api/quarantines?limit=200"), []),
  events: (limit = 500) => request<DsnEvent[]>(`/api/events?limit=${limit}`),
  feeds: () => request<FeedsStatus>("/api/feeds/status", {}, true),
  quarantine: (nodeId: string, reason: string, minutes: number) =>
    request<Quarantine>("/api/quarantines", {
      method: "POST",
      body: JSON.stringify({ node_id: nodeId, reason, minutes }),
    }),
  release: (id: number, reason: string) =>
    request<Quarantine>(`/api/quarantines/${id}/release`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  approve: (nodeId: string) =>
    request<Device>(`/api/devices/${encodeURIComponent(nodeId)}/approve`, { method: "POST" }),
  quarantinesByStatus: (status?: "active" | "released" | "failed") =>
    lab(() => request<Quarantine[]>(`/api/quarantines?limit=200${status ? `&status=${status}` : ""}`), []),
  detections: (nodeId?: string, limit = 100) =>
    lab(
      () =>
        request<Detection[]>(
          `/api/detections?limit=${limit}${nodeId ? `&node_id=${encodeURIComponent(nodeId)}` : ""}`,
        ),
      [],
    ),
  rules: () => lab(() => request<Rule[]>("/api/rules"), []),
  relatedThreats: async (ioc: string) => {
    // Lab: only the hand-built indicator is simulated; hosted: any IPv4 address.
    if (ioc.trim() !== SIM_IOC) await modeReady;
    const simulated = scenarioFor(ioc, hosted);
    if (simulated) return simulated.threats;
    return lab(() => request<RelatedThreat[]>(`/api/intel/related-threats?ioc=${encodeURIComponent(ioc)}`), []);
  },
  cves: (cpe: string) => lab(() => request<CveMatch[]>(`/api/intel/cves?cpe=${encodeURIComponent(cpe)}`), []),
  graphCounts: async () => {
    await modeReady;
    return hosted ? simulatedCounts() : request<Record<string, number>>("/api/intel/graph/counts");
  },
  riskModel: () =>
    request<{ linear: { thresholds: Partial<Record<RiskLevel, number>> } }>("/api/risk/model"),
  audit: (limit = 100) => lab(() => request<AuditEntry[]>(`/api/audit?limit=${limit}`), []),
  auditVerify: () => request<AuditVerify>("/api/audit/verify"),
};
