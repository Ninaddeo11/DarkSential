import type {
  Device,
  FeedsStatus,
  Liveness,
  Me,
  Quarantine,
  RiskDecision,
  RiskDetail,
  Session,
} from "./types";
import type { DsnEvent } from "../generated/events";

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
  devices: () => request<Device[]>("/api/devices"),
  risks: () => request<RiskDecision[]>("/api/risk"),
  risk: (nodeId: string) => request<RiskDetail>(`/api/risk/${encodeURIComponent(nodeId)}`),
  quarantines: () => request<Quarantine[]>("/api/quarantines?limit=200"),
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
};
