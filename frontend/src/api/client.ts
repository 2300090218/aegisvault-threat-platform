import type {
  Alert,
  AlertDetail,
  AlertStatus,
  AttackScenario,
  AuditLogEntry,
  AuditVerifyResult,
  DashboardAnalytics,
  FederatedStatus,
  PrivacySettings,
  PsiCheckResponse,
  ReidentificationRequest,
  ReidentificationReveal,
  SecurityEvent,
  TokenResponse,
  User,
} from "../types";

const API_BASE = (import.meta.env.VITE_API_URL as string | undefined) || "/api/v1";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  token?: string | null
): Promise<T> {
  const headers = new Headers(options.headers);
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const resp = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const data = await resp.json();
      detail = data.detail || JSON.stringify(data);
    } catch {
      // ignore non-json error body
    }
    throw new ApiError(resp.status, detail);
  }
  return (await resp.json()) as T;
}

export const apiClient = {
  login: (username: string, password: string) =>
    request<TokenResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  me: (token: string) => request<User>("/auth/me", {}, token),

  getDashboardAnalytics: (token: string) =>
    request<DashboardAnalytics>("/analytics/dashboard", {}, token),

  listAlerts: (token: string, params?: { status?: string; severity?: string }) => {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.severity) qs.set("severity", params.severity);
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return request<Alert[]>(`/alerts${suffix}`, {}, token);
  },

  getAlertDetail: (token: string, alertId: string) =>
    request<AlertDetail>(`/alerts/${alertId}`, {}, token),

  updateAlertStatus: (token: string, alertId: string, status: AlertStatus) =>
    request<Alert>(
      `/alerts/${alertId}/status`,
      { method: "PATCH", body: JSON.stringify({ status }) },
      token
    ),

  listEvents: (token: string, limit = 30) =>
    request<SecurityEvent[]>(`/events?limit=${limit}`, {}, token),

  simulateAttack: (token: string, scenario: AttackScenario, count = 8, region = "us-east") =>
    request<{ scenario: AttackScenario; events_enqueued: number; stream_ids: string[] }>(
      "/events/simulate",
      { method: "POST", body: JSON.stringify({ scenario, count, region }) },
      token
    ),

  getPrivacySettings: (token: string) =>
    request<PrivacySettings>("/privacy/settings", {}, token),

  updateEpsilon: (token: string, dp_epsilon: number) =>
    request<PrivacySettings>(
      "/privacy/settings/epsilon",
      { method: "PATCH", body: JSON.stringify({ dp_epsilon }) },
      token
    ),

  rotateHmacKey: (token: string) =>
    request<{ previous_key_id: string | null; new_key_id: string; rotated_at: string }>(
      "/privacy/keys/rotate",
      { method: "POST" },
      token
    ),

  requestReidentification: (
    token: string,
    payload: { alert_id: string; tokens: string[]; justification: string }
  ) =>
    request<ReidentificationRequest>(
      "/privacy/reidentify/request",
      { method: "POST", body: JSON.stringify(payload) },
      token
    ),

  listReidentificationRequests: (token: string, status?: string) =>
    request<ReidentificationRequest[]>(
      `/privacy/reidentify/requests${status ? `?status=${status}` : ""}`,
      {},
      token
    ),

  decideReidentificationRequest: (
    token: string,
    reqId: string,
    decision: "approved" | "rejected",
    decision_note: string
  ) =>
    request<ReidentificationRequest>(
      `/privacy/reidentify/requests/${reqId}/decide`,
      { method: "POST", body: JSON.stringify({ decision, decision_note }) },
      token
    ),

  revealReidentifiedEntities: (token: string, reqId: string) =>
    request<ReidentificationReveal>(
      `/privacy/reidentify/requests/${reqId}/reveal`,
      { method: "POST" },
      token
    ),

  getAuditLogs: (token: string, limit = 100) =>
    request<AuditLogEntry[]>(`/privacy/audit-log?limit=${limit}`, {}, token),

  verifyAuditChain: (token: string) =>
    request<AuditVerifyResult>("/privacy/audit-log/verify", {}, token),

  runRetention: (token: string, retention_days?: number) =>
    request<{
      cutoff_timestamp: string;
      events_aggregated: number;
      events_deleted: number;
      vault_entries_deleted: number;
    }>(
      "/privacy/retention/run",
      { method: "POST", body: JSON.stringify({ retention_days }) },
      token
    ),

  checkPsi: (token: string, blinded_points: string[]) =>
    request<PsiCheckResponse>(
      "/privacy/psi/check",
      { method: "POST", body: JSON.stringify({ blinded_points }) },
      token
    ),

  getPsiDemoHints: (token: string) =>
    request<{ sample_candidates: { label: string; sha256: string }[] }>(
      "/privacy/psi/demo-hints",
      {},
      token
    ),

  getFederatedStatus: (token: string) =>
    request<FederatedStatus>("/federated/status", {}, token),

  trainFederatedRounds: (token: string, rounds = 1, local_epochs = 3) =>
    request<FederatedStatus>(
      "/federated/train-round",
      { method: "POST", body: JSON.stringify({ rounds, local_epochs }) },
      token
    ),

  resetFederated: (token: string) =>
    request<FederatedStatus>("/federated/reset", { method: "POST" }, token),
};

export function buildAlertsWsUrl(token: string): string {
  const configured = import.meta.env.VITE_WS_URL as string | undefined;
  if (configured) {
    return `${configured.replace(/\/$/, "")}/ws/alerts?token=${encodeURIComponent(token)}`;
  }
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws/alerts?token=${encodeURIComponent(token)}`;
}
