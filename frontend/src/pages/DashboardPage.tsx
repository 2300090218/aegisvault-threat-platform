import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  EyeOff,
  Radio,
  ShieldAlert,
  Sparkles,
  Zap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { apiClient, buildAlertsWsUrl } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { Alert, AttackScenario, DashboardAnalytics } from "../types";

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-rose-500/20 text-rose-300 border-rose-500/50",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/50",
  medium: "bg-amber-500/20 text-amber-300 border-amber-500/50",
  low: "bg-sky-500/20 text-sky-300 border-sky-500/50",
};

const STATUS_BADGE: Record<string, string> = {
  new: "bg-rose-950 text-rose-300 border-rose-700/60",
  investigating: "bg-amber-950 text-amber-300 border-amber-700/60",
  resolved: "bg-emerald-950 text-emerald-300 border-emerald-700/60",
};

const SCENARIOS: { id: AttackScenario; label: string }[] = [
  { id: "brute_force", label: "Brute Force (T1110)" },
  { id: "impossible_travel", label: "Impossible Travel (T1078)" },
  { id: "data_exfiltration", label: "Data Exfiltration (T1041)" },
  { id: "port_scan", label: "Port Scan (T1046)" },
  { id: "malicious_hash", label: "Malicious Hash (T1204)" },
];

export function DashboardPage() {
  const { token, hasRole } = useAuth();
  const [analytics, setAnalytics] = useState<DashboardAnalytics | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState<AttackScenario>("brute_force");
  const [simulating, setSimulating] = useState(false);
  const [simNotice, setSimNotice] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const wsRef = useRef<WebSocket | null>(null);

  const loadSnapshot = useCallback(async () => {
    if (!token) return;
    const [dashData, alertList] = await Promise.all([
      apiClient.getDashboardAnalytics(token),
      apiClient.listAlerts(token, statusFilter ? { status: statusFilter } : undefined),
    ]);
    setAnalytics(dashData);
    setAlerts(alertList);
  }, [token, statusFilter]);

  useEffect(() => {
    void loadSnapshot();
  }, [loadSnapshot]);

  useEffect(() => {
    if (!token) return;
    let active = true;
    const ws = new WebSocket(buildAlertsWsUrl(token));
    wsRef.current = ws;

    ws.onopen = () => {
      if (active) setWsConnected(true);
    };
    ws.onclose = () => {
      if (active) setWsConnected(false);
    };
    ws.onerror = () => {
      if (active) setWsConnected(false);
    };

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data) as { type: string; data: unknown };
        if (msg.type === "alert") {
          const incoming = msg.data as Alert;
          setAlerts((prev) => {
            if (prev.some((a) => a.id === incoming.id)) return prev;
            return [incoming, ...prev].slice(0, 50);
          });
          void apiClient.getDashboardAnalytics(token).then(setAnalytics).catch(() => {});
        } else if (msg.type === "metrics") {
          const tick = msg.data as { timestamp: string; events_processed: number; alerts_triggered: number };
          const label = new Date(tick.timestamp).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          });
          setAnalytics((prev) => {
            if (!prev) return prev;
            const nextSeries = [
              ...prev.event_rate_series.slice(-11),
              { bucket: label, events: tick.events_processed, alerts: tick.alerts_triggered },
            ];
            return { ...prev, event_rate_series: nextSeries };
          });
        }
      } catch {
        // ignore malformed frames
      }
    };

    const pollTimer = window.setInterval(() => {
      if (active && (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN)) {
        void loadSnapshot();
      }
    }, 3000);

    return () => {
      active = false;
      window.clearInterval(pollTimer);
      ws.close();
      wsRef.current = null;
    };
  }, [token, loadSnapshot]);

  const handleSimulate = async () => {
    if (!token) return;
    setSimulating(true);
    setSimNotice(null);
    try {
      const res = await apiClient.simulateAttack(token, selectedScenario, 8, "us-east");
      setSimNotice(`Enqueued ${res.events_enqueued} '${res.scenario}' events into stream.`);
      await loadSnapshot();
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white tracking-tight">Live Threat Dashboard</h1>
            <span
              data-testid="ws-status-pill"
              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${
                wsConnected
                  ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/40"
                  : "bg-slate-800 text-slate-400 border-slate-700"
              }`}
            >
              <Radio className={`w-3 h-3 ${wsConnected ? "animate-pulse" : ""}`} />
              {wsConnected ? "LIVE STREAM" : "LIVE POLLING"}
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            All entities are HMAC-SHA256 pseudonymized by default. Aggregates use Laplace Differential Privacy.
          </p>
        </div>

        {hasRole("analyst", "admin") && (
          <div className="flex flex-wrap items-center gap-2 bg-slate-900 border border-slate-800 rounded-xl p-2">
            <select
              aria-label="Attack simulation scenario"
              value={selectedScenario}
              onChange={(e) => setSelectedScenario(e.target.value as AttackScenario)}
              className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              {SCENARIOS.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={handleSimulate}
              disabled={simulating}
              className="inline-flex items-center gap-1.5 rounded-lg bg-rose-500 hover:bg-rose-400 disabled:opacity-50 px-3.5 py-1.5 text-xs font-semibold text-white transition"
            >
              <Zap className="w-3.5 h-3.5" />
              {simulating ? "Injecting..." : "Simulate Attack"}
            </button>
          </div>
        )}
      </div>

      {simNotice && (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-xs text-emerald-300">
          {simNotice}
        </div>
      )}

      {/* KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Events (DP-Noised)</span>
            <Activity className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-2" data-testid="kpi-dp-events">
            {analytics?.total_events_noisy ?? "—"}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Mechanism: {analytics?.mechanism ?? "Laplace"}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Alerts (DP-Noised)</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-2">
            {analytics?.total_alerts_noisy ?? "—"}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Open un-resolved: {analytics?.open_alerts_count ?? 0}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Privacy Budget (ε)</span>
            <Sparkles className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-300 mt-2" data-testid="kpi-epsilon">
            ε = {analytics?.epsilon.toFixed(2) ?? "1.00"}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Lower ε = stronger privacy noise
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Default Visibility</span>
            <EyeOff className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-lg font-bold text-white mt-2">Pseudonymized</div>
          <div className="text-[11px] text-slate-500 mt-1">
            Raw PII locked in AES-256-GCM vault
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white">Real-Time Event & Alert Rate</h2>
              <p className="text-xs text-slate-400">Live ingestion throughput and detection triggers</p>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={analytics?.event_rate_series || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="bucket" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 12 }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  name="Events"
                  stroke="#38bdf8"
                  fill="#0284c7"
                  fillOpacity={0.25}
                />
                <Area
                  type="monotone"
                  dataKey="alerts"
                  name="Alerts"
                  stroke="#fb7185"
                  fill="#e11d48"
                  fillOpacity={0.35}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-white">DP Counts per Region</h2>
            <p className="text-xs text-slate-400">
              Laplace-perturbed regional counts (ε={analytics?.epsilon.toFixed(2) ?? "1.00"})
            </p>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analytics?.region_counts || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="region" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 12 }}
                />
                <Bar dataKey="noisy_count" name="Noisy Event Count" fill="#10b981" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom Grid: Live Alert Feed + Top-N DP Sources */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              <h2 className="text-sm font-semibold text-white">Real-Time Alert Feed</h2>
            </div>
            <select
              aria-label="Filter alerts by status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg bg-slate-950 border border-slate-700 px-2.5 py-1 text-xs text-slate-300"
            >
              <option value="">All Statuses</option>
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>

          {alerts.length === 0 ? (
            <div className="py-12 text-center text-sm text-slate-500">
              No alerts detected yet. Trigger an attack simulation or wait for stream telemetry.
            </div>
          ) : (
            <div className="space-y-3" data-testid="alert-feed">
              {alerts.map((al) => (
                <Link
                  key={al.id}
                  to={`/alerts/${al.id}`}
                  className="block rounded-xl border border-slate-800 bg-slate-950/70 hover:border-slate-600 p-4 transition"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase border ${
                          SEVERITY_BADGE[al.severity] || SEVERITY_BADGE.medium
                        }`}
                      >
                        {al.severity}
                      </span>
                      <span className="text-sm font-semibold text-white">{al.title}</span>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded-md text-[11px] font-medium border ${
                        STATUS_BADGE[al.status] || STATUS_BADGE.new
                      }`}
                    >
                      {al.status}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 mt-2 leading-relaxed">{al.explanation}</p>

                  <div className="flex flex-wrap items-center justify-between gap-2 mt-3 text-[11px] text-slate-400">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-sky-300 font-mono">
                        {al.mitre_technique_id} · {al.mitre_technique_name}
                      </span>
                      <span>Region: {al.region}</span>
                      <span>ML Score: {al.anomaly_score.toFixed(2)}</span>
                    </div>
                    <span>{new Date(al.created_at).toLocaleTimeString()}</span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-white">Top-N Pseudonymized Sources (DP)</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Source IPs remain HMAC-tokenized with Laplace noise on counts.
            </p>
          </div>
          <div className="space-y-2.5">
            {(analytics?.top_sources || []).length === 0 ? (
              <div className="text-xs text-slate-500">Waiting for traffic...</div>
            ) : (
              analytics?.top_sources.map((src) => (
                <div
                  key={src.source_ip_token}
                  className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2"
                >
                  <span className="font-mono text-xs text-emerald-300 truncate max-w-[190px]">
                    {src.source_ip_token}
                  </span>
                  <span className="text-xs font-semibold text-white">~{src.noisy_count}</span>
                </div>
              ))
            )}
          </div>
          {analytics?.privacy_note && (
            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-[11px] text-slate-400 leading-relaxed">
              {analytics.privacy_note}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
