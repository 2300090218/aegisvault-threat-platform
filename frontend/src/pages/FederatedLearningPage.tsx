import { useCallback, useEffect, useState } from "react";
import { Network, Play, RotateCcw } from "lucide-react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { apiClient } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { FederatedStatus } from "../types";

export function FederatedLearningPage() {
  const { token, hasRole } = useAuth();
  const [status, setStatus] = useState<FederatedStatus | null>(null);
  const [running, setRunning] = useState(false);

  const loadStatus = useCallback(async () => {
    if (!token) return;
    const res = await apiClient.getFederatedStatus(token);
    setStatus(res);
  }, [token]);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  const handleTrain = async (rounds: number) => {
    if (!token) return;
    setRunning(true);
    try {
      const updated = await apiClient.trainFederatedRounds(token, rounds, 3);
      setStatus(updated);
    } finally {
      setRunning(false);
    }
  };

  const handleReset = async () => {
    if (!token) return;
    setRunning(true);
    try {
      const updated = await apiClient.resetFederated(token);
      setStatus(updated);
    } finally {
      setRunning(false);
    }
  };

  const latestRound = status?.rounds[status.rounds.length - 1];
  const chartData = (status?.rounds || []).map((r) => ({
    round: `R${r.round_number}`,
    globalAccuracy: Number((r.global_accuracy * 100).toFixed(1)),
    globalLoss: r.global_loss,
  }));

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Network className="w-6 h-6 text-emerald-400" />
            Federated Learning (FedAvg) Simulator
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Three organizations train local anomaly detectors on non-IID security logs and exchange only
            gradient/weight updates—never raw telemetry.
          </p>
        </div>

        {hasRole("analyst", "privacy_officer", "admin") && (
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={running}
              onClick={() => void handleTrain(1)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 px-3.5 py-2 text-xs font-semibold text-slate-950"
            >
              <Play className="w-3.5 h-3.5" />
              Run 1 Round
            </button>
            <button
              type="button"
              disabled={running}
              onClick={() => void handleTrain(3)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-500/15 hover:bg-emerald-500/25 disabled:opacity-50 px-3.5 py-2 text-xs font-semibold text-emerald-300"
            >
              Run 3 Rounds
            </button>
            {hasRole("admin", "privacy_officer") && (
              <button
                type="button"
                disabled={running}
                onClick={() => void handleReset()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-3 py-2 text-xs text-slate-300"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                Reset
              </button>
            )}
          </div>
        )}
      </div>

      {/* Global Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-xs text-slate-400">Completed FedAvg Rounds</div>
          <div className="text-2xl font-bold text-white mt-1" data-testid="fl-current-round">
            {status?.current_round ?? 0}
          </div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-xs text-slate-400">Global Model Accuracy</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1" data-testid="fl-global-accuracy">
            {status ? `${(status.global_accuracy * 100).toFixed(1)}%` : "—"}
          </div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-xs text-slate-400">Global Evaluation Loss</div>
          <div className="text-2xl font-bold text-sky-300 mt-1">
            {status ? status.global_loss.toFixed(4) : "—"}
          </div>
        </div>
      </div>

      {/* Accuracy Chart */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h2 className="text-sm font-semibold text-white mb-4">Global FedAvg Convergence</h2>
        {chartData.length === 0 ? (
          <div className="h-56 flex items-center justify-center text-xs text-slate-500">
            Click "Run 1 Round" or "Run 3 Rounds" to start federated training across the 3 organizations.
          </div>
        ) : (
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="round" stroke="#64748b" fontSize={11} />
                <YAxis yAxisId="left" domain={[0, 100]} stroke="#10b981" fontSize={11} />
                <YAxis yAxisId="right" orientation="right" stroke="#38bdf8" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 12 }}
                />
                <Legend />
                <Line
                  yAxisId="left"
                  type="monotone"
                  dataKey="globalAccuracy"
                  name="Global Accuracy (%)"
                  stroke="#10b981"
                  strokeWidth={2.5}
                />
                <Line
                  yAxisId="right"
                  type="monotone"
                  dataKey="globalLoss"
                  name="Global Log-Loss"
                  stroke="#38bdf8"
                  strokeWidth={2}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Per-Organization Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {(latestRound?.org_metrics || [
          { org_id: "org_alpha", org_name: "Org-Alpha (FinTech)", sample_count: 300, local_accuracy: 0, local_loss: 0 },
          { org_id: "org_beta", org_name: "Org-Beta (HealthCare)", sample_count: 250, local_accuracy: 0, local_loss: 0 },
          { org_id: "org_gamma", org_name: "Org-Gamma (CloudSaaS)", sample_count: 290, local_accuracy: 0, local_loss: 0 },
        ]).map((org) => (
          <div key={org.org_id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-2">
            <div className="text-sm font-semibold text-white">{org.org_name}</div>
            <div className="text-xs text-slate-400">Private local samples: {org.sample_count}</div>
            <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-xs">
              <span className="text-slate-400">Local Accuracy:</span>
              <span className="font-semibold text-emerald-300">
                {latestRound ? `${(org.local_accuracy * 100).toFixed(1)}%` : "Pending"}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Local Loss:</span>
              <span className="font-mono text-slate-200">
                {latestRound ? org.local_loss.toFixed(4) : "—"}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
