import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Eye, Key, Lock, ShieldAlert, Unlock } from "lucide-react";
import { ApiError, apiClient } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { AlertDetail, AlertStatus, ReidentificationReveal } from "../types";

export function AlertDetailPage() {
  const { alertId } = useParams<{ alertId: string }>();
  const { token, hasRole } = useAuth();
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showModal, setShowModal] = useState(false);
  const [selectedTokens, setSelectedTokens] = useState<string[]>([]);
  const [justification, setJustification] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [revealed, setRevealed] = useState<ReidentificationReveal | null>(null);

  const loadDetail = useCallback(async () => {
    if (!token || !alertId) return;
    setLoading(true);
    try {
      const data = await apiClient.getAlertDetail(token, alertId);
      setDetail(data);
      const uniqueTokens = Array.from(
        new Set(data.alert.entity_tokens.map((e) => e.token))
      );
      setSelectedTokens(uniqueTokens);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load alert");
    } finally {
      setLoading(false);
    }
  }, [token, alertId]);

  useEffect(() => {
    void loadDetail();
  }, [loadDetail]);

  const handleStatusChange = async (nextStatus: AlertStatus) => {
    if (!token || !alertId) return;
    await apiClient.updateAlertStatus(token, alertId, nextStatus);
    await loadDetail();
  };

  const handleRequestSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!token || !alertId) return;
    setSubmitting(true);
    setError(null);
    try {
      await apiClient.requestReidentification(token, {
        alert_id: alertId,
        tokens: selectedTokens,
        justification,
      });
      setShowModal(false);
      setJustification("");
      await loadDetail();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to submit request");
    } finally {
      setSubmitting(false);
    }
  };

  const handleReveal = async (reqId: string) => {
    if (!token) return;
    setError(null);
    try {
      const data = await apiClient.revealReidentifiedEntities(token, reqId);
      setRevealed(data);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to decrypt vault entries");
    }
  };

  if (loading) return <div className="text-sm text-slate-400">Loading alert details...</div>;
  if (!detail) return <div className="text-sm text-rose-400">{error || "Alert not found."}</div>;

  const { alert, timeline_events, reidentification_requests } = detail;
  const uniqueEntities = Array.from(
    new Map(alert.entity_tokens.map((e) => [e.token, e])).values()
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <Link
          to="/"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-300 hover:text-white"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Live Dashboard
        </Link>

        {hasRole("analyst", "admin") && (
          <div className="flex items-center gap-2">
            {(["new", "investigating", "resolved"] as AlertStatus[]).map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => void handleStatusChange(st)}
                className={`px-3 py-1 rounded-lg text-xs font-medium border capitalize transition ${
                  alert.status === st
                    ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/50"
                    : "bg-slate-900 text-slate-400 border-slate-700 hover:text-white"
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Alert Header Card */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              <h1 className="text-xl font-bold text-white">{alert.title}</h1>
            </div>
            <p className="text-sm text-slate-300 mt-2">{alert.explanation}</p>
          </div>
          <div className="text-right text-xs text-slate-400 space-y-1">
            <div>
              MITRE ATT&amp;CK:{" "}
              <span className="font-mono text-sky-300">
                {alert.mitre_technique_id} ({alert.mitre_technique_name})
              </span>
            </div>
            <div>Tactic: {alert.mitre_tactic}</div>
            <div>Isolation Forest Score: {alert.anomaly_score.toFixed(3)}</div>
          </div>
        </div>
      </div>

      {/* Pseudonymized Entities + Break-Glass Button */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Lock className="w-4 h-4 text-emerald-400" />
                Pseudonymized Entities
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Identities tokenized with HMAC-SHA256. Raw values require audited approval.
              </p>
            </div>
            {hasRole("analyst", "admin") && uniqueEntities.length > 0 && (
              <button
                type="button"
                onClick={() => setShowModal(true)}
                className="inline-flex items-center gap-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 px-3 py-1.5 text-xs font-semibold text-slate-950 transition"
              >
                <Key className="w-3.5 h-3.5" />
                Request re-identification
              </button>
            )}
          </div>

          <div className="space-y-2">
            {uniqueEntities.map((ent) => (
              <div
                key={ent.token}
                className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 px-3 py-2"
              >
                <span className="text-xs uppercase font-semibold text-slate-400">{ent.entity_type}</span>
                <span className="font-mono text-xs text-emerald-300">{ent.token}</span>
              </div>
            ))}
          </div>

          {revealed && (
            <div className="rounded-xl border border-amber-500/50 bg-amber-500/10 p-4 space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold text-amber-300">
                <span className="flex items-center gap-1.5">
                  <Unlock className="w-4 h-4" />
                  Authorized Break-Glass Reveal (Audited)
                </span>
                {revealed.expires_at && (
                  <span>Expires {new Date(revealed.expires_at).toLocaleTimeString()}</span>
                )}
              </div>
              {revealed.entities.map((e) => (
                <div
                  key={e.token}
                  className="flex items-center justify-between text-xs bg-slate-950/80 rounded px-3 py-1.5"
                >
                  <span className="font-mono text-slate-400">{e.token}</span>
                  <span className="font-mono font-bold text-amber-200">{e.raw_value}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Break-Glass Requests Status */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white">Break-Glass Re-identification Requests</h2>
          {reidentification_requests.length === 0 ? (
            <p className="text-xs text-slate-500">No re-identification requests submitted for this alert.</p>
          ) : (
            <div className="space-y-3">
              {reidentification_requests.map((req) => (
                <div
                  key={req.id}
                  className="rounded-lg border border-slate-800 bg-slate-950 p-3 space-y-2"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-white">
                      Requested by {req.requester_username || req.requester_id}
                    </span>
                    <span className="uppercase font-semibold px-2 py-0.5 rounded bg-slate-800 text-amber-300">
                      {req.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{req.justification}</p>
                  {req.status === "approved" && (
                    <button
                      type="button"
                      onClick={() => void handleReveal(req.id)}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-3 py-1 text-xs font-semibold text-slate-950"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      Reveal Authorized Raw Entities
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Event Timeline */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
        <h2 className="text-sm font-semibold text-white">Correlated Pseudonymized Timeline</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2 pr-4">Timestamp</th>
                <th className="py-2 pr-4">Type</th>
                <th className="py-2 pr-4">Region</th>
                <th className="py-2 pr-4">Source IP Token</th>
                <th className="py-2 pr-4">User Token</th>
                <th className="py-2 pr-4">Port / Bytes</th>
                <th className="py-2">ML Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {timeline_events.map((ev) => (
                <tr key={ev.id} className="text-slate-300">
                  <td className="py-2.5 pr-4 whitespace-nowrap">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 pr-4 font-mono">{ev.event_type}</td>
                  <td className="py-2.5 pr-4">{ev.region}</td>
                  <td className="py-2.5 pr-4 font-mono text-emerald-300">{ev.source_ip_token || "—"}</td>
                  <td className="py-2.5 pr-4 font-mono text-sky-300">{ev.username_token || "—"}</td>
                  <td className="py-2.5 pr-4">
                    {ev.dest_port ?? "—"} / {ev.bytes_out.toLocaleString()} B
                  </td>
                  <td className="py-2.5">{ev.anomaly_score.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <form
            onSubmit={handleRequestSubmit}
            className="w-full max-w-lg rounded-2xl border border-slate-700 bg-slate-900 p-6 space-y-4"
          >
            <h3 className="text-base font-bold text-white">Request Break-Glass Re-identification</h3>
            <p className="text-xs text-slate-400">
              A Privacy Officer must approve this request before AES-256-GCM vault decryption is allowed.
              All actions are written to the hash-chained audit log.
            </p>

            <div>
              <div className="text-xs font-medium text-slate-300 mb-1.5">Tokens to Reveal</div>
              <div className="space-y-1.5">
                {uniqueEntities.map((ent) => (
                  <label key={ent.token} className="flex items-center gap-2 text-xs text-slate-200">
                    <input
                      type="checkbox"
                      checked={selectedTokens.includes(ent.token)}
                      onChange={(e) => {
                        setSelectedTokens((prev) =>
                          e.target.checked
                            ? [...prev, ent.token]
                            : prev.filter((t) => t !== ent.token)
                        );
                      }}
                    />
                    <span className="uppercase text-slate-400">{ent.entity_type}:</span>
                    <span className="font-mono text-emerald-300">{ent.token}</span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label htmlFor="justification" className="block text-xs font-medium text-slate-300 mb-1.5">
                Justification (minimum 12 characters)
              </label>
              <textarea
                id="justification"
                required
                minLength={12}
                rows={3}
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
                placeholder="Incident IR-2026-04: need raw source IP for perimeter firewall block."
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-amber-500 focus:outline-none"
              />
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowModal(false)}
                className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting || selectedTokens.length === 0}
                className="rounded-lg bg-amber-500 hover:bg-amber-400 disabled:opacity-50 px-4 py-1.5 text-xs font-semibold text-slate-950"
              >
                {submitting ? "Submitting..." : "Submit Request"}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
