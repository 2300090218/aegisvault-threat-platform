import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  CheckCircle2,
  DatabaseZap,
  FileSearch,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  Sliders,
} from "lucide-react";
import { ApiError, apiClient } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type {
  AuditLogEntry,
  AuditVerifyResult,
  PrivacySettings,
  ReidentificationRequest,
} from "../types";
import {
  blindClientItems,
  generateClientScalar,
  resolvePsiMatches,
} from "../utils/psi";

export function PrivacyConsolePage() {
  const { token, user, hasRole } = useAuth();
  const [settings, setSettings] = useState<PrivacySettings | null>(null);
  const [epsilonDraft, setEpsilonDraft] = useState<number>(1.0);
  const [requests, setRequests] = useState<ReidentificationRequest[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // ECDH-PSI Checker State
  const [psiInput, setPsiInput] = useState("");
  const [psiMatches, setPsiMatches] = useState<string[] | null>(null);
  const [psiServerSize, setPsiServerSize] = useState<number | null>(null);
  const [psiLoading, setPsiLoading] = useState(false);

  const canManagePrivacy = hasRole("privacy_officer", "admin");

  const loadAll = useCallback(async () => {
    if (!token) return;
    try {
      const [cfg, reqs] = await Promise.all([
        apiClient.getPrivacySettings(token),
        apiClient.listReidentificationRequests(token),
      ]);
      setSettings(cfg);
      setEpsilonDraft(cfg.dp_epsilon);
      setRequests(reqs);

      if (canManagePrivacy) {
        const logs = await apiClient.getAuditLogs(token, 50);
        setAuditLogs(logs);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load privacy console");
    }
  }, [token, canManagePrivacy]);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const handleSaveEpsilon = async () => {
    if (!token) return;
    setError(null);
    try {
      const updated = await apiClient.updateEpsilon(token, epsilonDraft);
      setSettings(updated);
      setNotice(`Updated Differential Privacy budget to ε = ${updated.dp_epsilon.toFixed(2)}`);
      await loadAll();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to update epsilon");
    }
  };

  const handleRotateKey = async () => {
    if (!token) return;
    setError(null);
    const res = await apiClient.rotateHmacKey(token);
    setNotice(`Rotated HMAC pseudonymization key from ${res.previous_key_id} to ${res.new_key_id}.`);
    await loadAll();
  };

  const handleRunRetention = async () => {
    if (!token) return;
    setError(null);
    const res = await apiClient.runRetention(token);
    setNotice(
      `Data minimization job ran: aggregated ${res.events_aggregated} events, purged ${res.events_deleted} events & ${res.vault_entries_deleted} vault entries.`
    );
    await loadAll();
  };

  const handleDecision = async (reqId: string, decision: "approved" | "rejected") => {
    if (!token) return;
    setError(null);
    try {
      await apiClient.decideReidentificationRequest(
        token,
        reqId,
        decision,
        decision === "approved" ? "Approved after justification review" : "Rejected by Privacy Officer"
      );
      setNotice(`Re-identification request ${decision}.`);
      await loadAll();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to process decision");
    }
  };

  const handleVerifyAudit = async () => {
    if (!token) return;
    const res = await apiClient.verifyAuditChain(token);
    setVerifyResult(res);
  };

  const handleLoadPsiHints = async () => {
    if (!token) return;
    const hints = await apiClient.getPsiDemoHints(token);
    setPsiInput(hints.sample_candidates.map((c) => c.sha256).join("\n"));
  };

  const handleRunPsi = async () => {
    if (!token) return;
    const items = psiInput
      .split(/\s+/)
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0);
    if (items.length === 0) return;

    setPsiLoading(true);
    setError(null);
    try {
      const scalar = generateClientScalar();
      const blinded = await blindClientItems(items, scalar);
      const resp = await apiClient.checkPsi(token, blinded);
      const matches = await resolvePsiMatches({
        candidateItems: items,
        scalar,
        doubleBlindedClientHashes: resp.double_blinded_client_hashes,
        serverBlindedPoints: resp.server_blinded_points,
      });
      setPsiMatches(matches);
      setPsiServerSize(resp.server_set_size);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "ECDH-PSI evaluation failed");
    } finally {
      setPsiLoading(false);
    }
  };

  const pendingRequests = requests.filter((r) => r.status === "pending");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Privacy Governance Console</h1>
        <p className="text-sm text-slate-400 mt-1">
          Configure Laplace Differential Privacy, manage HMAC key rotation, approve break-glass requests,
          verify hash-chained audit logs, and run ECDH Private Set Intersection.
        </p>
      </div>

      {notice && (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-2.5 text-xs text-emerald-300">
          {notice}
        </div>
      )}
      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Top Controls: Epsilon Slider + Key Rotation & Retention */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-emerald-400" />
              Differential Privacy Budget (ε)
            </h2>
            <span className="font-mono text-sm font-bold text-emerald-300">
              ε = {epsilonDraft.toFixed(2)}
            </span>
          </div>

          <input
            type="range"
            aria-label="Differential Privacy Epsilon Slider"
            min={0.1}
            max={5.0}
            step={0.1}
            value={epsilonDraft}
            disabled={!canManagePrivacy}
            onChange={(e) => setEpsilonDraft(parseFloat(e.target.value))}
            className="w-full accent-emerald-500"
          />

          <div className="flex justify-between text-[11px] text-slate-400">
            <span>0.10 (Strongest Privacy / High Noise)</span>
            <span>5.00 (High Utility / Low Noise)</span>
          </div>

          {canManagePrivacy ? (
            <button
              type="button"
              onClick={handleSaveEpsilon}
              className="rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-xs font-semibold text-slate-950 transition"
            >
              Apply Epsilon Policy
            </button>
          ) : (
            <div className="text-xs text-slate-500">
              Only Privacy Officers or Admins can modify ε.
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-sky-400" />
            Key Rotation &amp; Data Minimization
          </h2>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <div className="text-slate-400">Active HMAC Key ID</div>
              <div className="font-mono text-sm font-bold text-white mt-1">
                {settings?.active_key_id ?? "kv1"}
              </div>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <div className="text-slate-400">Retention Window</div>
              <div className="font-mono text-sm font-bold text-white mt-1">
                {settings?.retention_days ?? 30} days
              </div>
            </div>
          </div>
          {canManagePrivacy && (
            <div className="flex flex-wrap gap-2.5">
              <button
                type="button"
                onClick={handleRotateKey}
                className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-500/15 hover:bg-sky-500/25 px-3.5 py-2 text-xs font-semibold text-sky-300"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Rotate HMAC Key
              </button>
              <button
                type="button"
                onClick={handleRunRetention}
                className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/50 bg-amber-500/15 hover:bg-amber-500/25 px-3.5 py-2 text-xs font-semibold text-amber-300"
              >
                <DatabaseZap className="w-3.5 h-3.5" />
                Run Retention Job
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Pending Break-Glass Approvals */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">
            Pending Break-Glass Re-identification Approvals ({pendingRequests.length})
          </h2>
        </div>
        {pendingRequests.length === 0 ? (
          <p className="text-xs text-slate-500">No pending break-glass requests.</p>
        ) : (
          <div className="space-y-3">
            {pendingRequests.map((req) => (
              <div
                key={req.id}
                className="rounded-xl border border-slate-800 bg-slate-950 p-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-xs">
                    <span className="font-semibold text-white">
                      {req.requester_username || req.requester_id}
                    </span>
                    <span className="text-slate-500">·</span>
                    <Link to={`/alerts/${req.alert_id}`} className="text-sky-400 hover:underline">
                      Alert {req.alert_id.slice(0, 8)}
                    </Link>
                    <span className="text-slate-500">·</span>
                    <span className="font-mono text-emerald-300">
                      {req.requested_tokens.length} token(s)
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{req.justification}</p>
                </div>

                {canManagePrivacy && req.requester_id !== user?.id && (
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => void handleDecision(req.id, "approved")}
                      className="rounded-lg bg-emerald-500 hover:bg-emerald-400 px-3 py-1.5 text-xs font-semibold text-slate-950"
                    >
                      Approve
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleDecision(req.id, "rejected")}
                      className="rounded-lg border border-rose-500/50 bg-rose-500/10 hover:bg-rose-500/20 px-3 py-1.5 text-xs font-semibold text-rose-300"
                    >
                      Reject
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ECDH-PSI Threat-Intel Hash Checker */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <FileSearch className="w-4 h-4 text-purple-400" />
              ECDH Private Set Intersection (Threat-Intel Hash Lookup)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Client blinds SHA-256 hashes on NIST P-256 locally in your browser before querying the server.
            </p>
          </div>
          <button
            type="button"
            onClick={handleLoadPsiHints}
            className="rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 text-xs text-slate-200"
          >
            Load Sample Hashes
          </button>
        </div>

        <textarea
          rows={3}
          value={psiInput}
          onChange={(e) => setPsiInput(e.target.value)}
          placeholder="Paste one SHA-256 file hash per line..."
          className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs text-slate-200 focus:border-purple-500 focus:outline-none"
        />

        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={psiLoading || !psiInput.trim()}
            onClick={handleRunPsi}
            className="rounded-lg bg-purple-500 hover:bg-purple-400 disabled:opacity-50 px-4 py-2 text-xs font-semibold text-white"
          >
            {psiLoading ? "Computing P-256 Intersection..." : "Run ECDH-PSI Check"}
          </button>
          {psiMatches !== null && (
            <span className="text-xs text-slate-300">
              Matched <strong className="text-rose-300">{psiMatches.length}</strong> hash(es) against{" "}
              {psiServerSize} private threat-intel indicators.
            </span>
          )}
        </div>

        {psiMatches && psiMatches.length > 0 && (
          <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 space-y-1">
            <div className="text-xs font-semibold text-rose-300">Threat-Intel Intersection Hits:</div>
            {psiMatches.map((m) => (
              <div key={m} className="font-mono text-xs text-rose-200">
                {m}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Hash-Chained Audit Log Viewer */}
      {canManagePrivacy && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Append-Only Hash-Chained Audit Log
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Every entry commits to SHA-256(canonical_payload + prev_hash).
              </p>
            </div>
            <button
              type="button"
              onClick={handleVerifyAudit}
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-500/15 hover:bg-emerald-500/25 px-3.5 py-1.5 text-xs font-semibold text-emerald-300"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              Verify Chain Integrity
            </button>
          </div>

          {verifyResult && (
            <div
              data-testid="audit-verify-banner"
              className={`rounded-lg border px-4 py-2.5 text-xs ${
                verifyResult.valid
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                  : "border-rose-500/40 bg-rose-500/10 text-rose-300"
              }`}
            >
              <strong>{verifyResult.valid ? "CHAIN INTACT" : "CHAIN COMPROMISED"}:</strong>{" "}
              {verifyResult.message} (Latest hash: <code>{verifyResult.latest_hash?.slice(0, 16)}...</code>)
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2 pr-3">#</th>
                  <th className="py-2 pr-3">Timestamp</th>
                  <th className="py-2 pr-3">Role</th>
                  <th className="py-2 pr-3">Action</th>
                  <th className="py-2 pr-3">Resource</th>
                  <th className="py-2">Entry Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="text-slate-300">
                    <td className="py-2 pr-3 font-mono">{log.id}</td>
                    <td className="py-2 pr-3 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2 pr-3">{log.actor_role}</td>
                    <td className="py-2 pr-3 font-mono text-sky-300">{log.action}</td>
                    <td className="py-2 pr-3 font-mono">
                      {log.resource_type}:{log.resource_id.slice(0, 12)}
                    </td>
                    <td className="py-2 font-mono text-emerald-400">{log.entry_hash.slice(0, 18)}...</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
