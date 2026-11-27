import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { KeyRound, ShieldCheck } from "lucide-react";
import { ApiError } from "../api/client";
import { useAuth } from "../context/AuthContext";

const DEMO_ROLES = [
  { username: "viewer", label: "Viewer", desc: "Read-only pseudonymized telemetry" },
  { username: "analyst", label: "Analyst", desc: "Triage alerts & request break-glass" },
  { username: "officer", label: "Privacy Officer", desc: "Approve re-ID, DP epsilon & audit" },
  { username: "admin", label: "Admin", desc: "Full platform & FL orchestration" },
];

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("analyst");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const envDemoPassword = (import.meta.env.VITE_DEMO_PASSWORD as string | undefined) || "";

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password);
      navigate("/", { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Authentication failed. Verify backend availability.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/90 p-8 shadow-2xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="h-11 w-11 rounded-xl bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">AegisVault Threat Platform</h1>
            <p className="text-xs text-slate-400">Zero-trust pseudonymized SOC login</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="username" className="block text-xs font-medium text-slate-300 mb-1.5">
              Username
            </label>
            <input
              id="username"
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              placeholder="analyst"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-xs font-medium text-slate-300 mb-1.5">
              Password
            </label>
            <input
              id="password"
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              placeholder="Enter password"
            />
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 px-4 py-2.5 text-sm font-semibold text-slate-950 transition flex items-center justify-center gap-2"
          >
            <KeyRound className="w-4 h-4" />
            {submitting ? "Authenticating..." : "Sign In"}
          </button>
        </form>

        <div className="mt-6 pt-5 border-t border-slate-800">
          <div className="text-xs font-medium text-slate-400 mb-2.5">
            Select Role Profile {envDemoPassword ? "(auto-fills demo password)" : "(uses DEMO_USER_PASSWORD from .env)"}
          </div>
          <div className="grid grid-cols-2 gap-2">
            {DEMO_ROLES.map((r) => (
              <button
                key={r.username}
                type="button"
                onClick={() => {
                  setUsername(r.username);
                  if (envDemoPassword) setPassword(envDemoPassword);
                }}
                className={`text-left rounded-lg border p-2.5 transition ${
                  username === r.username
                    ? "border-emerald-500/60 bg-emerald-500/10"
                    : "border-slate-800 bg-slate-950/60 hover:border-slate-700"
                }`}
              >
                <div className="text-xs font-semibold text-white">{r.label}</div>
                <div className="text-[11px] text-slate-400 leading-tight mt-0.5">{r.desc}</div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
