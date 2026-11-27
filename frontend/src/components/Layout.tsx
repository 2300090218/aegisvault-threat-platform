import { Activity, Lock, LogOut, Network, Shield, ShieldCheck } from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const ROLE_STYLES: Record<string, string> = {
  viewer: "bg-slate-800 text-slate-300 border-slate-700",
  analyst: "bg-sky-950 text-sky-300 border-sky-700/60",
  privacy_officer: "bg-emerald-950 text-emerald-300 border-emerald-700/60",
  admin: "bg-purple-950 text-purple-300 border-purple-700/60",
};

export function Layout() {
  const { user, logout } = useAuth();

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition ${
      isActive
        ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/40"
        : "text-slate-300 hover:bg-slate-800/80 hover:text-white border border-transparent"
    }`;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2.5">
              <div className="h-9 w-9 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div>
                <div className="text-sm font-bold tracking-tight text-white">AegisVault SOC</div>
                <div className="text-[11px] text-slate-400">Privacy-Preserving Threat Detection</div>
              </div>
            </div>

            <nav className="hidden md:flex items-center gap-1.5" aria-label="Primary Navigation">
              <NavLink to="/" end className={navLinkClass}>
                <Activity className="w-4 h-4" />
                Live Dashboard
              </NavLink>
              <NavLink to="/privacy" className={navLinkClass}>
                <Lock className="w-4 h-4" />
                Privacy Console
              </NavLink>
              <NavLink to="/federated" className={navLinkClass}>
                <Network className="w-4 h-4" />
                Federated Learning
              </NavLink>
            </nav>
          </div>

          <div className="flex items-center gap-3">
            {user && (
              <>
                <div className="hidden sm:flex items-center gap-2 text-xs">
                  <Shield className="w-3.5 h-3.5 text-slate-400" />
                  <span className="text-slate-200 font-medium">{user.username}</span>
                  <span
                    data-testid="user-role-badge"
                    className={`px-2 py-0.5 rounded-full border text-[11px] font-semibold uppercase tracking-wide ${
                      ROLE_STYLES[user.role] || ROLE_STYLES.viewer
                    }`}
                  >
                    {user.role.replace("_", " ")}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={logout}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  Sign out
                </button>
              </>
            )}
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        <Outlet />
      </main>
    </div>
  );
}
