import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FederatedLearningPage } from "./pages/FederatedLearningPage";
import { LoginPage } from "./pages/LoginPage";
import { PrivacyConsolePage } from "./pages/PrivacyConsolePage";

function ProtectedRoutes() {
  const { token, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-sm text-slate-400">
        Verifying session...
      </div>
    );
  }
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <Layout />;
}

export function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<ProtectedRoutes />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
            <Route path="/privacy" element={<PrivacyConsolePage />} />
            <Route path="/federated" element={<FederatedLearningPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
