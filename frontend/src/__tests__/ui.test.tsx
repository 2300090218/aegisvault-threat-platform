import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "../api/client";
import { AuthProvider } from "../context/AuthContext";
import { LoginPage } from "../pages/LoginPage";
import { PrivacyConsolePage } from "../pages/PrivacyConsolePage";

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    apiClient: {
      login: vi.fn(),
      me: vi.fn(),
      getPrivacySettings: vi.fn(),
      listReidentificationRequests: vi.fn(),
      getAuditLogs: vi.fn(),
      updateEpsilon: vi.fn(),
      verifyAuditChain: vi.fn(),
      rotateHmacKey: vi.fn(),
      runRetention: vi.fn(),
      decideReidentificationRequest: vi.fn(),
      checkPsi: vi.fn(),
      getPsiDemoHints: vi.fn(),
    },
  };
});

describe("LoginPage & PrivacyConsolePage", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  it("renders role selector buttons and submits credentials on LoginPage", async () => {
    const officerUser = {
      id: "u1",
      username: "officer",
      email: "officer@privacy-soc.io",
      role: "privacy_officer" as const,
      is_active: true,
      created_at: new Date().toISOString(),
    };
    vi.mocked(apiClient.login).mockResolvedValue({
      access_token: "jwt-123",
      token_type: "bearer",
      user: officerUser,
    });
    vi.mocked(apiClient.me).mockResolvedValue(officerUser);

    render(
      <MemoryRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>
    );

    const user = userEvent.setup();
    await user.click(screen.getByText("Privacy Officer"));
    await user.type(screen.getByLabelText("Password"), "secret1234");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(apiClient.login).toHaveBeenCalledWith("officer", "secret1234");
    });
  });

  it("allows privacy_officer to inspect audit chain and adjust epsilon", async () => {
    localStorage.setItem("aegisvault_jwt", "jwt-officer");
    vi.mocked(apiClient.me).mockResolvedValue({
      id: "u-off",
      username: "officer",
      email: "officer@privacy-soc.io",
      role: "privacy_officer",
      is_active: true,
      created_at: new Date().toISOString(),
    });
    vi.mocked(apiClient.getPrivacySettings).mockResolvedValue({
      dp_epsilon: 1.0,
      retention_days: 30,
      hmac_rotation_hours: 24,
      active_key_id: "kv1",
      updated_at: new Date().toISOString(),
      updated_by: "system",
    });
    vi.mocked(apiClient.listReidentificationRequests).mockResolvedValue([]);
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue([
      {
        id: 1,
        timestamp: new Date().toISOString(),
        actor_id: "u-off",
        actor_role: "privacy_officer",
        action: "SYSTEM_BOOTSTRAPPED",
        resource_type: "platform",
        resource_id: "init",
        details: {},
        prev_hash: "0".repeat(64),
        entry_hash: "a".repeat(64),
      },
    ]);
    vi.mocked(apiClient.verifyAuditChain).mockResolvedValue({
      valid: true,
      checked_entries: 1,
      broken_at_id: null,
      latest_hash: "a".repeat(64),
      message: "All 1 audit log entries verified cryptographically intact.",
    });

    render(
      <MemoryRouter>
        <AuthProvider>
          <PrivacyConsolePage />
        </AuthProvider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("SYSTEM_BOOTSTRAPPED")).toBeInTheDocument();
    });

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /verify chain integrity/i }));

    await waitFor(() => {
      expect(screen.getByTestId("audit-verify-banner")).toHaveTextContent("CHAIN INTACT");
    });
  });
});
