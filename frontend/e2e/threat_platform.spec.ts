import { expect, test } from "@playwright/test";

const DEMO_PASSWORD = process.env.DEMO_USER_PASSWORD || "ThreatDemo!2026";

async function signIn(page: import("@playwright/test").Page, username: string) {
  await page.goto("/login");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(DEMO_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByText("Live Threat Dashboard")).toBeVisible();
}

test.describe("Privacy-Preserving Threat Detection E2E", () => {
  test("simulates attack, receives live alert, and completes audited break-glass re-identification", async ({
    page,
  }) => {
    await signIn(page, "analyst");
    await expect(page.getByTestId("ws-status-pill")).toContainText("LIVE STREAM", { timeout: 10_000 });

    // Trigger Data Exfiltration attack from Dashboard
    await page.getByLabel("Attack simulation scenario").selectOption("data_exfiltration");
    await page.getByRole("button", { name: /simulate attack/i }).click();

    // Verify real-time alert appears on feed with MITRE T1041 and pseudonymized tokens
    const feed = page.getByTestId("alert-feed");
    await expect(feed).toContainText("Anomalous Outbound Data Exfiltration", { timeout: 10_000 });
    await expect(feed).toContainText("T1041");
    await expect(feed).not.toContainText("10.44.8.19");

    // Open alert detail & submit break-glass re-identification request
    await feed.getByText("Anomalous Outbound Data Exfiltration").first().click();
    await expect(page.getByText("Pseudonymized Entities")).toBeVisible();
    await expect(page.getByText("Correlated Pseudonymized Timeline")).toBeVisible();

    await page.getByRole("button", { name: /request re-identification/i }).click();
    await page
      .getByLabel(/justification/i)
      .fill("Playwright E2E investigation: correlate exfiltration source IP.");
    await page.getByRole("button", { name: /submit request/i }).click();
    await expect(page.getByText(/pending/i).first()).toBeVisible();

    // Switch to Privacy Officer to approve & verify hash chain
    await page.getByRole("button", { name: /sign out/i }).click();
    await signIn(page, "officer");
    await page.getByRole("link", { name: /privacy console/i }).click();
    await expect(page.getByText("Privacy Governance Console")).toBeVisible();

    await page.getByRole("button", { name: /^approve$/i }).first().click();
    await expect(page.getByText(/re-identification request approved/i)).toBeVisible();

    await page.getByRole("button", { name: /verify chain integrity/i }).click();
    await expect(page.getByTestId("audit-verify-banner")).toContainText("CHAIN INTACT");

    // Analyst returns to alert and reveals authorized raw IP from AES-256-GCM vault
    await page.getByRole("button", { name: /sign out/i }).click();
    await signIn(page, "analyst");
    await page.getByTestId("alert-feed").getByText("Anomalous Outbound Data Exfiltration").first().click();
    await page.getByRole("button", { name: /reveal authorized raw entities/i }).click();
    await expect(page.getByText("10.44.8.19")).toBeVisible();
  });

  test("executes client-side ECDH-PSI check and 3-org Federated Learning rounds", async ({ page }) => {
    await signIn(page, "analyst");
    await page.getByRole("link", { name: /privacy console/i }).click();
    await page.getByRole("button", { name: /load sample hashes/i }).click();
    await page.getByRole("button", { name: /run ecdh-psi check/i }).click();
    await expect(page.getByText(/matched 1 hash\(es\)/i)).toBeVisible({ timeout: 10_000 });

    await page.getByRole("link", { name: /federated learning/i }).click();
    await expect(page.getByText("Federated Learning (FedAvg) Simulator")).toBeVisible();
    await page.getByRole("button", { name: /run 3 rounds/i }).click();
    await expect(page.getByTestId("fl-current-round")).not.toHaveText("0", { timeout: 10_000 });
    await expect(page.getByTestId("fl-global-accuracy")).toContainText("%");
  });
});
