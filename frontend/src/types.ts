export type UserRole = "viewer" | "analyst" | "privacy_officer" | "admin";
export type SeverityLevel = "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "investigating" | "resolved";
export type AttackScenario =
  | "normal"
  | "brute_force"
  | "impossible_travel"
  | "data_exfiltration"
  | "port_scan"
  | "malicious_hash";

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface EntityTokenRef {
  entity_type: "username" | "email" | "ip";
  token: string;
}

export interface Alert {
  id: string;
  title: string;
  severity: SeverityLevel;
  status: AlertStatus;
  rule_id: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  mitre_tactic: string;
  explanation: string;
  anomaly_score: number;
  entity_tokens: EntityTokenRef[];
  event_ids: string[];
  region: string;
  created_at: string;
  updated_at: string;
}

export interface SecurityEvent {
  id: string;
  event_type: string;
  timestamp: string;
  region: string;
  username_token: string | null;
  email_token: string | null;
  source_ip_token: string | null;
  dest_ip_token: string | null;
  dest_port: number | null;
  bytes_out: number;
  auth_success: boolean | null;
  file_hash: string | null;
  anomaly_score: number;
  is_anomaly: boolean;
  raw_metadata: Record<string, unknown>;
}

export interface ReidentificationRequest {
  id: string;
  alert_id: string;
  requester_id: string;
  requester_username: string | null;
  reviewer_id: string | null;
  reviewer_username: string | null;
  requested_tokens: string[];
  justification: string;
  status: "pending" | "approved" | "rejected" | "expired";
  decision_note: string | null;
  created_at: string;
  reviewed_at: string | null;
  expires_at: string | null;
}

export interface AlertDetail {
  alert: Alert;
  timeline_events: SecurityEvent[];
  reidentification_requests: ReidentificationRequest[];
}

export interface RevealedEntity {
  token: string;
  entity_type: string;
  raw_value: string;
  key_id: string;
}

export interface ReidentificationReveal {
  request_id: string;
  alert_id: string;
  expires_at: string | null;
  entities: RevealedEntity[];
}

export interface DashboardAnalytics {
  epsilon: number;
  mechanism: string;
  total_events_noisy: number;
  total_alerts_noisy: number;
  open_alerts_count: number;
  region_counts: { region: string; noisy_count: number }[];
  top_sources: { source_ip_token: string; noisy_count: number }[];
  severity_counts: Record<string, number>;
  event_rate_series: { bucket: string; events: number; alerts: number }[];
  privacy_note: string;
}

export interface PrivacySettings {
  dp_epsilon: number;
  retention_days: number;
  hmac_rotation_hours: number;
  active_key_id: string;
  updated_at: string;
  updated_by: string;
}

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  actor_id: string;
  actor_role: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
}

export interface AuditVerifyResult {
  valid: boolean;
  checked_entries: number;
  broken_at_id: number | null;
  latest_hash: string | null;
  message: string;
}

export interface PsiCheckResponse {
  curve: string;
  double_blinded_client_hashes: string[];
  server_blinded_points: string[];
  server_set_size: number;
}

export interface OrgRoundMetric {
  org_id: string;
  org_name: string;
  sample_count: number;
  local_accuracy: number;
  local_loss: number;
}

export interface FederatedRound {
  round_number: number;
  global_accuracy: number;
  global_loss: number;
  org_metrics: OrgRoundMetric[];
  created_at: string;
}

export interface FederatedStatus {
  current_round: number;
  global_accuracy: number;
  global_loss: number;
  rounds: FederatedRound[];
}
