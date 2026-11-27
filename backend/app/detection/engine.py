"""Unified threat detection engine combining deterministic rules and Isolation Forest."""

from __future__ import annotations

from dataclasses import dataclass

from app.detection.mitre import MITRE_TECHNIQUES
from app.detection.ml_model import AnomalyScorer, extract_event_features
from app.detection.rules import PseudonymizedEventInput, RuleEngine, RuleMatch


@dataclass(frozen=True)
class DetectionOutcome:
    anomaly_score: float
    is_anomaly: bool
    alerts: list[RuleMatch]


class ThreatDetectionEngine:
    """Runs rule-based detection and Isolation Forest scoring on pseudonymized events."""

    def __init__(
        self,
        *,
        rule_engine: RuleEngine | None = None,
        ml_scorer: AnomalyScorer | None = None,
        ml_alert_threshold: float = 0.86,
    ) -> None:
        self.rule_engine = rule_engine or RuleEngine()
        self.ml_scorer = ml_scorer or AnomalyScorer()
        self.ml_alert_threshold = ml_alert_threshold

    def evaluate(
        self,
        event: PseudonymizedEventInput,
        *,
        known_bad_hashes: dict[str, tuple[str, str]] | None = None,
    ) -> DetectionOutcome:
        recent_rate, recent_ports = self.rule_engine.get_ip_activity_features(
            event.source_ip_token, event.timestamp
        )
        features = extract_event_features(
            event_type=event.event_type,
            bytes_out=event.bytes_out,
            dest_port=event.dest_port,
            auth_success=event.auth_success,
            recent_rate=recent_rate,
            recent_unique_ports=recent_ports,
        )
        anomaly_score, is_anomaly = self.ml_scorer.score_features(features)
        rule_matches = self.rule_engine.evaluate(event, known_bad_hashes=known_bad_hashes)

        if not rule_matches and is_anomaly and anomaly_score >= self.ml_alert_threshold:
            entities = self.rule_engine._collect_entities(event)
            rule_matches.append(
                RuleMatch(
                    rule_id="RULE_ML_ISOLATION_FOREST",
                    title="Behavioral Anomaly Detected by Isolation Forest",
                    severity="medium" if anomaly_score < 0.85 else "high",
                    mitre=MITRE_TECHNIQUES["T1071"],
                    explanation=(
                        f"Isolation Forest scored event at {anomaly_score:.2f} (threshold={self.ml_alert_threshold:.2f}) "
                        f"based on bytes_out={event.bytes_out}, dest_port={event.dest_port}, "
                        f"recent_rate={recent_rate}, unique_ports={recent_ports}."
                    ),
                    entity_tokens=entities,
                    event_ids=[event.event_id],
                    region=event.region,
                )
            )

        return DetectionOutcome(
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            alerts=rule_matches,
        )
