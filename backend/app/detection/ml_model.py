"""Isolation Forest anomaly detection model for security event telemetry."""

from __future__ import annotations

import math

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

EVENT_TYPE_CODES: dict[str, float] = {
    "auth_log": 0.0,
    "network_flow": 1.0,
    "file_hash": 2.0,
}

COMMON_PORTS = {22, 53, 80, 443, 8080, 8443}


def extract_event_features(
    *,
    event_type: str,
    bytes_out: int,
    dest_port: int | None,
    auth_success: bool | None,
    recent_rate: int = 0,
    recent_unique_ports: int = 0,
) -> np.ndarray:
    """Convert pseudonymized event telemetry into a 7-feature numeric vector."""
    ev_code = EVENT_TYPE_CODES.get(event_type, 1.0)
    log_bytes = math.log1p(max(0, bytes_out))
    port_norm = (dest_port or 0) / 65535.0
    unusual_port = 1.0 if (dest_port is not None and dest_port not in COMMON_PORTS) else 0.0
    auth_fail = 1.0 if auth_success is False else 0.0
    return np.array(
        [
            ev_code,
            log_bytes,
            port_norm,
            unusual_port,
            auth_fail,
            float(recent_rate),
            float(recent_unique_ports),
        ],
        dtype=np.float64,
    )


def generate_baseline_training_data(n_samples: int = 600, seed: int = 42) -> np.ndarray:
    """Synthesize realistic baseline normal traffic to fit the initial Isolation Forest."""
    rng = np.random.default_rng(seed)
    rows: list[np.ndarray] = []
    for _ in range(n_samples):
        r = rng.random()
        if r < 0.45:
            # Normal auth_log: mostly successful logins
            auth_fail = rng.random() < 0.06
            rows.append(
                extract_event_features(
                    event_type="auth_log",
                    bytes_out=int(rng.integers(250, 2200)),
                    dest_port=443,
                    auth_success=not auth_fail,
                    recent_rate=int(rng.integers(0, 3)),
                    recent_unique_ports=1,
                )
            )
        elif r < 0.90:
            # Normal network_flow: moderate payload over standard ports
            port = int(rng.choice([80, 443, 22, 8443, 53]))
            rows.append(
                extract_event_features(
                    event_type="network_flow",
                    bytes_out=int(rng.integers(400, 180_000)),
                    dest_port=port,
                    auth_success=None,
                    recent_rate=int(rng.integers(0, 4)),
                    recent_unique_ports=int(rng.integers(1, 3)),
                )
            )
        else:
            # Normal file_hash telemetry
            rows.append(
                extract_event_features(
                    event_type="file_hash",
                    bytes_out=int(rng.integers(1024, 50_000)),
                    dest_port=None,
                    auth_success=None,
                    recent_rate=int(rng.integers(0, 2)),
                    recent_unique_ports=0,
                )
            )
    return np.vstack(rows)


class AnomalyScorer:
    """scikit-learn Isolation Forest wrapper producing normalized [0, 1] anomaly scores."""

    def __init__(self, *, contamination: float = 0.04, random_state: int = 42) -> None:
        self.pipeline = Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "iforest",
                    IsolationForest(
                        n_estimators=100,
                        contamination=contamination,
                        random_state=random_state,
                    ),
                ),
            ]
        )
        self._is_fitted = False
        self.fit_baseline()

    def fit_baseline(self, data: np.ndarray | None = None) -> None:
        train_x = data if data is not None else generate_baseline_training_data()
        self.pipeline.fit(train_x)
        self._is_fitted = True

    def score_features(self, features: np.ndarray) -> tuple[float, bool]:
        """Return (anomaly_score in [0.0, 1.0], is_anomaly)."""
        if not self._is_fitted:
            self.fit_baseline()
        x_2d = features.reshape(1, -1)
        raw_decision = float(self.pipeline.decision_function(x_2d)[0])
        pred = int(self.pipeline.predict(x_2d)[0])
        # decision_function typically ranges around [-0.25, +0.25]:
        # positive for inliers, negative for outliers. Scale by 20 for clean [0, 1] separation.
        prob_anomaly = 1.0 / (1.0 + math.exp(20.0 * raw_decision))
        score = round(min(1.0, max(0.0, prob_anomaly)), 4)
        return score, (pred == -1 or score >= 0.60)
