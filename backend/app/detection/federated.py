"""Federated Learning (FedAvg) simulator across 3 virtual security organizations.

Each organization holds private non-IID event feature tensors locally and trains a local
scikit-learn SGDClassifier (logistic anomaly detector). Only model parameter updates
(weights + bias + sample count) are transmitted to the central aggregator, which computes
sample-weighted Federated Averaging (FedAvg) and evaluates the global model.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, log_loss
from sklearn.preprocessing import StandardScaler
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models.db import FederatedRound
from app.models.schemas import FederatedRoundOut, FederatedStatusOut, OrgRoundMetric

CLASSES = np.array([0, 1], dtype=np.int64)
FEATURE_DIM = 7


@dataclass(frozen=True)
class VirtualOrgDataset:
    org_id: str
    org_name: str
    features: np.ndarray
    labels: np.ndarray


def _synthesize_org_samples(
    *,
    n_normal: int,
    n_attack: int,
    bias_profile: str,
    seed: int,
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    x_list: list[np.ndarray] = []
    y_list: list[int] = []

    for _ in range(n_normal):
        x_list.append(
            np.array(
                [
                    float(rng.choice([0.0, 1.0])),
                    float(rng.uniform(5.5, 11.2)),
                    float(rng.choice([80, 443, 22, 8443]) / 65535.0),
                    0.0,
                    1.0 if rng.random() < 0.05 else 0.0,
                    float(rng.integers(0, 4)),
                    float(rng.integers(1, 3)),
                ],
                dtype=np.float64,
            )
        )
        y_list.append(0)

    for _ in range(n_attack):
        if bias_profile == "fintech_auth":
            # Heavy brute force & failed logins
            x_list.append(
                np.array(
                    [
                        0.0,
                        float(rng.uniform(5.0, 7.5)),
                        443.0 / 65535.0,
                        0.0,
                        1.0,
                        float(rng.integers(6, 20)),
                        1.0,
                    ],
                    dtype=np.float64,
                )
            )
        elif bias_profile == "healthcare_exfil":
            # Heavy outbound data exfiltration
            x_list.append(
                np.array(
                    [
                        1.0,
                        float(rng.uniform(16.2, 18.5)),
                        float(rng.choice([4444, 8443, 9001]) / 65535.0),
                        1.0,
                        0.0,
                        float(rng.integers(2, 8)),
                        float(rng.integers(1, 3)),
                    ],
                    dtype=np.float64,
                )
            )
        else:
            # SaaS edge: heavy port scanning
            x_list.append(
                np.array(
                    [
                        1.0,
                        float(rng.uniform(4.5, 8.0)),
                        float(rng.integers(1024, 65000) / 65535.0),
                        1.0,
                        0.0,
                        float(rng.integers(8, 30)),
                        float(rng.integers(9, 25)),
                    ],
                    dtype=np.float64,
                )
            )
        y_list.append(1)

    x = np.vstack(x_list)
    y = np.array(y_list, dtype=np.int64)
    perm = rng.permutation(len(y))
    return x[perm], y[perm]


def build_federated_datasets() -> tuple[list[VirtualOrgDataset], np.ndarray, np.ndarray, StandardScaler]:
    """Construct 3 non-IID organizational datasets plus a shared global evaluation set."""
    orgs_raw = [
        ("org_alpha", "Org-Alpha (FinTech)", *_synthesize_org_samples(n_normal=220, n_attack=80, bias_profile="fintech_auth", seed=101)),
        ("org_beta", "Org-Beta (HealthCare)", *_synthesize_org_samples(n_normal=180, n_attack=70, bias_profile="healthcare_exfil", seed=202)),
        ("org_gamma", "Org-Gamma (CloudSaaS)", *_synthesize_org_samples(n_normal=200, n_attack=90, bias_profile="saas_scan", seed=303)),
    ]

    # Global test set blends all 3 attack profiles equally
    tx1, ty1 = _synthesize_org_samples(n_normal=60, n_attack=25, bias_profile="fintech_auth", seed=901)
    tx2, ty2 = _synthesize_org_samples(n_normal=60, n_attack=25, bias_profile="healthcare_exfil", seed=902)
    tx3, ty3 = _synthesize_org_samples(n_normal=60, n_attack=25, bias_profile="saas_scan", seed=903)
    test_x_raw = np.vstack([tx1, tx2, tx3])
    test_y = np.concatenate([ty1, ty2, ty3])

    scaler = StandardScaler()
    all_train = np.vstack([o[2] for o in orgs_raw])
    scaler.fit(all_train)

    orgs = [
        VirtualOrgDataset(
            org_id=oid,
            org_name=name,
            features=scaler.transform(fx),
            labels=fy,
        )
        for oid, name, fx, fy in orgs_raw
    ]
    return orgs, scaler.transform(test_x_raw), test_y, scaler


def _new_local_classifier(coef: np.ndarray, intercept: np.ndarray, seed: int) -> SGDClassifier:
    clf = SGDClassifier(
        loss="log_loss",
        penalty="l2",
        alpha=0.001,
        learning_rate="constant",
        eta0=0.04,
        random_state=seed,
    )
    # Initialize internal sklearn shape cleanly via a 2-sample dummy fit, then overwrite weights
    clf.partial_fit(np.zeros((2, FEATURE_DIM)), np.array([0, 1]), classes=CLASSES)
    clf.coef_ = coef.copy()
    clf.intercept_ = intercept.copy()
    return clf


class FederatedSimulator:
    """Executes FedAvg training rounds across 3 virtual organizations without sharing raw data."""

    def __init__(self) -> None:
        self.orgs, self.test_x, self.test_y, _ = build_federated_datasets()

    def _evaluate(self, coef: np.ndarray, intercept: np.ndarray, x: np.ndarray, y: np.ndarray) -> tuple[float, float]:
        clf = _new_local_classifier(coef, intercept, seed=42)
        preds = clf.predict(x)
        probs = np.clip(clf.predict_proba(x), 1e-6, 1.0 - 1e-6)
        acc = round(float(accuracy_score(y, preds)), 4)
        loss = round(float(log_loss(y, probs, labels=CLASSES)), 4)
        return acc, loss

    def run_rounds(
        self,
        db: Session,
        *,
        rounds: int = 1,
        local_epochs: int = 3,
    ) -> FederatedStatusOut:
        latest = db.execute(
            select(FederatedRound).order_by(FederatedRound.round_number.desc()).limit(1)
        ).scalar_one_or_none()

        if latest is None:
            current_round = 0
            rng = np.random.default_rng(7)
            global_coef = rng.normal(0.0, 0.05, size=(1, FEATURE_DIM))
            global_intercept = np.zeros((1,), dtype=np.float64)
        else:
            current_round = latest.round_number
            global_coef = np.array(latest.model_weights["coef"], dtype=np.float64)
            global_intercept = np.array(latest.model_weights["intercept"], dtype=np.float64)

        for r_idx in range(rounds):
            round_num = current_round + r_idx + 1
            local_updates: list[tuple[np.ndarray, np.ndarray, int]] = []
            org_metrics: list[dict] = []

            for org_idx, org in enumerate(self.orgs):
                clf = _new_local_classifier(global_coef, global_intercept, seed=1000 + round_num * 10 + org_idx)
                rng = np.random.default_rng(round_num * 100 + org_idx)
                for _ in range(local_epochs):
                    perm = rng.permutation(len(org.labels))
                    clf.partial_fit(org.features[perm], org.labels[perm], classes=CLASSES)

                l_acc, l_loss = self._evaluate(clf.coef_, clf.intercept_, org.features, org.labels)
                n_samples = len(org.labels)
                local_updates.append((clf.coef_.copy(), clf.intercept_.copy(), n_samples))
                org_metrics.append(
                    OrgRoundMetric(
                        org_id=org.org_id,
                        org_name=org.org_name,
                        sample_count=n_samples,
                        local_accuracy=l_acc,
                        local_loss=l_loss,
                    ).model_dump()
                )

            # Sample-weighted FedAvg aggregation (only weights leave each organization)
            total_samples = sum(n for _, _, n in local_updates)
            global_coef = sum((n / total_samples) * w for w, _, n in local_updates)
            global_intercept = sum((n / total_samples) * b for _, b, n in local_updates)

            g_acc, g_loss = self._evaluate(global_coef, global_intercept, self.test_x, self.test_y)
            db.add(
                FederatedRound(
                    round_number=round_num,
                    global_accuracy=g_acc,
                    global_loss=g_loss,
                    org_metrics=org_metrics,
                    model_weights={
                        "coef": global_coef.tolist(),
                        "intercept": global_intercept.tolist(),
                    },
                )
            )
            db.flush()

        return self.get_status(db)

    def get_status(self, db: Session) -> FederatedStatusOut:
        rows = db.execute(select(FederatedRound).order_by(FederatedRound.round_number.asc())).scalars().all()
        if not rows:
            rng = np.random.default_rng(7)
            init_coef = rng.normal(0.0, 0.05, size=(1, FEATURE_DIM))
            init_intercept = np.zeros((1,), dtype=np.float64)
            init_acc, init_loss = self._evaluate(init_coef, init_intercept, self.test_x, self.test_y)
            return FederatedStatusOut(
                current_round=0,
                global_accuracy=init_acc,
                global_loss=init_loss,
                rounds=[],
            )

        out_rounds = [
            FederatedRoundOut(
                round_number=r.round_number,
                global_accuracy=r.global_accuracy,
                global_loss=r.global_loss,
                org_metrics=[OrgRoundMetric(**m) for m in r.org_metrics],
                created_at=r.created_at,
            )
            for r in rows
        ]
        latest = out_rounds[-1]
        return FederatedStatusOut(
            current_round=latest.round_number,
            global_accuracy=latest.global_accuracy,
            global_loss=latest.global_loss,
            rounds=out_rounds,
        )

    def reset(self, db: Session) -> FederatedStatusOut:
        db.execute(delete(FederatedRound))
        db.flush()
        return self.get_status(db)
