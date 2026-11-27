"""Differentially private dashboard analytics endpoints."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.db import Alert, PrivacySetting, SecurityEvent, User
from app.models.schemas import (
    DashboardAnalyticsOut,
    EventRateBucketOut,
    RegionStatOut,
    TopSourceStatOut,
)
from app.privacy.differential_privacy import (
    privatize_count,
    privatize_histogram,
    privatize_top_n,
)

router = APIRouter(prefix="/analytics", tags=["analytics"])

DEFAULT_REGIONS = ("us-east", "us-west", "eu-west", "ap-south")
SEVERITIES = ("low", "medium", "high", "critical")


@router.get("/dashboard", response_model=DashboardAnalyticsOut)
def get_dashboard_analytics(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> DashboardAnalyticsOut:
    cfg = db.execute(select(PrivacySetting).where(PrivacySetting.id == 1)).scalar_one_or_none()
    epsilon = cfg.dp_epsilon if cfg is not None else 1.0

    # Sequential composition across 4 independent aggregate panels: each receives epsilon / 4
    panel_eps = max(0.01, epsilon / 4.0)

    total_events = int(db.execute(select(func.count(SecurityEvent.id))).scalar_one())
    total_alerts = int(db.execute(select(func.count(Alert.id))).scalar_one())
    open_alerts = int(
        db.execute(select(func.count(Alert.id)).where(Alert.status != "resolved")).scalar_one()
    )

    region_rows = db.execute(
        select(SecurityEvent.region, func.count(SecurityEvent.id)).group_by(SecurityEvent.region)
    ).all()
    region_counts_raw: dict[str, int] = {r: 0 for r in DEFAULT_REGIONS}
    for region, cnt in region_rows:
        region_counts_raw[str(region)] = int(cnt)
    region_counts_dp = privatize_histogram(region_counts_raw, epsilon=panel_eps)

    source_rows = db.execute(
        select(SecurityEvent.source_ip_token, func.count(SecurityEvent.id))
        .where(SecurityEvent.source_ip_token.is_not(None))
        .group_by(SecurityEvent.source_ip_token)
    ).all()
    source_pairs = [(str(tok), int(cnt)) for tok, cnt in source_rows if tok]
    top_sources_dp = privatize_top_n(source_pairs, top_n=5, epsilon=panel_eps)

    sev_rows = db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    ).all()
    sev_raw: dict[str, int] = {s: 0 for s in SEVERITIES}
    for sev, cnt in sev_rows:
        sev_raw[str(sev)] = int(cnt)
    sev_dp = privatize_histogram(sev_raw, epsilon=panel_eps)

    # Recent 10-minute / 10-bucket telemetry chart
    now = datetime.now(UTC)
    window_start = now - timedelta(minutes=10)
    recent_events = db.execute(
        select(SecurityEvent.timestamp).where(SecurityEvent.timestamp >= window_start)
    ).scalars().all()
    recent_alerts = db.execute(
        select(Alert.created_at).where(Alert.created_at >= window_start)
    ).scalars().all()

    ev_buckets: dict[int, int] = defaultdict(int)
    al_buckets: dict[int, int] = defaultdict(int)
    for ts in recent_events:
        utc_ts = ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)
        idx = min(9, max(0, int((utc_ts - window_start).total_seconds() // 60)))
        ev_buckets[idx] += 1
    for ts in recent_alerts:
        utc_ts = ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)
        idx = min(9, max(0, int((utc_ts - window_start).total_seconds() // 60)))
        al_buckets[idx] += 1

    series = [
        EventRateBucketOut(
            bucket=(window_start + timedelta(minutes=i + 1)).strftime("%H:%M"),
            events=ev_buckets[i],
            alerts=al_buckets[i],
        )
        for i in range(10)
    ]

    return DashboardAnalyticsOut(
        epsilon=round(epsilon, 3),
        mechanism="Laplace",
        total_events_noisy=privatize_count(total_events, panel_eps),
        total_alerts_noisy=privatize_count(total_alerts, panel_eps),
        open_alerts_count=open_alerts,
        region_counts=[
            RegionStatOut(region=reg, noisy_count=cnt)
            for reg, cnt in sorted(region_counts_dp.items())
        ],
        top_sources=[
            TopSourceStatOut(source_ip_token=tok, noisy_count=cnt)
            for tok, cnt in top_sources_dp
        ],
        severity_counts=sev_dp,
        event_rate_series=series,
        privacy_note=(
            f"Aggregate counts are perturbed with Laplace(Delta_f=1, epsilon={epsilon:.2f} "
            "split across 4 panels via sequential composition) and clamped >= 0."
        ),
    )
