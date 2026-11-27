"""Laplace differential privacy mechanism for aggregate threat analytics."""

from __future__ import annotations

import math
import secrets
from collections.abc import Callable

_sysrand = secrets.SystemRandom()


def sample_laplace(scale: float, rng: Callable[[float, float], float] | None = None) -> float:
    """Sample from Laplace(0, scale) using inverse-CDF with CSPRNG."""
    if scale < 0:
        raise ValueError("Laplace scale must be non-negative")
    if scale == 0:
        return 0.0
    uniform_fn = rng or _sysrand.uniform
    # Avoid exact +/-0.5 to prevent log(0)
    u = uniform_fn(-0.499999999999, 0.499999999999)
    return -scale * math.copysign(1.0, u) * math.log(1.0 - 2.0 * abs(u))


def privatize_count(
    true_count: int,
    epsilon: float,
    *,
    sensitivity: float = 1.0,
    clamp_non_negative: bool = True,
) -> int:
    """Apply Laplace(sensitivity / epsilon) noise to an integer count."""
    if epsilon <= 0:
        raise ValueError("epsilon must be strictly positive")
    if sensitivity < 0:
        raise ValueError("sensitivity must be non-negative")
    scale = sensitivity / epsilon
    noisy = true_count + sample_laplace(scale)
    rounded = int(round(noisy))
    return max(0, rounded) if clamp_non_negative else rounded


def privatize_histogram(
    counts: dict[str, int],
    epsilon: float,
    *,
    sensitivity: float = 1.0,
) -> dict[str, int]:
    """Privatize disjoint histogram buckets (parallel composition preserves epsilon-DP)."""
    if epsilon <= 0:
        raise ValueError("epsilon must be strictly positive")
    return {
        bucket: privatize_count(val, epsilon, sensitivity=sensitivity, clamp_non_negative=True)
        for bucket, val in counts.items()
    }


def privatize_top_n(
    source_counts: list[tuple[str, int]],
    *,
    top_n: int,
    epsilon: float,
    sensitivity: float = 1.0,
) -> list[tuple[str, int]]:
    """Apply Laplace noise to each source count, sort by noisy count, and return top N."""
    if epsilon <= 0:
        raise ValueError("epsilon must be strictly positive")
    if top_n <= 0 or not source_counts:
        return []
    noised = [
        (key, privatize_count(cnt, epsilon, sensitivity=sensitivity, clamp_non_negative=True))
        for key, cnt in source_counts
    ]
    noised.sort(key=lambda item: item[1], reverse=True)
    return noised[:top_n]
