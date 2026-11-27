"""Unit tests for Laplace differential privacy mechanism."""

from __future__ import annotations

import statistics

import pytest

from app.privacy.differential_privacy import (
    privatize_count,
    privatize_histogram,
    privatize_top_n,
    sample_laplace,
)


def test_laplace_distribution_mean_and_variance() -> None:
    scale = 2.0
    samples = [sample_laplace(scale) for _ in range(4000)]
    mean = statistics.mean(samples)
    var = statistics.variance(samples)
    # Theoretical mean = 0, theoretical variance = 2 * scale^2 = 8.0
    assert abs(mean) < 0.25
    assert 6.5 < var < 9.5

    assert sample_laplace(0.0) == 0.0
    with pytest.raises(ValueError):
        sample_laplace(-1.0)


def test_privatize_count_and_histogram() -> None:
    true_hist = {"us-east": 1000, "eu-west": 500, "ap-south": 250}
    noisy_high_eps = privatize_histogram(true_hist, epsilon=5.0)
    assert set(noisy_high_eps.keys()) == set(true_hist.keys())
    for k, val in true_hist.items():
        assert noisy_high_eps[k] >= 0
        assert abs(noisy_high_eps[k] - val) < 25

    # Clamping prevents negative counts for small true counts with high noise
    for _ in range(50):
        assert privatize_count(0, epsilon=0.1, clamp_non_negative=True) >= 0

    with pytest.raises(ValueError):
        privatize_count(10, epsilon=0.0)
    with pytest.raises(ValueError):
        privatize_count(10, epsilon=1.0, sensitivity=-1.0)
    with pytest.raises(ValueError):
        privatize_histogram(true_hist, epsilon=-0.5)


def test_privatize_top_n() -> None:
    sources = [("ip_kv1_a", 500), ("ip_kv1_b", 200), ("ip_kv1_c", 50), ("ip_kv1_d", 10)]
    top2 = privatize_top_n(sources, top_n=2, epsilon=4.0)
    assert len(top2) == 2
    assert top2[0][1] >= top2[1][1]
    assert top2[0][0] == "ip_kv1_a"
    assert privatize_top_n(sources, top_n=0, epsilon=1.0) == []
    assert privatize_top_n([], top_n=5, epsilon=1.0) == []
    with pytest.raises(ValueError):
        privatize_top_n(sources, top_n=2, epsilon=0.0)
