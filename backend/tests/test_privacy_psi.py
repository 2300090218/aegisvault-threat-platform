"""Unit tests for ECDH P-256 Private Set Intersection."""

from __future__ import annotations

import secrets

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.privacy.psi import (
    P256_N,
    PsiClient,
    PsiServer,
    compress_point,
    decompress_point,
    derive_server_scalar,
    hash_to_curve,
    is_on_curve,
    point_add,
    scalar_mult,
)


def test_p256_scalar_mult_matches_cryptography_library() -> None:
    priv = ec.generate_private_key(ec.SECP256R1())
    k = priv.private_numbers().private_value
    expected_compressed = priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    ).hex()

    # Standard NIST P-256 generator G
    gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    g = (gx, gy)
    assert is_on_curve(g)

    computed = scalar_mult(k, g)
    assert compress_point(computed) == expected_compressed
    assert decompress_point(expected_compressed) == computed
    assert point_add(computed, None) == computed
    assert point_add(None, computed) == computed
    assert point_add(computed, (computed[0], (-computed[1]) % 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF)) is None


def test_ecdh_psi_exact_intersection_without_exposing_non_matches() -> None:
    threat_intel = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "deadbeef" * 8,
        "cafebabe" * 8,
        "12345678" * 8,
    ]
    client_queries = [
        "00000000" * 8,
        "DEADBEEF" * 8,  # case-insensitive match
        "ffffffff" * 8,
        "cafebabe" * 8,
    ]

    server_scalar = derive_server_scalar(secrets.token_bytes(32))
    server = PsiServer(server_scalar)
    client = PsiClient()

    blinded = client.blind_items(client_queries)
    # Blinded points should not equal raw hashes or plain hash-to-curve points
    for q, b in zip(client_queries, blinded, strict=True):
        assert b != compress_point(hash_to_curve(q))

    res = server.evaluate(client_blinded_points=blinded, server_items=threat_intel)
    assert res.server_set_size == len(threat_intel)

    matches = client.find_matches(
        candidate_items=client_queries,
        double_blinded_client_hashes=res.double_blinded_client_hashes,
        server_blinded_points=res.server_blinded_points,
    )
    assert matches == ["DEADBEEF" * 8, "cafebabe" * 8]


def test_psi_rejects_invalid_curve_points() -> None:
    server = PsiServer(123456789)
    # x >= P256_P is out of field range
    with pytest.raises(ValueError, match="field range"):
        server.evaluate(client_blinded_points=["02" + "ff" * 32], server_items=["abc"])
    # Find an x value that is a quadratic non-residue mod P256_P
    non_residue_hex = "02" + (4).to_bytes(32, "big").hex()
    with pytest.raises(ValueError):
        decompress_point(non_residue_hex)
    with pytest.raises(ValueError):
        decompress_point("04" + "11" * 32)
    with pytest.raises(ValueError):
        PsiServer(P256_N)
    with pytest.raises(ValueError):
        compress_point(None)
