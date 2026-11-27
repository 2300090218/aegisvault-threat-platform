"""ECDH-based Private Set Intersection (PSI) over NIST P-256 (secp256r1).

Protocol overview:
1. Both parties share a deterministic hash-to-curve function H: {0,1}* -> E(Fp).
2. Client picks random ephemeral scalar `a` in [1, n-1], computes A_i = a * H(x_i),
   and sends compressed points {A_i} to the server.
3. Server holds secret scalar `b` in [1, n-1], verifies every A_i is a valid curve
   point (not identity), computes double-blinded hashes H_tag(b * A_i), and computes
   shuffled server-blinded points {b * H(y_j)} for its threat-intel set {y_j}.
4. Client multiplies each server point S_j by `a` to get H_tag(a * S_j) and checks
   intersection with H_tag(b * A_i). Because a*(b*P) == b*(a*P), matching items share
   the exact same tag while neither party reveals non-intersecting elements.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

# NIST P-256 (secp256r1) domain parameters
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = (P256_P - 3) % P256_P
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

Point = tuple[int, int] | None  # None represents point at infinity


def is_on_curve(pt: Point) -> bool:
    """Return True if pt is a valid non-infinity point on NIST P-256."""
    if pt is None:
        return False
    x, y = pt
    if not (0 <= x < P256_P and 0 <= y < P256_P):
        return False
    return (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P == 0


def point_add(p1: Point, p2: Point) -> Point:
    """Add two points on NIST P-256."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P256_P == 0:
            return None
        lam = ((3 * x1 * x1 + P256_A) * pow((2 * y1) % P256_P, P256_P - 2, P256_P)) % P256_P
    else:
        lam = ((y2 - y1) * pow((x2 - x1) % P256_P, P256_P - 2, P256_P)) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def scalar_mult(k: int, pt: Point) -> Point:
    """Compute k * pt on P-256 using double-and-add."""
    k = k % P256_N
    if k == 0 or pt is None:
        return None
    result: Point = None
    addend: Point = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def compress_point(pt: Point) -> str:
    """Encode a P-256 point in compressed SEC1 hex format (66 hex chars)."""
    if pt is None or not is_on_curve(pt):
        raise ValueError("Cannot compress point at infinity or off-curve point")
    x, y = pt
    prefix = "02" if (y & 1) == 0 else "03"
    return prefix + x.to_bytes(32, "big").hex()


def decompress_point(hex_str: str) -> tuple[int, int]:
    """Decode a compressed SEC1 hex point and validate it lies on P-256."""
    cleaned = hex_str.strip().lower()
    if len(cleaned) != 66 or cleaned[:2] not in ("02", "03"):
        raise ValueError("Point must be a 33-byte SEC1 compressed hex string")
    raw = bytes.fromhex(cleaned)
    parity = raw[0] & 1
    x = int.from_bytes(raw[1:], "big")
    if x >= P256_P:
        raise ValueError("Point x-coordinate out of field range")
    rhs = (x * x * x + P256_A * x + P256_B) % P256_P
    if pow(rhs, (P256_P - 1) // 2, P256_P) != 1:
        raise ValueError("Point does not lie on P-256")
    # Since P256_P % 4 == 3, modular square root is rhs^((p+1)//4) mod p
    y = pow(rhs, (P256_P + 1) // 4, P256_P)
    if (y & 1) != parity:
        y = P256_P - y
    pt = (x, y)
    if not is_on_curve(pt):
        raise ValueError("Decompressed point failed curve validation")
    return pt


def hash_to_curve(item: str) -> tuple[int, int]:
    """Deterministic try-and-increment hash-to-curve H(item) -> P-256 point."""
    normalized = item.strip().lower().encode("utf-8")
    for counter in range(256):
        digest = hashlib.sha256(b"PSI-P256-H2C:" + normalized + bytes([counter])).digest()
        x = int.from_bytes(digest, "big") % P256_P
        rhs = (x * x * x + P256_A * x + P256_B) % P256_P
        if pow(rhs, (P256_P - 1) // 2, P256_P) == 1:
            y = pow(rhs, (P256_P + 1) // 4, P256_P)
            if (y & 1) == 1:
                y = P256_P - y
            pt = (x, y)
            if is_on_curve(pt):
                return pt
    raise RuntimeError("Hash-to-curve failed to locate a valid P-256 point")


def tag_point(pt: Point) -> str:
    """Hash a double-blinded curve point into an intersection comparison tag."""
    return hashlib.sha256(b"PSI-TAG:" + compress_point(pt).encode("ascii")).hexdigest()


def derive_server_scalar(master_key: bytes, epoch_salt: str = "psi-v1") -> int:
    """Derive a valid non-zero scalar b in [1, P256_N - 1] from master_key."""
    digest = hmac.new(master_key, f"ecdh-psi:{epoch_salt}".encode(), hashlib.sha256).digest()
    return (int.from_bytes(digest, "big") % (P256_N - 1)) + 1


@dataclass(frozen=True)
class PsiServerResult:
    double_blinded_client_hashes: list[str]
    server_blinded_points: list[str]
    server_set_size: int


class PsiServer:
    """Server-side ECDH-PSI evaluator for threat-intelligence hashes."""

    def __init__(self, server_scalar: int) -> None:
        if not (1 <= server_scalar < P256_N):
            raise ValueError("Invalid P-256 server scalar")
        self.server_scalar = server_scalar

    def evaluate(
        self,
        *,
        client_blinded_points: list[str],
        server_items: list[str],
    ) -> PsiServerResult:
        double_blinded_hashes: list[str] = []
        for pt_hex in client_blinded_points:
            client_pt = decompress_point(pt_hex)
            double_blinded = scalar_mult(self.server_scalar, client_pt)
            double_blinded_hashes.append(tag_point(double_blinded))

        server_points: list[str] = []
        for item in server_items:
            base_pt = hash_to_curve(item)
            blinded_pt = scalar_mult(self.server_scalar, base_pt)
            server_points.append(compress_point(blinded_pt))

        secrets.SystemRandom().shuffle(server_points)
        return PsiServerResult(
            double_blinded_client_hashes=double_blinded_hashes,
            server_blinded_points=server_points,
            server_set_size=len(server_points),
        )


class PsiClient:
    """Client-side helper for blinding candidate hashes and matching PSI responses."""

    def __init__(self, scalar: int | None = None) -> None:
        self.scalar = scalar if scalar is not None else (secrets.randbelow(P256_N - 1) + 1)

    def blind_items(self, items: list[str]) -> list[str]:
        return [compress_point(scalar_mult(self.scalar, hash_to_curve(item))) for item in items]

    def find_matches(
        self,
        *,
        candidate_items: list[str],
        double_blinded_client_hashes: list[str],
        server_blinded_points: list[str],
    ) -> list[str]:
        if len(candidate_items) != len(double_blinded_client_hashes):
            raise ValueError("Mismatched candidate items and double-blinded hashes length")

        server_tags = {
            tag_point(scalar_mult(self.scalar, decompress_point(pt_hex)))
            for pt_hex in server_blinded_points
        }
        return [
            item
            for item, tag in zip(candidate_items, double_blinded_client_hashes, strict=True)
            if tag in server_tags
        ]
