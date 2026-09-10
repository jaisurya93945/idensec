"""Minimal Ed25519 signature verification, RFC 8032, standard library only.

Present so that ``tools/verify_commits.py`` runs anywhere Python does, with no
install step and no third-party code in the path of a security check. Verifying
a commit signature should not itself require trusting a dependency tree.

Verification only -- there is no key generation and no signing here, and there
should not be. This code is not constant-time, which is irrelevant for
verification (it handles only public inputs) and would be disqualifying for
signing.
"""

from __future__ import annotations

import hashlib

__all__ = ["verify"]

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

# Base point.
_BY = 4 * pow(5, P - 2, P) % P
_BX = 0  # filled in below by recovering x from y


def _recover_x(y: int, sign: int) -> int | None:
    """Recover the x coordinate of a curve point from y and a sign bit."""
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if x % 2 != sign:
        x = P - x
    return x


_BX = _recover_x(_BY, 0) or 0
BASE = (_BX, _BY, 1, _BX * _BY % P)
IDENTITY = (0, 1, 1, 0)

Point = tuple[int, int, int, int]


def _add(p: Point, q: Point) -> Point:
    """Extended twisted Edwards addition (RFC 8032 section 5.1.4)."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar: int, point: Point) -> Point:
    result = IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p: Point, q: Point) -> bool:
    """Projective coordinates are not unique; compare cross-multiplied."""
    if (p[0] * q[2] - q[0] * p[2]) % P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % P == 0


def _decode_point(data: bytes) -> Point | None:
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Return True if ``signature`` is a valid Ed25519 signature over ``message``."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    point_a = _decode_point(public_key)
    if point_a is None:
        return False
    point_r = _decode_point(signature[:32])
    if point_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        # Non-canonical scalar. Rejecting this is what stops trivial signature
        # malleability.
        return False
    k = (
        int.from_bytes(
            hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
        )
        % L
    )
    return _equal(_mul(s, BASE), _add(point_r, _mul(k, point_a)))
