"""Pure-Python Ed25519 with Followee-strict verification.

Signing and key derivation follow the pure Ed25519 variant of RFC 8032.
Verification additionally enforces every Followee v1 requirement from
Section 3.3 of the specification:

1. the public key is exactly 32 bytes;
2. the signature is exactly 64 bytes;
3. the public-key encoding and the signature's encoded R point are canonical
   (y < p, and the x sign bit is 0 whenever x = 0);
4. the scalar S is less than the group order L;
5. the public key decodes to a non-identity point in the prime-order
   subgroup;
6. R decodes to a point in the prime-order subgroup; and
7. the uncofactored verification equation [S]B = R + [k]A holds exactly.

This module is written from RFC 8032 directly; it deliberately shares no
code with any other Followee implementation.  Performance is secondary to
clarity and strictness.
"""

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, P)) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)

# Points are extended homogeneous coordinates (X, Y, Z, T) with x = X/Z,
# y = Y/Z, and T = X*Y/Z.
_IDENTITY = (0, 1, 1, 0)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _pt_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * _D % P
    d = 2 * z1 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _pt_mul(scalar: int, point):
    result = _IDENTITY
    while scalar:
        if scalar & 1:
            result = _pt_add(result, point)
        point = _pt_add(point, point)
        scalar >>= 1
    return result


def _pt_equal(p, q) -> bool:
    return (
        (p[0] * q[2] - q[0] * p[2]) % P == 0
        and (p[1] * q[2] - q[1] * p[2]) % P == 0
    )


def _is_identity(point) -> bool:
    return _pt_equal(point, _IDENTITY)


def _decompress(encoded: bytes):
    """Decode a canonical point encoding; return None on any failure.

    Rejects y >= p and the non-canonical encoding of x = 0 with sign bit 1
    (RFC 8032 Section 5.1.3 decoding, which is inherently canonical-strict).
    """
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= P:
        return None
    u = (y * y - 1) % P
    v = (_D * y * y + 1) % P
    x = u * pow(v, 3, P) % P * pow(u * pow(v, 7, P) % P, (P - 5) // 8, P) % P
    vx2 = v * x % P * x % P
    if vx2 == u:
        pass
    elif vx2 == (P - u) % P:
        x = x * _SQRT_M1 % P
    else:
        return None
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def _compress(point) -> bytes:
    x, y, z, _ = point
    z_inv = pow(z, -1, P)
    x = x * z_inv % P
    y = y * z_inv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_BASE = _decompress((4 * pow(5, -1, P) % P).to_bytes(32, "little"))
assert _BASE is not None


def _secret_expand(seed: bytes):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = _sha512(seed)
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key_from_seed(seed: bytes) -> bytes:
    scalar, _ = _secret_expand(seed)
    return _compress(_pt_mul(scalar, _BASE))


def sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _secret_expand(seed)
    public = _compress(_pt_mul(scalar, _BASE))
    r = int.from_bytes(_sha512(prefix + message), "little") % L
    r_encoded = _compress(_pt_mul(r, _BASE))
    k = int.from_bytes(_sha512(r_encoded + public + message), "little") % L
    s = (r + k * scalar) % L
    return r_encoded + s.to_bytes(32, "little")


def verify_strict(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Followee-strict Ed25519 verification.  Returns True iff every check
    in Section 3.3 passes."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    public_key = bytes(public_key)
    signature = bytes(signature)

    a_point = _decompress(public_key)
    if a_point is None:
        return False
    if _is_identity(a_point):
        return False
    if not _is_identity(_pt_mul(L, a_point)):
        return False

    r_encoded = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    r_point = _decompress(r_encoded)
    if r_point is None:
        return False
    if not _is_identity(_pt_mul(L, r_point)):
        return False

    k = int.from_bytes(_sha512(r_encoded + public_key + message), "little") % L
    lhs = _pt_mul(s, _BASE)
    rhs = _pt_add(r_point, _pt_mul(k, a_point))
    return _pt_equal(lhs, rhs)
