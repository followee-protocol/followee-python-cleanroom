"""Record construction and signing (Sections 4.4, 5.1, 5.3, 6.2).

These helpers exist so tests and the Appendix B reproduction can build
records from structured input; they are the signer side of the model.
"""

from typing import Optional

from . import cose, detcbor, ed25519
from .record import AUTHORITY_ROOT, AUTHORITY_ROOT_REVOKED, UINT64_MAX


def build_record_body(
    did: str,
    timestamp_ms: int,
    authority: int,
    descriptor_obj: dict,
    contact: dict,
    revocation_key_obj: Optional[dict] = None,
    valid_until_ms: Optional[int] = None,
    extensions: Optional[dict] = None,
) -> dict:
    """Assemble a v1 record-body map (Section 5.1)."""
    body = {
        0: 1,
        1: did,
        2: timestamp_ms,
        3: authority,
        4: descriptor_obj,
        7: contact,
    }
    if authority == AUTHORITY_ROOT_REVOKED:
        if revocation_key_obj is None:
            raise ValueError("root-revoked record requires the revocation key")
        body[5] = revocation_key_obj
    elif authority == AUTHORITY_ROOT:
        if revocation_key_obj is not None:
            raise ValueError("root record must not carry the revocation key")
    else:
        raise ValueError("authority must be 0 or 1")
    if valid_until_ms is not None:
        body[6] = valid_until_ms
    if extensions is not None:
        body[8] = extensions
    return body


def encode_record_body(body: dict) -> bytes:
    return detcbor.encode(body)


def sign_record_body(record_body_bytes: bytes, seed: bytes) -> bytes:
    """Sign exact deterministic record-body bytes; return the complete
    tagged COSE envelope."""
    signature = ed25519.sign(seed, cose.sig_structure(record_body_bytes))
    return cose.build_envelope(record_body_bytes, signature)


def next_timestamp(now_ms: int, previous_ms: Optional[int] = None) -> int:
    """Signer timestamp algorithm (Section 5.3) with checked arithmetic.

    ``previous_ms`` is the greatest non-premature timestamp known to the
    signer; the caller must already have excluded timestamps that lead its
    trusted clock.
    """
    if not 0 <= now_ms <= UINT64_MAX:
        raise ValueError("now_ms out of uint64 range")
    if previous_ms is None:
        return now_ms
    if not 0 <= previous_ms <= UINT64_MAX:
        raise ValueError("previous_ms out of uint64 range")
    candidate = previous_ms + 1  # checked: must still fit uint64
    if candidate > UINT64_MAX:
        raise OverflowError("timestamp space exhausted")
    return max(now_ms, candidate)
