"""Full-record verification algorithm (Section 8.1).

``verify_full_record`` performs steps 1-18 and 20 of Section 8.1 in the
listed order and either returns a :class:`VerifiedRecord` or raises
:class:`FolloweeError` with the symbolic code of the first failing step.
Step 17 (premature) and step 20 (stale) are classifications carried on the
returned record; step 19 (sticky authority-state exclusion and ordering)
is applied by :mod:`followee_model.selection`.
"""

import hashlib
from dataclasses import dataclass
from typing import Optional

from . import cose, descriptor, detcbor, did as did_module, record
from .errors import ErrorCode, FolloweeError

#: Hard maximum for a complete tagged COSE Identity Record (Section 15.1).
MAX_RECORD_BYTES = 16 * 1024

#: v1 future bound constant (Section 5.4).
MAX_FUTURE_SKEW_MS = 300_000


def is_premature(timestamp_ms: int, now_ms: int) -> bool:
    """Section 5.4 recipient check.  Python integers are unbounded, so the
    comparison is inherently overflow-safe."""
    return timestamp_ms > now_ms + MAX_FUTURE_SKEW_MS


@dataclass
class VerifiedRecord:
    """A schema-conforming, descriptor-bound, signature-valid record."""

    target: str
    envelope_bytes: bytes
    body_bytes: bytes
    body_digest: bytes
    timestamp_ms: int
    authority: int
    descriptor: dict
    root_public_key: bytes
    revocation_commitment: bytes
    revocation_public_key: Optional[bytes]
    signing_public_key: bytes
    valid_until_ms: Optional[int]
    contact: dict
    extensions: Optional[dict]
    premature: bool
    stale: bool


def verify_full_record(
    target: str, envelope_bytes: bytes, now_ms: int
) -> VerifiedRecord:
    envelope_bytes = bytes(envelope_bytes)

    # Step 1: hard size limit before any allocation from declared lengths.
    if len(envelope_bytes) > MAX_RECORD_BYTES:
        raise FolloweeError(
            ErrorCode.RECORD_TOO_LARGE,
            f"envelope is {len(envelope_bytes)} bytes, cap {MAX_RECORD_BYTES}",
        )

    # Steps 2-3: exactly one tagged COSE Sign1 object with the exact profile.
    envelope = cose.parse_envelope(envelope_bytes)

    # Step 4: one deterministic record-body item, no trailing bytes.  The
    # record-body depth and aggregate member limits apply here.
    body = detcbor.decode(
        envelope.payload,
        max_depth=record.MAX_RECORD_BODY_DEPTH,
        max_members=record.MAX_RECORD_BODY_MEMBERS,
    )

    # Deterministic self-check: the strict decoder must reproduce the exact
    # received bytes.  A mismatch indicates a model bug, never valid input.
    if detcbor.encode(body) != envelope.payload:
        raise FolloweeError(
            ErrorCode.INTERNAL_ERROR, "decoder failed byte-exact round trip"
        )

    # Step 5: protocolVersion = 1 and the v1 top-level schema.
    record.validate_record_body(body)

    # Step 6: parse the target DID (invalidDid / unsupportedHash).
    target_digest = did_module.parse_did(target)

    # Step 7: signed body id must equal the target byte for byte.
    if body[1] != target:
        raise FolloweeError(
            ErrorCode.IDENTITY_BINDING_MISMATCH,
            "body id does not equal the target DID",
        )

    # Step 8: Authority Descriptor schema (deterministic encoding is already
    # guaranteed by the strict payload decode).
    root_public_key, revocation_commitment = descriptor.validate_descriptor(
        body[4]
    )

    # Step 9: independently recompute the descriptor digest and require it to
    # reproduce the target.
    if descriptor.descriptor_digest(body[4]) != target_digest:
        raise FolloweeError(
            ErrorCode.IDENTITY_BINDING_MISMATCH,
            "authority descriptor does not derive the target DID",
        )

    # Step 10: authority-dependent presence of the revealed revocation key.
    authority = body[3]
    if authority == record.AUTHORITY_ROOT and 5 in body:
        raise FolloweeError(
            ErrorCode.SCHEMA_VIOLATION,
            "root record must not contain label 5 (revocationKey)",
        )
    if authority == record.AUTHORITY_ROOT_REVOKED and 5 not in body:
        raise FolloweeError(
            ErrorCode.SCHEMA_VIOLATION,
            "root-revoked record must contain label 5 (revocationKey)",
        )

    # Steps 11-12: select the signing key; for a revoked record, recompute
    # and require the revocation-key commitment.
    revocation_public_key: Optional[bytes] = None
    if authority == record.AUTHORITY_ROOT:
        signing_public_key = root_public_key
    else:
        revocation_public_key = descriptor.validate_public_key(
            body[5],
            suite_error=ErrorCode.INVALID_REVOCATION_KEY,
            size_error=ErrorCode.INVALID_REVOCATION_KEY,
        )
        if descriptor.revocation_commitment(body[5]) != revocation_commitment:
            raise FolloweeError(
                ErrorCode.INVALID_REVOCATION_KEY,
                "revealed key does not reproduce the descriptor commitment",
            )
        signing_public_key = revocation_public_key

    # Step 13: selected key suite must equal the protected COSE algorithm.
    # Both are pinned to -19 by the checks above; assert the invariant.
    if descriptor.SUITE_ED25519 != cose.SUITE_ED25519:  # pragma: no cover
        raise FolloweeError(ErrorCode.INTERNAL_ERROR, "suite constants diverge")

    # Step 14: strict Ed25519 over the COSE Sig_structure built from the
    # exact received payload bytes.
    from . import ed25519

    if not ed25519.verify_strict(
        signing_public_key,
        cose.sig_structure(envelope.payload),
        envelope.signature,
    ):
        raise FolloweeError(
            ErrorCode.INVALID_SIGNATURE, "strict Ed25519 verification failed"
        )

    # Step 15: Contact Document, record extensions, and aggregate limits.
    record.validate_contact(body[7], own_did=target)
    if 8 in body:
        record.validate_extension_map(body[8], "record.extensions")

    # Step 16: optional validity horizon relation.
    timestamp_ms = body[2]
    valid_until_ms = body.get(6)
    if valid_until_ms is not None and valid_until_ms < timestamp_ms:
        raise FolloweeError(
            ErrorCode.SCHEMA_VIOLATION, "validUntil_ms is less than timestamp_ms"
        )

    # Step 17: premature or time-admissible under the recipient clock.
    premature = is_premature(timestamp_ms, now_ms)

    # Step 18: body digest over the received payload bytes.
    body_digest = hashlib.sha256(envelope.payload).digest()

    # Step 20: fresh or stale (staleness never affects authenticity).
    stale = valid_until_ms is not None and now_ms > valid_until_ms

    return VerifiedRecord(
        target=target,
        envelope_bytes=envelope_bytes,
        body_bytes=envelope.payload,
        body_digest=body_digest,
        timestamp_ms=timestamp_ms,
        authority=authority,
        descriptor=body[4],
        root_public_key=root_public_key,
        revocation_commitment=revocation_commitment,
        revocation_public_key=revocation_public_key,
        signing_public_key=signing_public_key,
        valid_until_ms=valid_until_ms,
        contact=body[7],
        extensions=body.get(8),
        premature=premature,
        stale=stale,
    )
