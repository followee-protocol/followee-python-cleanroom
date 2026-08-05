"""COSE Sign1 envelope profile and Sig_structure (Section 6.2).

The complete Identity Record is the tagged COSE Sign1 structure

    18([ h'a10132', {}, recordBodyBytes, signature ])

with the exact restrictions of Section 6.2.  The parser preserves the exact
received payload bytes: those bytes, not any re-encoding, feed signature
verification and the body digest.
"""

from dataclasses import dataclass

from . import detcbor
from .errors import ErrorCode, FolloweeError

#: Encoded protected header {1: -19} (Section 6.2 item 3).
PROTECTED_HEADER = bytes.fromhex("a10132")

#: COSE external AAD, exact ASCII bytes without terminal zero (Section 3.4).
EXTERNAL_AAD = b"Followee/IdentityRecord/v1"

COSE_SIGN1_TAG = 18
SUITE_ED25519 = -19


def _schema(message: str) -> FolloweeError:
    return FolloweeError(ErrorCode.SCHEMA_VIOLATION, message)


@dataclass
class Envelope:
    """A structurally valid v1 COSE Sign1 Identity Record envelope."""

    payload: bytes
    signature: bytes


def _check_outer_tag(data: bytes) -> bytes:
    """Verify the leading COSE Sign1 tag 18; return the remaining bytes."""
    if len(data) == 0:
        raise FolloweeError(ErrorCode.INVALID_CBOR, "empty input")
    initial = data[0]
    major = initial >> 5
    if major != 6:
        raise _schema("missing required COSE Sign1 tag 18")
    if initial == 0xD2:  # tag 18, minimal encoding
        return data[1:]
    ai = initial & 0x1F
    if ai in (24, 25, 26, 27):
        size = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
        if len(data) < 1 + size:
            raise FolloweeError(ErrorCode.INVALID_CBOR, "truncated tag head")
        tag = int.from_bytes(data[1 : 1 + size], "big")
        if tag == COSE_SIGN1_TAG:
            raise FolloweeError(
                ErrorCode.NON_DETERMINISTIC_CBOR, "non-minimal tag encoding"
            )
        raise _schema(f"wrong outer tag {tag}, expected 18")
    if ai < 24:
        raise _schema(f"wrong outer tag {ai}, expected 18")
    raise FolloweeError(ErrorCode.INVALID_CBOR, "ill-formed tag head")


def _classify_protected(protected) -> None:
    """Protected header bytes differ from a10132: classify the failure."""
    if not isinstance(protected, bytes):
        raise _schema("protected header must be a byte string")
    try:
        header = detcbor.decode(protected, max_depth=2, max_members=8)
    except FolloweeError:
        raise _schema("protected header is not a deterministic CBOR map") from None
    if (
        isinstance(header, dict)
        and set(header.keys()) == {1}
        and type(header[1]) is int
        and header[1] != SUITE_ED25519
    ):
        raise FolloweeError(
            ErrorCode.UNSUPPORTED_SUITE,
            f"protected COSE algorithm {header[1]} is not suite -19",
        )
    raise _schema("protected header must be exactly {1: -19}")


def parse_envelope(data: bytes) -> Envelope:
    """Parse and profile-check one complete tagged COSE Sign1 envelope."""
    inner = _check_outer_tag(bytes(data))
    # The envelope structure is a fixed shallow array; the record-body depth
    # and member limits apply to the payload, decoded separately.
    value = detcbor.decode(inner, max_depth=3, max_members=16)
    if not isinstance(value, list) or len(value) != 4:
        raise _schema("COSE Sign1 content must be a 4-element array")
    protected, unprotected, payload, signature = value

    if not isinstance(protected, bytes) or protected != PROTECTED_HEADER:
        _classify_protected(protected)
    if not isinstance(unprotected, dict) or unprotected != {}:
        raise _schema("unprotected header map must be empty")
    if payload is None:
        raise _schema("payload must be attached, not detached")
    if not isinstance(payload, bytes):
        raise _schema("payload must be a byte string")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise _schema("signature must be exactly 64 bytes")
    return Envelope(payload=payload, signature=signature)


def sig_structure(record_body_bytes: bytes) -> bytes:
    """Deterministic CBOR encoding of the COSE Sig_structure (Section 6.2)."""
    return detcbor.encode(
        ["Signature1", PROTECTED_HEADER, EXTERNAL_AAD, bytes(record_body_bytes)]
    )


def build_envelope(record_body_bytes: bytes, signature: bytes) -> bytes:
    """Assemble the complete tagged envelope from body bytes and signature."""
    if len(signature) != 64:
        raise ValueError("signature must be 64 bytes")
    return b"\xd2" + detcbor.encode(
        [PROTECTED_HEADER, {}, bytes(record_body_bytes), bytes(signature)]
    )
