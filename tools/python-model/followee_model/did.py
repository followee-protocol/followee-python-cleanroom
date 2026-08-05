"""``did:flw`` identifier construction and parsing (Section 3.1, 4.3).

Parsing distinguishes ``invalidDid`` (malformed syntax, multibase, base58, or
multihash structure) from ``unsupportedHash`` (a structurally well-formed
multihash naming a code other than 0x12 or a digest length other than 0x20).
"""

from . import base58
from .errors import ErrorCode, FolloweeError

DID_PREFIX = "did:flw:"
SHA2_256_CODE = 0x12
V1_DIGEST_LENGTH = 0x20

# Cap on unsigned-varint length, matching the 9-byte practical maximum of the
# multiformats unsigned-varint convention (see AUTHORING-RECORD.md).
_MAX_VARINT_BYTES = 9


def _invalid(message: str) -> FolloweeError:
    return FolloweeError(ErrorCode.INVALID_DID, message)


def _read_uvarint(buffer: bytes, pos: int):
    """Read one minimally encoded unsigned varint; return (value, new_pos)."""
    value = 0
    shift = 0
    count = 0
    while True:
        if pos >= len(buffer):
            raise _invalid("truncated varint in multihash")
        byte = buffer[pos]
        pos += 1
        count += 1
        if count > _MAX_VARINT_BYTES:
            raise _invalid("varint too long")
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if count > 1 and byte == 0:
                raise _invalid("non-minimal varint encoding")
            return value, pos
        shift += 7


def parse_did(did: str) -> bytes:
    """Parse a canonical v1 Followee DID; return its 32-byte digest.

    Raises FolloweeError with ``INVALID_DID`` or ``UNSUPPORTED_HASH``.
    """
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        raise _invalid("missing lowercase 'did:flw:' prefix")
    method_specific = did[len(DID_PREFIX) :]
    if not method_specific.startswith("z"):
        raise _invalid("missing multibase base58btc prefix 'z'")
    encoded = method_specific[1:]
    if not encoded:
        raise _invalid("empty base58btc payload")
    try:
        raw = base58.decode(encoded)
    except ValueError:
        raise _invalid("invalid base58btc character") from None

    code, pos = _read_uvarint(raw, 0)
    length, pos = _read_uvarint(raw, pos)
    if len(raw) - pos != length:
        raise _invalid("declared digest length disagrees with bytes present")
    if code != SHA2_256_CODE or length != V1_DIGEST_LENGTH:
        raise FolloweeError(
            ErrorCode.UNSUPPORTED_HASH,
            f"multihash code {code:#x} length {length:#x} unsupported in v1",
        )
    return raw[pos:]


def multihash_from_digest(digest: bytes) -> bytes:
    if len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    return bytes([SHA2_256_CODE, V1_DIGEST_LENGTH]) + digest


def did_from_digest(digest: bytes) -> str:
    return DID_PREFIX + "z" + base58.encode(multihash_from_digest(digest))
