"""Authority Descriptor, public-key objects, and DID derivation
(Sections 3.2, 3.4, 4.1-4.3)."""

import hashlib

from . import detcbor, did
from .errors import ErrorCode, FolloweeError

SUITE_ED25519 = -19

# Exact ASCII domain-separation byte strings (Section 3.4).  The first two
# include the terminal zero byte.
DESCRIPTOR_HASH_PREFIX = b"Followee/AuthorityDescriptor/v1\x00"
REVOCATION_KEY_PREFIX = b"Followee/RevocationKey/v1\x00"


def _schema(message: str) -> FolloweeError:
    return FolloweeError(ErrorCode.SCHEMA_VIOLATION, message)


def make_public_key(public_key: bytes) -> dict:
    """Build the canonical v1 public-key object for 32 raw key bytes."""
    if len(public_key) != 32:
        raise ValueError("public key must be 32 bytes")
    return {0: SUITE_ED25519, 1: bytes(public_key)}


def validate_public_key(
    obj,
    *,
    suite_error: ErrorCode = ErrorCode.UNSUPPORTED_SUITE,
    size_error: ErrorCode = ErrorCode.SCHEMA_VIOLATION,
) -> bytes:
    """Validate a v1 ``public-key`` map; return the 32 raw key bytes.

    ``suite_error``/``size_error`` let the caller select the classification
    for a wrong suite or wrong key length (the revealed revocation key uses
    ``invalidRevocationKey`` for both per the Section 15.3 description
    "does not match the commitment or key profile").
    """
    if not isinstance(obj, dict) or set(obj.keys()) != {0, 1}:
        raise _schema("public-key object must contain exactly labels 0 and 1")
    suite = obj[0]
    if type(suite) is not int:
        raise _schema("public-key suite must be an integer")
    if suite != SUITE_ED25519:
        raise FolloweeError(suite_error, f"unsupported signature suite {suite}")
    key = obj[1]
    if not isinstance(key, bytes):
        raise _schema("public-key bytes must be a byte string")
    if len(key) != 32:
        raise FolloweeError(size_error, "public key must be exactly 32 bytes")
    return key


def validate_descriptor(obj) -> tuple:
    """Validate a v1 Authority Descriptor map.

    Returns ``(root_public_key_bytes, revocation_commitment_bytes)``.
    """
    if not isinstance(obj, dict) or set(obj.keys()) != {0, 1, 2}:
        raise _schema("authority descriptor must contain exactly labels 0, 1, 2")
    version = obj[0]
    if type(version) is not int or version != 1:
        raise _schema("descriptorVersion must equal 1")
    root_key = validate_public_key(obj[1])
    commitment = obj[2]
    if not isinstance(commitment, bytes) or len(commitment) != 32:
        raise _schema("revocationCommitment must be exactly 32 bytes")
    return root_key, commitment


def revocation_commitment(public_key_obj: dict) -> bytes:
    """SHA-256 over the revocation-key domain prefix and the deterministic
    CBOR of the public-key object (Section 4.2)."""
    return hashlib.sha256(
        REVOCATION_KEY_PREFIX + detcbor.encode(public_key_obj)
    ).digest()


def descriptor_digest(descriptor_obj: dict) -> bytes:
    """SHA-256 over the descriptor domain prefix and the deterministic CBOR
    of the Authority Descriptor (Section 4.3)."""
    return hashlib.sha256(
        DESCRIPTOR_HASH_PREFIX + detcbor.encode(descriptor_obj)
    ).digest()


def did_for_descriptor(descriptor_obj: dict) -> str:
    return did.did_from_digest(descriptor_digest(descriptor_obj))


def make_descriptor(root_public_key: bytes, revocation_public_key: bytes) -> dict:
    """Construct the v1 Authority Descriptor from two raw public keys."""
    return {
        0: 1,
        1: make_public_key(root_public_key),
        2: revocation_commitment(make_public_key(revocation_public_key)),
    }
