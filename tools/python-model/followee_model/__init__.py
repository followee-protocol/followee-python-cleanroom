"""Independent clean-room Python model of the Followee protocol core
(Followee-Specification.md v0.8.1, Sections 3-8).

Implements DID derivation and parsing, deterministic CBOR, Authority
Descriptor binding, COSE Sig_structure construction, Followee-strict
Ed25519, Identity Record verification with symbolic error classification,
and deterministic candidate selection with sticky root revocation.

No HTTP, relay, persistence, or CLI functionality is included.
"""

from .errors import ERROR_NAMES, ErrorCode, FolloweeError
from .verify import (
    MAX_FUTURE_SKEW_MS,
    MAX_RECORD_BYTES,
    VerifiedRecord,
    is_premature,
    verify_full_record,
)
from .selection import CandidateOutcome, SelectionResult, select_current

__all__ = [
    "ERROR_NAMES",
    "ErrorCode",
    "FolloweeError",
    "MAX_FUTURE_SKEW_MS",
    "MAX_RECORD_BYTES",
    "VerifiedRecord",
    "is_premature",
    "verify_full_record",
    "CandidateOutcome",
    "SelectionResult",
    "select_current",
]
