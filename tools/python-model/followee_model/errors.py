"""Symbolic protocol error codes (Followee-Specification.md Section 15.3).

The Python model classifies every rejection with one of these codes so that
results can be compared symbolically against other implementations.
"""

from enum import IntEnum


class ErrorCode(IntEnum):
    INVALID_DID = 0
    UNSUPPORTED_HASH = 1
    UNSUPPORTED_SUITE = 2
    RECORD_TOO_LARGE = 3
    INVALID_CBOR = 4
    NON_DETERMINISTIC_CBOR = 5
    SCHEMA_VIOLATION = 6
    IDENTITY_BINDING_MISMATCH = 7
    INVALID_REVOCATION_KEY = 8
    INVALID_SIGNATURE = 9
    PREMATURE = 10
    ROOT_REVOKED = 11
    LOSING_RECORD = 12
    DUPLICATE = 13
    POLICY_REJECTED = 14
    RATE_LIMITED = 15
    RESPONSE_TOO_LARGE = 16
    TEMPORARILY_UNAVAILABLE = 17
    INVALID_CURSOR = 18
    INTERNAL_ERROR = 19


#: Wire names from Section 15.3, keyed by code.
ERROR_NAMES = {
    ErrorCode.INVALID_DID: "invalidDid",
    ErrorCode.UNSUPPORTED_HASH: "unsupportedHash",
    ErrorCode.UNSUPPORTED_SUITE: "unsupportedSuite",
    ErrorCode.RECORD_TOO_LARGE: "recordTooLarge",
    ErrorCode.INVALID_CBOR: "invalidCbor",
    ErrorCode.NON_DETERMINISTIC_CBOR: "nonDeterministicCbor",
    ErrorCode.SCHEMA_VIOLATION: "schemaViolation",
    ErrorCode.IDENTITY_BINDING_MISMATCH: "identityBindingMismatch",
    ErrorCode.INVALID_REVOCATION_KEY: "invalidRevocationKey",
    ErrorCode.INVALID_SIGNATURE: "invalidSignature",
    ErrorCode.PREMATURE: "premature",
    ErrorCode.ROOT_REVOKED: "rootRevoked",
    ErrorCode.LOSING_RECORD: "losingRecord",
    ErrorCode.DUPLICATE: "duplicate",
    ErrorCode.POLICY_REJECTED: "policyRejected",
    ErrorCode.RATE_LIMITED: "rateLimited",
    ErrorCode.RESPONSE_TOO_LARGE: "responseTooLarge",
    ErrorCode.TEMPORARILY_UNAVAILABLE: "temporarilyUnavailable",
    ErrorCode.INVALID_CURSOR: "invalidCursor",
    ErrorCode.INTERNAL_ERROR: "internalError",
}


class FolloweeError(Exception):
    """A protocol-level rejection carrying its symbolic error code."""

    def __init__(self, code: ErrorCode, message: str):
        super().__init__(f"{ERROR_NAMES[code]}: {message}")
        self.code = code
        self.message = message
