"""Focused conformance tests for the v0.8 -> v0.8.1 specification delta,
within the model's Sections 3-8 scope.

v0.8.1 makes one classification explicit (Section 6.1.2, new paragraph):
a well-formed, basically valid, deterministically encoded CBOR simple
value other than ``false``, ``true``, ``null``, and ``undefined`` is not
admitted by any v1 schema and produces ``schemaViolation``, not
``nonDeterministicCbor``.  ``undefined`` remains forbidden by the profile
(rule 4) and still produces ``nonDeterministicCbor``.  This confirms the
classification this model derived independently during the v0.8 pass
(AUTHORING-RECORD.md, v0.8 ambiguity 2, now resolved).

Covers:

1. Appendix B.12 fault-isolated schema-disallowed-simple-value records
   (simple value 16 as ``f0``, simple value 32 as ``f8 20``), reproduced
   from structured inputs, re-signed with Alice's legitimate root seed,
   and compared against the specification-status v0.8.1 fixture; each
   complete envelope MUST fail with exactly ``schemaViolation``;
2. Appendix B.7 item 19 at the decoder layer: both encoding forms are
   ``schemaViolation``; the classification boundaries with ``undefined``
   (``nonDeterministicCbor``) and the ill-formed two-byte form below 32
   (``invalidCbor``) are unchanged;
3. position independence: the same simple value nested deeper inside an
   otherwise valid unknown extension is still ``schemaViolation``.

No wire encoding, cryptographic rule, authority rule, ordering rule, or
relay behaviour changed in v0.8.1, so no other model behavior is
re-tested here.
"""

import hashlib
import json
import pathlib
import unittest

from followee_model import cose, descriptor, detcbor, ed25519, signing, verify
from followee_model.errors import ErrorCode, FolloweeError

_FIXTURES = pathlib.Path(__file__).resolve().parents[3] / "fixtures" / "specification"

with open(_FIXTURES / "appendix_b_v081.json", "r", encoding="utf-8") as handle:
    FIXTURE_V081 = json.load(handle)


# Structured vector inputs (Appendix B.2, B.4): seeds, timestamp, and
# Contact Document content.  These are inputs, not derived values.
ALICE_ROOT_SEED = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
ALICE_REVOCATION_SEED = bytes.fromhex(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
)
ALICE_TIMESTAMP_MS = 1785589200123
ALICE_CONTACT = {
    0: "Alice Example",
    1: "Writer",
    3: ["acct:alice@example.com"],
    4: [
        {
            0: "feed",
            1: "Feed",
            2: "https://alice.example/feed.xml",
            3: "application/atom+xml",
            4: "Writing",
        }
    ],
}

NOW_MS = ALICE_TIMESTAMP_MS + 60_000

#: B.12 extension key (an otherwise valid Section 7.2 URI).
B12_EXTENSION_KEY = "https://example.com/ext"

VECTORS = ("b12_simple_value_16", "b12_simple_value_32")


def alice_descriptor() -> dict:
    return descriptor.make_descriptor(
        ed25519.public_key_from_seed(ALICE_ROOT_SEED),
        ed25519.public_key_from_seed(ALICE_REVOCATION_SEED),
    )


def alice_did() -> str:
    return descriptor.did_for_descriptor(alice_descriptor())


def alice_b4_body_bytes() -> bytes:
    body = signing.build_record_body(
        did=alice_did(),
        timestamp_ms=ALICE_TIMESTAMP_MS,
        authority=0,
        descriptor_obj=alice_descriptor(),
        contact=ALICE_CONTACT,
    )
    return signing.encode_record_body(body)


class SchemaDisallowedSimpleValueB12(unittest.TestCase):
    """B.12: fault-isolated schema-disallowed-simple-value records built
    from the B.4 Alice body (map head a6 -> a7, appended label-8
    extension bytes), signed with Alice's legitimate root seed over the
    exact received body bytes."""

    def mutated_body_bytes(self, appended: bytes) -> bytes:
        base = alice_b4_body_bytes()
        self.assertEqual(base[0], 0xA6)
        return b"\xa7" + base[1:] + appended

    def test_extension_key_and_value_encodings(self):
        # The appended bytes embed exactly the fixture's extension key
        # after the label-8 one-entry map head, followed by the stated
        # shortest encoding of the simple value: f0 for 16 (one-byte),
        # f8 20 for 32 (two-byte).
        key_encoded = detcbor.encode(B12_EXTENSION_KEY)
        self.assertEqual(B12_EXTENSION_KEY, FIXTURE_V081["b12_extension_key"])
        tails = {"b12_simple_value_16": b"\xf0", "b12_simple_value_32": b"\xf8\x20"}
        for name in VECTORS:
            appended = bytes.fromhex(FIXTURE_V081[name]["appended_bytes"])
            self.assertEqual(appended[:2], b"\x08\xa1", name)
            self.assertEqual(appended[2 : 2 + len(key_encoded)], key_encoded, name)
            self.assertEqual(appended[2 + len(key_encoded) :], tails[name], name)

    def test_reproduction_and_rejection(self):
        for name in VECTORS:
            with self.subTest(name):
                vector = FIXTURE_V081[name]
                body = self.mutated_body_bytes(
                    bytes.fromhex(vector["appended_bytes"])
                )
                self.assertEqual(
                    hashlib.sha256(body).digest(),
                    bytes.fromhex(vector["body_digest"]),
                )
                structure = cose.sig_structure(body)
                self.assertEqual(len(structure), vector["sig_structure_length"])
                signature = ed25519.sign(ALICE_ROOT_SEED, structure)
                self.assertEqual(signature, bytes.fromhex(vector["signature"]))
                envelope = cose.build_envelope(body, signature)

                # The re-signature over the exact mutated bytes is genuine:
                # reporting invalidSignature means the received bytes were
                # altered, and reporting nonDeterministicCbor means a
                # schema-disallowed simple value was misclassified as a
                # profile violation.  The required result is exactly
                # schemaViolation.
                self.assertEqual(vector["expected_result"], "schemaViolation")
                with self.assertRaises(FolloweeError) as ctx:
                    verify.verify_full_record(alice_did(), envelope, NOW_MS)
                self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)

    def test_nested_simple_value_is_also_schema_violation(self):
        # Model-derived variant (not a specification vector): the same
        # disallowed simple value one level deeper, inside an array
        # extension value.  Classification is position-independent.
        key_encoded = detcbor.encode(B12_EXTENSION_KEY)
        appended = b"\x08\xa1" + key_encoded + b"\x81\xf0"
        body = self.mutated_body_bytes(appended)
        signature = ed25519.sign(ALICE_ROOT_SEED, cose.sig_structure(body))
        envelope = cose.build_envelope(body, signature)
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(alice_did(), envelope, NOW_MS)
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)


class SimpleValueClassificationBoundaries(unittest.TestCase):
    """Section 6.1.2 (v0.8.1 paragraph) and B.7 item 19 at the decoder
    layer: exact classification of every simple-value form."""

    def decode_code(self, data_hex: str) -> ErrorCode:
        try:
            detcbor.decode(bytes.fromhex(data_hex), max_depth=8, max_members=256)
        except FolloweeError as error:
            return error.code
        self.fail(f"{data_hex} unexpectedly accepted")

    def test_admitted_simple_values(self):
        # false, true, and null are the only simple values any v1 schema
        # admits; undefined is profile-forbidden (rule 4).
        self.assertIs(
            detcbor.decode(b"\xf4", max_depth=8, max_members=256), False
        )
        self.assertIs(
            detcbor.decode(b"\xf5", max_depth=8, max_members=256), True
        )
        self.assertIsNone(detcbor.decode(b"\xf6", max_depth=8, max_members=256))

    def test_schema_disallowed_simple_values(self):
        # One-byte encodings 0..19 and two-byte encodings 32..255 pass
        # Sections 6.1.1 and 6.1.2 and fail at the schema layer.
        for data_hex in ("e0", "f0", "f3", "f820", "f8ff"):
            self.assertEqual(
                self.decode_code(data_hex), ErrorCode.SCHEMA_VIOLATION, data_hex
            )

    def test_undefined_remains_profile_forbidden(self):
        self.assertEqual(
            self.decode_code("f7"), ErrorCode.NON_DETERMINISTIC_CBOR
        )

    def test_ill_formed_two_byte_form_remains_invalid_cbor(self):
        # RFC 8949: a two-byte simple value below 32 is not well-formed.
        for data_hex in ("f800", "f81f"):
            self.assertEqual(
                self.decode_code(data_hex), ErrorCode.INVALID_CBOR, data_hex
            )


if __name__ == "__main__":
    unittest.main()
