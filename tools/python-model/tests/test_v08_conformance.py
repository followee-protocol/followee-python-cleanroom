"""Focused conformance and regression tests for the v0.7 -> v0.8
specification delta, within the model's Sections 3-8 scope.

Covers the normative changes that touch this model:

1. Section 6.1 layered CBOR classification: well-formedness and basic
   validity (duplicate map keys under value equivalence, RFC 3629 UTF-8)
   produce ``invalidCbor``; deterministic-profile violations produce
   ``nonDeterministicCbor``; multi-fault inputs have an unspecified exact
   error (exercised in test_detcbor.py and test_mutations.py, plus the
   record-level B.10 vectors here);
2. Appendix B.10 fault-isolated basic-validity records, reproduced from
   structured inputs and compared against the specification-status v0.8
   fixture;
3. Appendix B.9 independent Bob identity, reproduced from structured
   inputs, with cross-DID state isolation at the selection layer;
4. Section 6.1.1 byte-string opacity: byte strings are never recursively
   interpreted as CBOR (exercised in test_detcbor.py).

The Section 12/13/14 relay-wrapper, batch-alignment, and cursor-progress
changes and the B.11 vectors are outside this model's scope (no relay
wire protocol is modelled).
"""

import hashlib
import json
import pathlib
import unittest

from followee_model import (
    base58,
    cose,
    descriptor,
    detcbor,
    did,
    ed25519,
    selection,
    signing,
    verify,
)
from followee_model.errors import ErrorCode, FolloweeError

_FIXTURES = pathlib.Path(__file__).resolve().parents[3] / "fixtures" / "specification"

with open(_FIXTURES / "appendix_b.json", "r", encoding="utf-8") as handle:
    FIXTURE_B = json.load(handle)
with open(_FIXTURES / "appendix_b_v08.json", "r", encoding="utf-8") as handle:
    FIXTURE_V08 = json.load(handle)


def fx8(name: str) -> bytes:
    return bytes.fromhex(FIXTURE_V08[name])


# Structured vector inputs (Appendix B.2, B.4, B.9, B.10): seeds,
# timestamps, and Contact Document content.  These are inputs, not
# derived values.
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

BOB_ROOT_SEED = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
)
BOB_REVOCATION_SEED = bytes.fromhex(
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
)
BOB_TIMESTAMP_MS = 1785589201123
BOB_CONTACT = {
    0: "Bob Example",
    1: "Reader",
    3: ["acct:bob@example.net"],
    4: [
        {
            0: "feed",
            1: "Feed",
            2: "https://bob.example/feed.xml",
            3: "application/atom+xml",
            4: "Reading",
        }
    ],
}

NOW_MS = BOB_TIMESTAMP_MS + 60_000

#: B.10 extension key (an otherwise valid Section 7.2 URI).
B10_EXTENSION_KEY = "https://example.com/ext"


def alice_descriptor() -> dict:
    return descriptor.make_descriptor(
        ed25519.public_key_from_seed(ALICE_ROOT_SEED),
        ed25519.public_key_from_seed(ALICE_REVOCATION_SEED),
    )


def alice_did() -> str:
    return descriptor.did_for_descriptor(alice_descriptor())


def bob_descriptor() -> dict:
    return descriptor.make_descriptor(
        ed25519.public_key_from_seed(BOB_ROOT_SEED),
        ed25519.public_key_from_seed(BOB_REVOCATION_SEED),
    )


def bob_did() -> str:
    return descriptor.did_for_descriptor(bob_descriptor())


class BobIdentityReproductionB9(unittest.TestCase):
    """B.9: every derived Bob value reproduced from structured inputs."""

    def test_public_keys_from_seeds(self):
        self.assertEqual(
            ed25519.public_key_from_seed(BOB_ROOT_SEED),
            fx8("bob_root_public_key"),
        )
        self.assertEqual(
            ed25519.public_key_from_seed(BOB_REVOCATION_SEED),
            fx8("bob_revocation_public_key"),
        )

    def test_revocation_public_key_cbor_and_commitment(self):
        key_obj = descriptor.make_public_key(
            ed25519.public_key_from_seed(BOB_REVOCATION_SEED)
        )
        self.assertEqual(
            detcbor.encode(key_obj), fx8("bob_revocation_public_key_cbor")
        )
        self.assertEqual(
            descriptor.revocation_commitment(key_obj),
            fx8("bob_revocation_commitment"),
        )

    def test_descriptor_digest_multihash_and_did(self):
        desc = bob_descriptor()
        self.assertEqual(
            detcbor.encode(desc), fx8("bob_authority_descriptor_cbor")
        )
        digest = descriptor.descriptor_digest(desc)
        self.assertEqual(digest, fx8("bob_descriptor_digest"))
        self.assertEqual(
            did.multihash_from_digest(digest), fx8("bob_multihash_bytes")
        )
        self.assertEqual(bob_did(), FIXTURE_V08["bob_followee_did"])
        self.assertEqual(
            "did:flw:z" + base58.encode(fx8("bob_multihash_bytes")),
            FIXTURE_V08["bob_followee_did"],
        )

    def build_body_bytes(self) -> bytes:
        body = signing.build_record_body(
            did=bob_did(),
            timestamp_ms=BOB_TIMESTAMP_MS,
            authority=0,
            descriptor_obj=bob_descriptor(),
            contact=BOB_CONTACT,
        )
        return signing.encode_record_body(body)

    def test_record_body_sig_structure_and_digest(self):
        body_bytes = self.build_body_bytes()
        self.assertEqual(body_bytes, fx8("bob_record_body"))
        structure = cose.sig_structure(body_bytes)
        self.assertEqual(
            len(structure), FIXTURE_V08["bob_sig_structure_length"]
        )
        self.assertEqual(structure, fx8("bob_sig_structure"))
        self.assertEqual(
            hashlib.sha256(body_bytes).digest(), fx8("bob_body_digest")
        )

    def test_signature_and_envelope(self):
        envelope = signing.sign_record_body(
            self.build_body_bytes(), BOB_ROOT_SEED
        )
        self.assertEqual(envelope[-64:], fx8("bob_signature"))
        self.assertEqual(envelope, fx8("bob_record_envelope"))

    def test_full_verification(self):
        record = verify.verify_full_record(
            bob_did(), fx8("bob_record_envelope"), NOW_MS
        )
        self.assertEqual(record.authority, 0)
        self.assertEqual(record.timestamp_ms, BOB_TIMESTAMP_MS)
        self.assertEqual(record.timestamp_ms, FIXTURE_V08["bob_timestamp_ms"])
        self.assertEqual(record.signing_public_key, fx8("bob_root_public_key"))
        self.assertFalse(record.premature)
        self.assertFalse(record.stale)


class CrossDidStateIsolation(unittest.TestCase):
    """B.9: Alice and Bob have independent identity binding and sticky
    authority state.  Admitting or revoking one MUST NOT modify the
    other's outcome."""

    def test_bob_record_rejected_against_alice_target(self):
        for target, envelope in (
            (alice_did(), fx8("bob_record_envelope")),
            (bob_did(), bytes.fromhex(FIXTURE_B["root_record_envelope"])),
        ):
            with self.assertRaises(FolloweeError) as ctx:
                verify.verify_full_record(target, envelope, NOW_MS)
            self.assertEqual(
                ctx.exception.code, ErrorCode.IDENTITY_BINDING_MISMATCH
            )

    def test_alice_revocation_does_not_affect_bob_selection(self):
        # Selection state is per-DID: Alice's RootRevoked transition
        # activates sticky state for her DID only, and Bob's Root record
        # still wins under his own (non-revoked) sticky state.
        alice_result = selection.select_current(
            alice_did(),
            [
                bytes.fromhex(FIXTURE_B["root_record_envelope"]),
                bytes.fromhex(FIXTURE_B["root_revoked_envelope"]),
            ],
            NOW_MS,
        )
        self.assertTrue(alice_result.root_revoked)
        self.assertEqual(alice_result.winner.authority, 1)

        bob_result = selection.select_current(
            bob_did(), [fx8("bob_record_envelope")], NOW_MS
        )
        self.assertFalse(bob_result.root_revoked)
        self.assertIsNotNone(bob_result.winner)
        self.assertEqual(bob_result.winner.authority, 0)
        self.assertEqual(
            bob_result.winner.body_digest, fx8("bob_body_digest")
        )


class FaultIsolatedBasicValidityB10(unittest.TestCase):
    """B.10: fault-isolated basic-validity records built from the B.4
    Alice body (map head a6 -> a7, appended label-8 extension bytes),
    signed with Alice's legitimate root seed without decoding or
    normalizing the invalid value."""

    VECTORS = (
        "b10_duplicate_key",
        "b10_overlong",
        "b10_surrogate",
        "b10_above_max",
        "b10_incomplete",
    )

    def alice_b4_body_bytes(self) -> bytes:
        body = signing.build_record_body(
            did=alice_did(),
            timestamp_ms=ALICE_TIMESTAMP_MS,
            authority=0,
            descriptor_obj=alice_descriptor(),
            contact=ALICE_CONTACT,
        )
        return signing.encode_record_body(body)

    def mutated_body_bytes(self, appended: bytes) -> bytes:
        base = self.alice_b4_body_bytes()
        self.assertEqual(base[0], 0xA6)
        return b"\xa7" + base[1:] + appended

    def test_extension_key_is_the_stated_uri(self):
        # The appended bytes embed exactly the fixture's extension key,
        # deterministically encoded, after the label-8 one-entry map head.
        key_encoded = detcbor.encode(B10_EXTENSION_KEY)
        self.assertEqual(
            B10_EXTENSION_KEY, FIXTURE_V08["b10_extension_key"]
        )
        for name in self.VECTORS:
            appended = bytes.fromhex(FIXTURE_V08[name]["appended_bytes"])
            self.assertEqual(appended[:2], b"\x08\xa1", name)
            self.assertEqual(
                appended[2 : 2 + len(key_encoded)], key_encoded, name
            )

    def test_reproduction_and_rejection(self):
        for name in self.VECTORS:
            with self.subTest(name):
                vector = FIXTURE_V08[name]
                body = self.mutated_body_bytes(
                    bytes.fromhex(vector["appended_bytes"])
                )
                self.assertEqual(
                    hashlib.sha256(body).digest(),
                    bytes.fromhex(vector["body_digest"]),
                )
                structure = cose.sig_structure(body)
                self.assertEqual(
                    len(structure), vector["sig_structure_length"]
                )
                signature = ed25519.sign(ALICE_ROOT_SEED, structure)
                self.assertEqual(
                    signature, bytes.fromhex(vector["signature"])
                )
                envelope = cose.build_envelope(body, signature)

                # The re-signature over the exact mutated bytes is genuine,
                # so a verifier reporting invalidSignature has altered the
                # received body bytes; the required result is invalidCbor.
                self.assertEqual(vector["expected_result"], "invalidCbor")
                with self.assertRaises(FolloweeError) as ctx:
                    verify.verify_full_record(alice_did(), envelope, NOW_MS)
                self.assertEqual(ctx.exception.code, ErrorCode.INVALID_CBOR)

    def test_duplicate_key_vector_is_adjacent_and_minimal(self):
        # B.10: two adjacent deterministic encodings of integer key 0
        # inside the nested extension object; duplicate-key basic validity
        # is the only fault.
        appended = bytes.fromhex(
            FIXTURE_V08["b10_duplicate_key"]["appended_bytes"]
        )
        self.assertTrue(appended.endswith(bytes.fromhex("a200000001")))


if __name__ == "__main__":
    unittest.main()
