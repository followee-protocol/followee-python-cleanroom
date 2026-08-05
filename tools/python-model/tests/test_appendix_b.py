"""Independent reproduction of Appendix B from structured inputs.

Every derived value (public keys, commitment, descriptor bytes, digest,
DID, body bytes, Sig_structure, body digests, signatures, envelopes) is
computed by the model from the structured inputs below and then compared
against the specification-status fixture.  No expected value is embedded
in the model itself.
"""

import hashlib
import json
import pathlib
import unittest

from followee_model import (
    base58,
    cose,
    descriptor,
    did,
    detcbor,
    ed25519,
    signing,
    verify,
)
from followee_model.errors import ErrorCode, FolloweeError

FIXTURE_PATH = (
    pathlib.Path(__file__).resolve().parents[3]
    / "fixtures"
    / "specification"
    / "appendix_b.json"
)

with open(FIXTURE_PATH, "r", encoding="utf-8") as handle:
    FIXTURE = json.load(handle)


def fx(name: str) -> bytes:
    return bytes.fromhex(FIXTURE[name])


# Structured vector inputs (Appendix B.2, B.4, B.5): seeds, timestamps, and
# the Contact Document content.  These are inputs, not derived values.
ROOT_SEED = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
REVOCATION_SEED = bytes.fromhex(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
)
ROOT_TIMESTAMP_MS = 1785589200123  # B.4: 2026-08-01T13:00:00.123Z
REVOKED_TIMESTAMP_MS = 1785589201123  # B.5 body input
CONTACT = {
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

ATTACKER_ROOT_SEED = bytes.fromhex(
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
)
ATTACKER_REVOCATION_SEED = bytes.fromhex(
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
)

NOW_MS = ROOT_TIMESTAMP_MS + 60_000


class KeyAndDescriptorDerivation(unittest.TestCase):
    def test_public_keys_from_seeds(self):
        self.assertEqual(
            ed25519.public_key_from_seed(ROOT_SEED), fx("root_public_key")
        )
        self.assertEqual(
            ed25519.public_key_from_seed(REVOCATION_SEED),
            fx("revocation_public_key"),
        )

    def test_revocation_public_key_cbor(self):
        key_obj = descriptor.make_public_key(
            ed25519.public_key_from_seed(REVOCATION_SEED)
        )
        self.assertEqual(
            detcbor.encode(key_obj), fx("revocation_public_key_cbor")
        )

    def test_revocation_commitment(self):
        key_obj = descriptor.make_public_key(
            ed25519.public_key_from_seed(REVOCATION_SEED)
        )
        self.assertEqual(
            descriptor.revocation_commitment(key_obj),
            fx("revocation_commitment"),
        )

    def test_authority_descriptor_cbor(self):
        desc = self._descriptor()
        self.assertEqual(detcbor.encode(desc), fx("authority_descriptor_cbor"))

    def test_descriptor_digest_multihash_and_did(self):
        desc = self._descriptor()
        digest = descriptor.descriptor_digest(desc)
        self.assertEqual(digest, fx("descriptor_digest"))
        self.assertEqual(did.multihash_from_digest(digest), fx("multihash_bytes"))
        self.assertEqual(
            descriptor.did_for_descriptor(desc), FIXTURE["followee_did"]
        )

    def test_did_parses_back_to_descriptor_digest(self):
        self.assertEqual(
            did.parse_did(FIXTURE["followee_did"]), fx("descriptor_digest")
        )

    @staticmethod
    def _descriptor() -> dict:
        return descriptor.make_descriptor(
            ed25519.public_key_from_seed(ROOT_SEED),
            ed25519.public_key_from_seed(REVOCATION_SEED),
        )


def alice_descriptor() -> dict:
    return descriptor.make_descriptor(
        ed25519.public_key_from_seed(ROOT_SEED),
        ed25519.public_key_from_seed(REVOCATION_SEED),
    )


def alice_did() -> str:
    return descriptor.did_for_descriptor(alice_descriptor())


class RootRecordReproduction(unittest.TestCase):
    def build_body_bytes(self) -> bytes:
        body = signing.build_record_body(
            did=alice_did(),
            timestamp_ms=ROOT_TIMESTAMP_MS,
            authority=0,
            descriptor_obj=alice_descriptor(),
            contact=CONTACT,
        )
        return signing.encode_record_body(body)

    def test_record_body_bytes(self):
        self.assertEqual(self.build_body_bytes(), fx("root_record_body"))

    def test_sig_structure(self):
        structure = cose.sig_structure(self.build_body_bytes())
        self.assertEqual(len(structure), 327)  # B.4 stated length
        self.assertEqual(structure, fx("root_sig_structure"))

    def test_body_digest(self):
        self.assertEqual(
            hashlib.sha256(self.build_body_bytes()).digest(),
            fx("root_body_digest"),
        )

    def test_protected_header(self):
        self.assertEqual(cose.PROTECTED_HEADER, fx("protected_header"))
        self.assertEqual(detcbor.encode({1: -19}), fx("protected_header"))

    def test_signature_and_envelope(self):
        body_bytes = self.build_body_bytes()
        envelope = signing.sign_record_body(body_bytes, ROOT_SEED)
        self.assertEqual(envelope[-64:], fx("root_signature"))
        self.assertEqual(envelope, fx("root_record_envelope"))

    def test_full_verification(self):
        record = verify.verify_full_record(
            alice_did(), fx("root_record_envelope"), NOW_MS
        )
        self.assertEqual(record.authority, 0)
        self.assertEqual(record.timestamp_ms, ROOT_TIMESTAMP_MS)
        self.assertEqual(record.body_digest, fx("root_body_digest"))
        self.assertEqual(record.signing_public_key, fx("root_public_key"))
        self.assertFalse(record.premature)
        self.assertFalse(record.stale)


class RootRevokedReproduction(unittest.TestCase):
    def build_body_bytes(self) -> bytes:
        body = signing.build_record_body(
            did=alice_did(),
            timestamp_ms=REVOKED_TIMESTAMP_MS,
            authority=1,
            descriptor_obj=alice_descriptor(),
            contact=CONTACT,
            revocation_key_obj=descriptor.make_public_key(
                ed25519.public_key_from_seed(REVOCATION_SEED)
            ),
        )
        return signing.encode_record_body(body)

    def test_record_body_bytes(self):
        self.assertEqual(self.build_body_bytes(), fx("root_revoked_body"))

    def test_body_digest(self):
        self.assertEqual(
            hashlib.sha256(self.build_body_bytes()).digest(),
            fx("root_revoked_body_digest"),
        )

    def test_signature_and_envelope(self):
        body_bytes = self.build_body_bytes()
        envelope = signing.sign_record_body(body_bytes, REVOCATION_SEED)
        self.assertEqual(envelope[-64:], fx("root_revoked_signature"))
        self.assertEqual(envelope, fx("root_revoked_envelope"))

    def test_full_verification(self):
        record = verify.verify_full_record(
            alice_did(), fx("root_revoked_envelope"), NOW_MS
        )
        self.assertEqual(record.authority, 1)
        self.assertEqual(record.timestamp_ms, REVOKED_TIMESTAMP_MS)
        self.assertEqual(
            record.signing_public_key, fx("revocation_public_key")
        )


class EqualTimeOrderingReproduction(unittest.TestCase):
    def variant_body_digest(self, display_name: str) -> bytes:
        contact = dict(CONTACT)
        contact[0] = display_name
        body = signing.build_record_body(
            did=alice_did(),
            timestamp_ms=ROOT_TIMESTAMP_MS,
            authority=0,
            descriptor_obj=alice_descriptor(),
            contact=contact,
        )
        return hashlib.sha256(signing.encode_record_body(body)).digest()

    def test_variant_digests(self):
        digest_a = self.variant_body_digest("Alice A")
        digest_b = self.variant_body_digest("Alice B")
        self.assertEqual(digest_a, fx("alice_a_body_digest"))
        self.assertEqual(digest_b, fx("alice_b_body_digest"))
        # B.6: Alice A wins because its digest is lexicographically lower.
        self.assertLess(digest_a, digest_b)


class DescriptorSubstitutionB8(unittest.TestCase):
    def attacker_descriptor(self) -> dict:
        return descriptor.make_descriptor(
            ed25519.public_key_from_seed(ATTACKER_ROOT_SEED),
            ed25519.public_key_from_seed(ATTACKER_REVOCATION_SEED),
        )

    def test_attacker_key_material(self):
        self.assertEqual(
            ed25519.public_key_from_seed(ATTACKER_ROOT_SEED),
            fx("attacker_root_public_key"),
        )
        self.assertEqual(
            ed25519.public_key_from_seed(ATTACKER_REVOCATION_SEED),
            fx("attacker_revocation_public_key"),
        )
        self.assertEqual(
            descriptor.revocation_commitment(
                descriptor.make_public_key(
                    ed25519.public_key_from_seed(ATTACKER_REVOCATION_SEED)
                )
            ),
            fx("attacker_revocation_commitment"),
        )
        self.assertEqual(
            detcbor.encode(self.attacker_descriptor()),
            fx("attacker_descriptor_cbor"),
        )
        self.assertEqual(
            descriptor.did_for_descriptor(self.attacker_descriptor()),
            FIXTURE["attacker_did"],
        )

    def build_substituted_envelope(self) -> bytes:
        # B.8.2: identical to the B.4 body except label 4 carries the
        # attacker's descriptor; signed by the attacker's root key.
        body = signing.build_record_body(
            did=alice_did(),  # unchanged target DID in body label 1
            timestamp_ms=ROOT_TIMESTAMP_MS,
            authority=0,
            descriptor_obj=self.attacker_descriptor(),
            contact=CONTACT,
        )
        body_bytes = signing.encode_record_body(body)
        return signing.sign_record_body(body_bytes, ATTACKER_ROOT_SEED)

    def test_substituted_record_reproduction(self):
        envelope = self.build_substituted_envelope()
        self.assertEqual(envelope, fx("b8_envelope"))
        self.assertEqual(envelope[-64:], fx("b8_signature"))
        body_bytes = cose.parse_envelope(envelope).payload
        self.assertEqual(hashlib.sha256(body_bytes).digest(), fx("b8_body_digest"))
        self.assertEqual(FIXTURE["b8_target_did"], alice_did())

    def test_signature_is_valid_under_attacker_key(self):
        # The only negative vector where strict Ed25519 itself succeeds.
        envelope = cose.parse_envelope(self.build_substituted_envelope())
        self.assertTrue(
            ed25519.verify_strict(
                fx("attacker_root_public_key"),
                cose.sig_structure(envelope.payload),
                envelope.signature,
            )
        )

    def test_rejected_with_identity_binding_mismatch(self):
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(
                alice_did(), self.build_substituted_envelope(), NOW_MS
            )
        self.assertEqual(
            ctx.exception.code, ErrorCode.IDENTITY_BINDING_MISMATCH
        )


class FixtureConsistency(unittest.TestCase):
    def test_fixture_did_matches_spec_constant(self):
        # The fixture and the derived DID must agree with the b58 encoding.
        multihash = fx("multihash_bytes")
        self.assertEqual(
            "did:flw:z" + base58.encode(multihash), FIXTURE["followee_did"]
        )


if __name__ == "__main__":
    unittest.main()
