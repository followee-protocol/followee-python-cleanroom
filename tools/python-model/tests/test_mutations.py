"""Required negative mutations (Appendix B.7) and related COSE-profile
rejections.  Where Appendix B assigns an error, that classification is
asserted exactly."""

import unittest

from followee_model import cose, descriptor, detcbor, ed25519, verify
from followee_model.errors import ErrorCode, FolloweeError

from . import helpers
from .helpers import (
    ATTACKER_DID,
    DID,
    NOW_MS,
    ROOT_SEED,
    REVOCATION_SEED,
    raw_envelope,
    raw_map,
    revoked_body,
    root_body,
    root_body_raw_entries,
    sign_body,
    sign_body_bytes,
)


class MutationTestCase(unittest.TestCase):
    def assert_rejected(self, envelope, code, target=DID, now=NOW_MS):
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(target, envelope, now)
        self.assertEqual(ctx.exception.code, code)
        return ctx.exception


class IdentityBindingMutations(MutationTestCase):
    """B.7 item 1: all three identity-binding permutations."""

    def test_unchanged_envelope_against_different_target(self):
        envelope = sign_body(root_body())
        self.assert_rejected(
            envelope, ErrorCode.IDENTITY_BINDING_MISMATCH, target=ATTACKER_DID
        )

    def test_resigned_id_mutation_against_original_target(self):
        # body id changed to another valid DID, re-signed by the legitimate
        # root key, verified against the original target.
        envelope = sign_body(root_body(did=ATTACKER_DID))
        self.assert_rejected(envelope, ErrorCode.IDENTITY_BINDING_MISMATCH)

    def test_resigned_id_mutation_against_mutated_target(self):
        # Same mutation verified against the mutated target: the body/target
        # relation passes but descriptor-to-target binding fails.
        envelope = sign_body(root_body(did=ATTACKER_DID))
        self.assert_rejected(
            envelope, ErrorCode.IDENTITY_BINDING_MISMATCH, target=ATTACKER_DID
        )


class TargetDidMutations(MutationTestCase):
    """B.7 item 2: target-DID classification without envelope mutation."""

    def test_unsupported_code_and_length(self):
        envelope = sign_body(root_body())
        digest = bytes(range(32))
        from followee_model import base58

        wrong_code = "did:flw:z" + base58.encode(b"\x13\x20" + digest)
        self.assert_rejected(envelope, ErrorCode.UNSUPPORTED_HASH, target=wrong_code)
        wrong_len = "did:flw:z" + base58.encode(b"\x12\x1f" + digest[:31])
        self.assert_rejected(envelope, ErrorCode.UNSUPPORTED_HASH, target=wrong_len)

    def test_structurally_invalid_targets(self):
        envelope = sign_body(root_body())
        from followee_model import base58

        digest = bytes(range(32))
        non_minimal = "did:flw:z" + base58.encode(b"\x92\x00\x20" + digest)
        self.assert_rejected(envelope, ErrorCode.INVALID_DID, target=non_minimal)
        disagreeing = "did:flw:z" + base58.encode(b"\x12\x20" + digest[:30])
        self.assert_rejected(envelope, ErrorCode.INVALID_DID, target=disagreeing)
        trailing = "did:flw:z" + base58.encode(b"\x12\x20" + digest + b"\xff")
        self.assert_rejected(envelope, ErrorCode.INVALID_DID, target=trailing)


class CoseProfileMutations(MutationTestCase):
    def payload(self) -> bytes:
        return detcbor.encode(root_body())

    def test_algorithm_minus_8_rejected(self):
        # B.7 item 3: deprecated polymorphic EdDSA value.
        envelope = raw_envelope(self.payload(), protected=detcbor.encode({1: -8}))
        self.assert_rejected(envelope, ErrorCode.UNSUPPORTED_SUITE)

    def test_other_algorithms_rejected(self):
        envelope = raw_envelope(self.payload(), protected=detcbor.encode({1: -7}))
        self.assert_rejected(envelope, ErrorCode.UNSUPPORTED_SUITE)

    def test_extra_protected_entries_rejected(self):
        envelope = raw_envelope(
            self.payload(), protected=detcbor.encode({1: -19, 4: b"kid"})
        )
        self.assert_rejected(envelope, ErrorCode.SCHEMA_VIOLATION)

    def test_missing_tag_rejected(self):
        # B.7 item 4.
        envelope = raw_envelope(self.payload(), tag=b"")
        self.assert_rejected(envelope, ErrorCode.SCHEMA_VIOLATION)

    def test_wrong_tag_rejected(self):
        envelope = raw_envelope(self.payload(), tag=b"\xd1")  # tag 17
        self.assert_rejected(envelope, ErrorCode.SCHEMA_VIOLATION)

    def test_non_minimal_tag_encoding_rejected(self):
        envelope = raw_envelope(self.payload(), tag=b"\xd8\x12")
        self.assert_rejected(envelope, ErrorCode.NON_DETERMINISTIC_CBOR)

    def test_non_empty_unprotected_rejected(self):
        # B.7 item 5.
        unprotected = raw_map([(detcbor.encode(4), detcbor.encode(b"ab"))])
        envelope = raw_envelope(self.payload(), unprotected=unprotected)
        self.assert_rejected(envelope, ErrorCode.SCHEMA_VIOLATION)

    def test_detached_payload_rejected(self):
        # B.7 item 6: payload nil instead of an attached byte string.
        payload = self.payload()
        signature = ed25519.sign(ROOT_SEED, cose.sig_structure(payload))
        envelope = (
            b"\xd2\x84"
            + detcbor.encode(cose.PROTECTED_HEADER)
            + b"\xa0"
            + b"\xf6"
            + detcbor.encode(signature)
        )
        self.assert_rejected(envelope, ErrorCode.SCHEMA_VIOLATION)

    def test_trailing_bytes_after_envelope_rejected(self):
        envelope = sign_body(root_body()) + b"\x00"
        self.assert_rejected(envelope, ErrorCode.INVALID_CBOR)

    def test_wrong_signature_length_rejected(self):
        payload = self.payload()
        envelope = raw_envelope(payload, signature=b"\x00" * 63)
        self.assert_rejected(envelope, ErrorCode.SCHEMA_VIOLATION)


class NonDeterministicBodyMutations(MutationTestCase):
    """B.7 items 7-9: a valid signature over the mutated bytes must not
    rescue a non-deterministic body."""

    def test_non_minimal_integer_encoding(self):
        entries = root_body_raw_entries()
        # authority 0 encoded as 0x1800 instead of 0x00.
        mutated = [
            (key, b"\x18\x00" if key == b"\x03" else value)
            for key, value in entries
        ]
        envelope = sign_body_bytes(raw_map(mutated))
        self.assert_rejected(envelope, ErrorCode.NON_DETERMINISTIC_CBOR)

    def test_reordered_map_keys(self):
        entries = root_body_raw_entries()
        swapped = [entries[1], entries[0]] + entries[2:]
        envelope = sign_body_bytes(raw_map(swapped))
        self.assert_rejected(envelope, ErrorCode.NON_DETERMINISTIC_CBOR)

    def test_duplicate_map_key(self):
        entries = root_body_raw_entries()
        duplicated = entries + [entries[0]]
        envelope = sign_body_bytes(raw_map(duplicated))
        self.assert_rejected(envelope, ErrorCode.NON_DETERMINISTIC_CBOR)


class AuthorityAndKeyMutations(MutationTestCase):
    def test_root_record_with_label_5(self):
        # B.7 item 10.
        body = root_body(
            extra_labels={5: descriptor.make_public_key(helpers.REVOCATION_PUBLIC)}
        )
        self.assert_rejected(sign_body(body), ErrorCode.SCHEMA_VIOLATION)

    def test_root_revoked_missing_label_5(self):
        # B.7 item 11.
        body = revoked_body()
        del body[5]
        envelope = sign_body(body, REVOCATION_SEED)
        self.assert_rejected(envelope, ErrorCode.SCHEMA_VIOLATION)

    def test_revealed_revocation_key_bit_flip(self):
        # B.7 item 12: valid signature by the mutated key's holder is
        # irrelevant; the commitment no longer matches.
        mutated_key = bytearray(helpers.REVOCATION_PUBLIC)
        mutated_key[0] ^= 0x01
        body = revoked_body(
            revocation_key_obj=descriptor.make_public_key(bytes(mutated_key))
        )
        envelope = sign_body(body, REVOCATION_SEED)
        self.assert_rejected(envelope, ErrorCode.INVALID_REVOCATION_KEY)

    def test_revealed_key_wrong_suite(self):
        body = revoked_body(
            revocation_key_obj={0: -8, 1: helpers.REVOCATION_PUBLIC}
        )
        envelope = sign_body(body, REVOCATION_SEED)
        self.assert_rejected(envelope, ErrorCode.INVALID_REVOCATION_KEY)

    def test_signature_bit_flip(self):
        # B.7 item 13.
        envelope = bytearray(sign_body(root_body()))
        envelope[-1] ^= 0x01
        self.assert_rejected(bytes(envelope), ErrorCode.INVALID_SIGNATURE)

    def test_s_greater_or_equal_l(self):
        # B.7 item 14: S >= L.
        envelope = sign_body(root_body())
        signature = envelope[-64:]
        s = int.from_bytes(signature[32:], "little")
        mutated_sig = signature[:32] + (s + ed25519.L).to_bytes(32, "little")
        payload = cose.parse_envelope(envelope).payload
        mutated = raw_envelope(payload, signature=mutated_sig)
        self.assert_rejected(mutated, ErrorCode.INVALID_SIGNATURE)

    def test_non_canonical_r(self):
        # B.7 item 14: non-canonical point encoding for R.
        envelope = sign_body(root_body())
        signature = envelope[-64:]
        bad_r = ed25519.P.to_bytes(32, "little")
        payload = cose.parse_envelope(envelope).payload
        mutated = raw_envelope(payload, signature=bad_r + signature[32:])
        self.assert_rejected(mutated, ErrorCode.INVALID_SIGNATURE)

    def test_small_order_root_public_key(self):
        # B.7 item 14: a small-order public key must fail strict
        # verification even with a structurally valid record.
        small_order = (ed25519.P - 1).to_bytes(32, "little")  # order-2 point
        desc = {
            0: 1,
            1: {0: -19, 1: small_order},
            2: bytes(32),
        }
        target = descriptor.did_for_descriptor(desc)
        body = root_body(did=target, descriptor_obj=desc)
        envelope = sign_body(body)  # signature cannot matter
        self.assert_rejected(envelope, ErrorCode.INVALID_SIGNATURE, target=target)

    def test_valid_until_before_timestamp(self):
        # B.7 item 15.
        body = root_body(valid_until_ms=helpers.TIMESTAMP_MS - 1)
        self.assert_rejected(sign_body(body), ErrorCode.SCHEMA_VIOLATION)

    def test_valid_until_equal_timestamp_accepted(self):
        body = root_body(valid_until_ms=helpers.TIMESTAMP_MS)
        record = verify.verify_full_record(DID, sign_body(body), NOW_MS)
        self.assertEqual(record.valid_until_ms, helpers.TIMESTAMP_MS)

    def test_descriptor_wrong_version(self):
        desc = dict(helpers.DESCRIPTOR)
        desc[0] = 2
        target = descriptor.did_for_descriptor(desc)
        body = root_body(did=target, descriptor_obj=desc)
        self.assert_rejected(
            sign_body(body), ErrorCode.SCHEMA_VIOLATION, target=target
        )

    def test_descriptor_root_key_wrong_suite(self):
        desc = {
            0: 1,
            1: {0: -8, 1: helpers.ROOT_PUBLIC},
            2: helpers.DESCRIPTOR[2],
        }
        target = descriptor.did_for_descriptor(desc)
        body = root_body(did=target, descriptor_obj=desc)
        self.assert_rejected(
            sign_body(body), ErrorCode.UNSUPPORTED_SUITE, target=target
        )


class AggregateLimitMutations(MutationTestCase):
    """B.7 item 16: aggregate hard limits."""

    def test_envelope_over_16_kib(self):
        extensions = {"https://x.example/pad": b"\x00" * 17000}
        body = root_body(extensions=extensions)
        envelope = sign_body(body)
        self.assertGreater(len(envelope), verify.MAX_RECORD_BYTES)
        self.assert_rejected(envelope, ErrorCode.RECORD_TOO_LARGE)

    def test_contact_over_12_kib(self):
        contact = {6: {"https://x.example/pad": b"\x00" * 12500}}
        body = root_body(contact=contact)
        envelope = sign_body(body)
        self.assertLessEqual(len(envelope), verify.MAX_RECORD_BYTES)
        self.assert_rejected(envelope, ErrorCode.SCHEMA_VIOLATION)

    def test_member_limit_over_256(self):
        extensions = {"https://x.example/many": list(range(250))}
        body = root_body(extensions=extensions)
        self.assert_rejected(sign_body(body), ErrorCode.SCHEMA_VIOLATION)

    def test_depth_limit_over_8(self):
        nested = b"pit"
        for _ in range(7):  # extension map is depth 2; 7 arrays reach 9
            nested = [nested]
        body = root_body(extensions={"https://x.example/deep": nested})
        self.assert_rejected(sign_body(body), ErrorCode.SCHEMA_VIOLATION)

    def test_depth_8_accepted(self):
        nested = b"ok"
        for _ in range(6):  # innermost container at depth 8
            nested = [nested]
        body = root_body(extensions={"https://x.example/deep": nested})
        record = verify.verify_full_record(DID, sign_body(body), NOW_MS)
        self.assertIsNotNone(record.extensions)

    def test_display_name_boundary(self):
        record = verify.verify_full_record(
            DID, sign_body(root_body(contact={0: "x" * 256})), NOW_MS
        )
        self.assertEqual(record.contact[0], "x" * 256)
        self.assert_rejected(
            sign_body(root_body(contact={0: "x" * 257})),
            ErrorCode.SCHEMA_VIOLATION,
        )

    def test_uri_boundary(self):
        long_uri = "https://x.example/" + "a" * (2048 - len("https://x.example/"))
        record = verify.verify_full_record(
            DID, sign_body(root_body(contact={2: long_uri})), NOW_MS
        )
        self.assertEqual(record.contact[2], long_uri)
        self.assert_rejected(
            sign_body(root_body(contact={2: long_uri + "a"})),
            ErrorCode.SCHEMA_VIOLATION,
        )

    def test_also_known_as_boundary(self):
        accepted = ["https://x.example/%d" % i for i in range(32)]
        verify.verify_full_record(
            DID, sign_body(root_body(contact={3: accepted})), NOW_MS
        )
        rejected = accepted + ["https://x.example/32"]
        self.assert_rejected(
            sign_body(root_body(contact={3: rejected})),
            ErrorCode.SCHEMA_VIOLATION,
        )


if __name__ == "__main__":
    unittest.main()
