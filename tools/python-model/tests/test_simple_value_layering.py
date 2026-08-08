"""Post-freeze conformance correction (2026-08-08): deterministic-CBOR /
schema layering for schema-disallowed simple values.

Provenance: this correction was prompted by a post-freeze neutral
differential result against the harness operation ``validateCbor``, which
applies Sections 6.1.1 and 6.1.2 plus explicit depth/member limits but no
record or envelope schema.  It is therefore reviewed conformance work, not
independent clean-room evidence; the v0.8.1 freeze
(``cleanroom-v0.8.1-maintenance-freeze``) is preserved unchanged as the
evidence of the independent interpretation that produced the disagreement.
See AUTHORING-RECORD.md, "Post-freeze differential conformance correction".

The corrected layering, per the pinned v0.8.1 specification:

* ``detcbor.decode`` (the production deterministic-CBOR entry point used by
  record verification) accepts deterministically encoded simple values
  other than ``false``/``true``/``null``/``undefined`` and preserves them
  as :class:`detcbor.SimpleValue` (Section 6.1.2, v0.8.1 paragraph: they
  pass Sections 6.1.1 and 6.1.2);
* the schema parsers reject ``SimpleValue`` wherever their schemas do not
  admit it, producing ``schemaViolation`` (Section 6.1.3);
* ``undefined`` (``f7``) remains profile-forbidden:
  ``nonDeterministicCbor``;
* two-byte simple encodings below 32 (``f8 00``, ``f8 1f``) remain not
  well-formed: ``invalidCbor``;
* the complete Appendix B.12 envelopes still fail with exactly
  ``schemaViolation`` (now at the schema step rather than inside decode).
"""

import unittest

from followee_model import cose, descriptor, detcbor, ed25519, record, verify
from followee_model.detcbor import SimpleValue
from followee_model.errors import ErrorCode, FolloweeError

from . import helpers
from . import test_v081_conformance as v081


def dec(data_hex: str):
    return detcbor.decode(bytes.fromhex(data_hex), max_depth=8, max_members=256)


class DecodeAcceptsDeterministicSimpleValues(unittest.TestCase):
    """detcbor.decode applies only Sections 6.1.1/6.1.2 and the explicit
    limits to simple values; schema admission is not its concern."""

    def test_one_byte_forms(self):
        self.assertEqual(dec("e0"), SimpleValue(0))
        self.assertEqual(dec("f0"), SimpleValue(16))  # bare B.12 value 16
        self.assertEqual(dec("f3"), SimpleValue(19))

    def test_two_byte_forms(self):
        self.assertEqual(dec("f820"), SimpleValue(32))  # bare B.12 value 32
        self.assertEqual(dec("f8ff"), SimpleValue(255))

    def test_byte_exact_round_trip(self):
        for data_hex in ("e0", "f0", "f3", "f820", "f8ff"):
            data = bytes.fromhex(data_hex)
            self.assertEqual(detcbor.encode(dec(data_hex)), data, data_hex)

    def test_undefined_remains_profile_forbidden(self):
        with self.assertRaises(FolloweeError) as ctx:
            dec("f7")
        self.assertEqual(ctx.exception.code, ErrorCode.NON_DETERMINISTIC_CBOR)

    def test_ill_formed_two_byte_forms_remain_invalid_cbor(self):
        for data_hex in ("f800", "f81f"):
            with self.assertRaises(FolloweeError) as ctx:
                dec(data_hex)
            self.assertEqual(
                ctx.exception.code, ErrorCode.INVALID_CBOR, data_hex
            )


class SimpleValueTypeSafety(unittest.TestCase):
    """The representation preserves generic-data-model type identity and
    cannot collide with integers or booleans."""

    def test_distinct_from_every_other_type(self):
        self.assertNotEqual(SimpleValue(16), 16)
        self.assertNotEqual(16, SimpleValue(16))
        self.assertNotEqual(SimpleValue(0), 0)
        self.assertNotEqual(SimpleValue(0), False)
        self.assertNotEqual(SimpleValue(1), True)
        self.assertNotEqual(SimpleValue(0), None)
        self.assertFalse(SimpleValue(0) == 0)

    def test_equality_and_hash_among_simple_values(self):
        self.assertEqual(SimpleValue(16), SimpleValue(16))
        self.assertEqual(hash(SimpleValue(16)), hash(SimpleValue(16)))
        self.assertNotEqual(SimpleValue(16), SimpleValue(32))

    def test_immutable(self):
        value = SimpleValue(16)
        with self.assertRaises(AttributeError):
            value.value = 17
        with self.assertRaises(AttributeError):
            del value.value

    def test_unconstructible_numeric_values(self):
        # 20..23 have dedicated representations (false/true/null) or are
        # profile-forbidden (undefined); 24..31 are not well-formed.
        for bad in (-1, 20, 21, 22, 23, 24, 31, 256):
            with self.assertRaises(ValueError):
                SimpleValue(bad)
        with self.assertRaises(ValueError):
            SimpleValue(True)  # bool is not an admitted constructor type

    def test_map_key_type_identity(self):
        # SimpleValue(0), integer 0, and false are distinct
        # generic-data-model keys: SimpleValue(0) coexists with either in
        # one decoded map without colliding.  (Integer 0 alongside false
        # remains the pre-existing decoded-representation collision of
        # Python's 0 == False, rejected as before; that behavior is
        # unchanged by this correction.)
        data = bytes.fromhex("a20001e002")
        decoded = detcbor.decode(data, max_depth=8, max_members=256)
        self.assertEqual(decoded, {0: 1, SimpleValue(0): 2})
        self.assertEqual(len(decoded), 2)
        self.assertEqual(decoded[SimpleValue(0)], 2)
        self.assertEqual(decoded[0], 1)
        self.assertEqual(detcbor.encode(decoded), data)

        data = bytes.fromhex("a2e001f402")
        decoded = detcbor.decode(data, max_depth=8, max_members=256)
        self.assertEqual(decoded, {SimpleValue(0): 1, False: 2})
        self.assertEqual(len(decoded), 2)
        self.assertEqual(decoded[SimpleValue(0)], 1)
        self.assertEqual(decoded[False], 2)
        self.assertEqual(detcbor.encode(decoded), data)


class StructuralPreservation(unittest.TestCase):
    """Nested arrays and maps preserve simple values structurally."""

    def test_nested_array(self):
        self.assertEqual(dec("81f0"), [SimpleValue(16)])
        self.assertEqual(dec("82f0f820"), [SimpleValue(16), SimpleValue(32)])

    def test_nested_map_value(self):
        self.assertEqual(dec("a100f0"), {0: SimpleValue(16)})

    def test_simple_value_map_key(self):
        self.assertEqual(dec("a1e000"), {SimpleValue(0): 0})

    def test_deep_nesting_round_trip(self):
        data = bytes.fromhex("a10082f0a1f820f8ff")
        decoded = detcbor.decode(data, max_depth=8, max_members=256)
        self.assertEqual(
            decoded, {0: [SimpleValue(16), {SimpleValue(32): SimpleValue(255)}]}
        )
        self.assertEqual(detcbor.encode(decoded), data)


class SchemaParsersRejectSimpleValues(unittest.TestCase):
    """Representative typed positions in every schema parser produce
    schemaViolation for SimpleValue (Section 6.1.3)."""

    def assert_schema(self, callable_, *args):
        with self.assertRaises(FolloweeError) as ctx:
            callable_(*args)
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)

    def test_extension_value_positions(self):
        # The exact B.12 positions: an extension value, and nested inside
        # array and object extension values.
        self.assert_schema(record.validate_extension_value, SimpleValue(16), "t")
        self.assert_schema(record.validate_extension_value, SimpleValue(32), "t")
        self.assert_schema(
            record.validate_extension_value, [SimpleValue(16)], "t"
        )
        self.assert_schema(
            record.validate_extension_value, {0: SimpleValue(32)}, "t"
        )

    def test_extension_map_value_and_object_key(self):
        self.assert_schema(
            record.validate_extension_map,
            {"https://example.com/ext": SimpleValue(16)},
            "t",
        )
        self.assert_schema(
            record.validate_extension_value, {SimpleValue(0): 1}, "t"
        )

    def test_record_body_positions(self):
        base = helpers.root_body()
        for mutate in (
            lambda b: b.__setitem__(3, SimpleValue(0)),  # authority
            lambda b: b.__setitem__(2, SimpleValue(16)),  # timestamp
            lambda b: b.__setitem__(SimpleValue(0), 1),  # body label
        ):
            body = dict(base)
            mutate(body)
            self.assert_schema(record.validate_record_body, body)

    def test_descriptor_positions(self):
        desc = dict(helpers.DESCRIPTOR)
        desc[0] = SimpleValue(1)  # descriptorVersion
        self.assert_schema(descriptor.validate_descriptor, desc)
        labeled = {SimpleValue(0): 1, 1: helpers.DESCRIPTOR[1], 2: helpers.DESCRIPTOR[2]}
        self.assert_schema(descriptor.validate_descriptor, labeled)
        self.assert_schema(
            descriptor.validate_public_key, {0: SimpleValue(16), 1: b"\x00" * 32}
        )

    def test_contact_service_and_migration_positions(self):
        did = helpers.DID
        self.assert_schema(
            record.validate_contact, {0: SimpleValue(16)}, did
        )  # displayName
        self.assert_schema(
            record.validate_contact, {3: [SimpleValue(16)]}, did
        )  # alsoKnownAs entry
        self.assert_schema(
            record.validate_contact,
            {4: [{0: SimpleValue(1), 1: "Website", 2: "https://a.example/"}]},
            did,
        )  # service id
        self.assert_schema(
            record.validate_migration, {0: SimpleValue(16)}, did
        )  # migration predecessor

    def test_envelope_positions(self):
        # Payload position: 18([a10132, {}, simple(16), 64-byte bstr]).
        raw = (
            b"\xd2\x84\x43\xa1\x01\x32\xa0\xf0\x58\x40" + b"\x00" * 64
        )
        self.assert_schema(cose.parse_envelope, raw)
        # Protected-header position: the header bytes decode to simple(16).
        raw = (
            b"\xd2\x84\x41\xf0\xa0\x41\x00\x58\x40" + b"\x00" * 64
        )
        self.assert_schema(cose.parse_envelope, raw)


class FullRecordPath(unittest.TestCase):
    """End-to-end production path: a genuinely signed record whose only
    fault is a schema-disallowed simple value fails with exactly
    schemaViolation, after its Ed25519 signature verifies."""

    def test_simple_value_in_contact_display_name(self):
        body = helpers.root_body(contact={0: SimpleValue(16)})
        envelope = helpers.sign_body(body)
        parsed = cose.parse_envelope(envelope)
        self.assertTrue(
            ed25519.verify_strict(
                helpers.ROOT_PUBLIC,
                cose.sig_structure(parsed.payload),
                parsed.signature,
            )
        )
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(helpers.DID, envelope, helpers.NOW_MS)
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)

    def test_b12_envelopes_still_schema_violation(self):
        # Both exact Appendix B.12 envelopes, reconstructed from the
        # specification-status fixture exactly as in
        # test_v081_conformance, still fail with schemaViolation; the
        # bare simple values they embed pass deterministic-CBOR
        # validation on their own.
        case = v081.SchemaDisallowedSimpleValueB12("test_reproduction_and_rejection")
        tails = {"b12_simple_value_16": "f0", "b12_simple_value_32": "f820"}
        for name in v081.VECTORS:
            with self.subTest(name):
                vector = v081.FIXTURE_V081[name]
                body = case.mutated_body_bytes(
                    bytes.fromhex(vector["appended_bytes"])
                )
                signature = ed25519.sign(
                    v081.ALICE_ROOT_SEED, cose.sig_structure(body)
                )
                self.assertEqual(signature, bytes.fromhex(vector["signature"]))
                envelope = cose.build_envelope(body, signature)
                with self.assertRaises(FolloweeError) as ctx:
                    verify.verify_full_record(
                        v081.alice_did(), envelope, v081.NOW_MS
                    )
                self.assertEqual(
                    ctx.exception.code, ErrorCode.SCHEMA_VIOLATION
                )
                # The fault-isolated bare value passes the structural
                # deterministic-CBOR validator.
                expected_value = {"f0": 16, "f820": 32}[tails[name]]
                self.assertEqual(
                    dec(tails[name]), SimpleValue(expected_value)
                )


if __name__ == "__main__":
    unittest.main()
