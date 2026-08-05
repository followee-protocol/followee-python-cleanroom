"""Focused conformance and regression tests for the v0.6 -> v0.7
specification delta.

Covers the three normative changes:

1. Section 7.2: URI fields use the RFC 3986 ``URI`` production — queries
   and fragments are permitted; every relative-reference form is malformed
   (behavior change relative to the v0.6 model, which rejected fragments);
2. Section 7.2: both ``v`` and ``V`` introduce IPvFuture (model already
   conformed since the v0.6 post-freeze review);
3. Section 6.1 and Appendix B.7 item 17: exact CBOR unsigned-integer label
   typing — ``false``/``true`` must not satisfy labels ``0``/``1`` (model
   already conformed since the v0.6 post-freeze review).
"""

import unittest

from followee_model import cose, descriptor, detcbor, ed25519, syntax, verify
from followee_model.errors import ErrorCode, FolloweeError

from . import helpers
from .helpers import DID, NOW_MS, revoked_body, root_body, sign_body


class UriProductionInRecords(unittest.TestCase):
    """v0.7 change 1 applied to every URI-bearing record field."""

    def accept(self, contact=None, extensions=None):
        body = root_body(
            contact=contact if contact is not None else dict(helpers.BASIC_CONTACT),
            extensions=extensions,
        )
        return verify.verify_full_record(DID, sign_body(body), NOW_MS)

    def reject(self, contact=None, extensions=None):
        body = root_body(
            contact=contact if contact is not None else dict(helpers.BASIC_CONTACT),
            extensions=extensions,
        )
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(DID, sign_body(body), NOW_MS)
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)

    def test_avatar_with_query_and_fragment(self):
        record = self.accept(contact={2: "https://example.com/a.png?s=64#main"})
        self.assertEqual(record.contact[2], "https://example.com/a.png?s=64#main")

    def test_also_known_as_with_fragment(self):
        self.accept(contact={3: ["https://example.com/profile#about"]})
        self.accept(contact={3: ["did:web:example.com#key-1"]})

    def test_service_endpoint_and_type_with_fragment(self):
        entry = {
            0: "svc",
            1: "https://types.example/spec#service",
            2: "https://example.com/api#endpoint",
        }
        self.accept(contact={4: [entry]})

    def test_rel_uri_with_fragment(self):
        entry = {
            0: "svc",
            1: "Website",
            2: "https://example.com/",
            6: "https://rels.example/spec#rel",
        }
        self.accept(contact={4: [entry]})

    def test_extension_keys_with_fragment(self):
        # Section 5.6 now references Section 7.2 for extension keys, for
        # both record extensions and contact extensions.
        self.accept(extensions={"https://ext.example/spec#v1": 1})
        self.accept(contact={6: {"https://ext.example/spec#v1": 1}})

    def test_every_relative_reference_form_rejected(self):
        relative_forms = (
            "//example.com/x",  # network-path reference
            "/profile",  # absolute-path reference
            "profile/x",  # relative-path reference
            "?view=full",  # query-only reference
            "#about",  # fragment-only reference
        )
        for value in relative_forms:
            self.reject(contact={2: value})
            self.reject(contact={3: [value]})
            self.reject(
                contact={4: [{0: "svc", 1: "Website", 2: value}]}
            )
            self.reject(extensions={value: 1})

    def test_uri_byte_limit_still_applies_with_fragment(self):
        base = "https://example.com/#"
        exact = base + "a" * (2048 - len(base))
        self.accept(contact={2: exact})
        self.reject(contact={2: exact + "a"})


class IpvFutureCase(unittest.TestCase):
    """v0.7 change 2: ABNF literals are case-insensitive (RFC 5234)."""

    def test_unit_level(self):
        self.assertTrue(syntax.is_uri("https://[v1.a]/x"))
        self.assertTrue(syntax.is_uri("https://[V1.a]/x"))

    def test_record_level_both_cases(self):
        for host in ("[v7.ab:12]", "[V7.ab:12]"):
            entry = {0: "svc", 1: "Website", 2: f"https://{host}/api"}
            body = root_body(contact={4: [entry]})
            record = verify.verify_full_record(DID, sign_body(body), NOW_MS)
            self.assertIn(host, record.contact[4][0][2])


class ExactLabelTyping(unittest.TestCase):
    """v0.7 change 3 (Section 6.1 paragraph and B.7 item 17): CBOR simple
    values false/true are different data items from labels 0/1."""

    def test_b7_item_17_signed_descriptor_vector(self):
        # An otherwise internally consistent, descriptor-bound, correctly
        # signed record whose descriptor uses false for label 0 must fail
        # with schemaViolation, demonstrating schema enforcement rather
        # than a signature or binding failure.
        desc = {
            False: 1,
            1: descriptor.make_public_key(helpers.ROOT_PUBLIC),
            2: helpers.DESCRIPTOR[2],
        }
        target = descriptor.did_for_descriptor(desc)
        envelope = sign_body(root_body(did=target, descriptor_obj=desc))
        parsed = cose.parse_envelope(envelope)
        self.assertTrue(
            ed25519.verify_strict(
                helpers.ROOT_PUBLIC,
                cose.sig_structure(parsed.payload),
                parsed.signature,
            )
        )
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(target, envelope, NOW_MS)
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)

    def test_b7_item_17_nested_public_key_vector(self):
        # true substituted for label 1 in the nested public-key object.
        desc = {
            0: 1,
            1: {0: -19, True: helpers.ROOT_PUBLIC},
            2: helpers.DESCRIPTOR[2],
        }
        target = descriptor.did_for_descriptor(desc)
        envelope = sign_body(root_body(did=target, descriptor_obj=desc))
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(target, envelope, NOW_MS)
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)

    def test_boolean_label_in_revealed_revocation_key(self):
        body = revoked_body(
            revocation_key_obj={False: -19, 1: helpers.REVOCATION_PUBLIC}
        )
        envelope = sign_body(body, helpers.REVOCATION_SEED)
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(DID, envelope, NOW_MS)
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)

    def test_wire_level_false_label_bytes(self):
        # Byte-level check: the descriptor map key f4 (false) is decoded
        # and then rejected by the schema, never treated as label 0.
        desc_obj = {
            False: 1,
            1: descriptor.make_public_key(helpers.ROOT_PUBLIC),
            2: helpers.DESCRIPTOR[2],
        }
        encoded = detcbor.encode(desc_obj)
        self.assertIn(b"\xf4", encoded)
        decoded = detcbor.decode(encoded, max_depth=8, max_members=256)
        self.assertIn(False, decoded)
        with self.assertRaises(FolloweeError) as ctx:
            descriptor.validate_descriptor(decoded)
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)


if __name__ == "__main__":
    unittest.main()
