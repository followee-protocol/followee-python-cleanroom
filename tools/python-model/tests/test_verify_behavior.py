"""Verification behavior beyond the B.7 list: time classification,
Contact Document field rules, migration, extensions, and error precedence."""

import unittest

from followee_model import verify
from followee_model.errors import ErrorCode, FolloweeError

from .helpers import (
    ATTACKER_DID,
    DID,
    NOW_MS,
    TIMESTAMP_MS,
    revoked_body,
    root_body,
    sign_body,
)


class TimeClassificationTests(unittest.TestCase):
    def test_future_bound_boundary(self):
        envelope = sign_body(root_body())
        boundary_now = TIMESTAMP_MS - verify.MAX_FUTURE_SKEW_MS
        record = verify.verify_full_record(DID, envelope, boundary_now)
        self.assertFalse(record.premature)  # exactly at the bound is allowed
        record = verify.verify_full_record(DID, envelope, boundary_now - 1)
        self.assertTrue(record.premature)

    def test_stale_boundary(self):
        body = root_body(valid_until_ms=TIMESTAMP_MS + 10)
        envelope = sign_body(body)
        record = verify.verify_full_record(DID, envelope, TIMESTAMP_MS + 10)
        self.assertFalse(record.stale)
        record = verify.verify_full_record(DID, envelope, TIMESTAMP_MS + 11)
        self.assertTrue(record.stale)

    def test_staleness_does_not_invalidate(self):
        body = root_body(valid_until_ms=TIMESTAMP_MS)
        record = verify.verify_full_record(
            DID, sign_body(body), TIMESTAMP_MS + 10_000_000
        )
        self.assertTrue(record.stale)


class ContactRuleTests(unittest.TestCase):
    def assert_schema_violation(self, contact):
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(
                DID, sign_body(root_body(contact=contact)), NOW_MS
            )
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)

    def accept(self, contact):
        return verify.verify_full_record(
            DID, sign_body(root_body(contact=contact)), NOW_MS
        )

    def test_empty_contact_document_is_valid(self):
        record = self.accept({})
        self.assertEqual(record.contact, {})

    def test_unknown_contact_label(self):
        self.assert_schema_violation({7: "x"})

    def test_relative_uris_are_malformed(self):
        self.assert_schema_violation({2: "/avatar.png"})
        self.assert_schema_violation({3: ["example.com/profile"]})

    def test_service_requirements(self):
        base = {0: "svc", 1: "Website", 2: "https://example.com/"}
        self.accept({4: [base]})
        for missing in (0, 1, 2):
            entry = dict(base)
            del entry[missing]
            self.assert_schema_violation({4: [entry]})

    def test_service_type_token_case_sensitive(self):
        entry = {0: "svc", 1: "feed", 2: "https://example.com/"}
        # "feed" is not a token and not an absolute URI.
        self.assert_schema_violation({4: [entry]})
        entry[1] = "Feed"
        self.accept({4: [entry]})
        entry[1] = "https://types.example/mine"
        self.accept({4: [entry]})

    def test_duplicate_service_ids(self):
        entry = {0: "svc", 1: "Website", 2: "https://example.com/"}
        self.assert_schema_violation({4: [entry, dict(entry)]})
        second = dict(entry)
        second[0] = "svc2"
        self.accept({4: [entry, second]})

    def test_media_type_language_rel_syntax(self):
        entry = {0: "svc", 1: "Website", 2: "https://example.com/"}
        good = {**entry, 3: "application/atom+xml", 5: "en-US", 6: "me"}
        self.accept({4: [good]})
        self.assert_schema_violation(
            {4: [{**entry, 3: "text/plain;charset=utf-8"}]}
        )
        self.assert_schema_violation({4: [{**entry, 5: "not a tag"}]})
        self.assert_schema_violation({4: [{**entry, 6: "ME"}]})
        self.accept({4: [{**entry, 6: "https://rels.example/mine"}]})

    def test_migration_rules(self):
        self.accept({5: {0: ATTACKER_DID}})
        self.accept({5: {1: ATTACKER_DID}})
        self.accept({5: {0: ATTACKER_DID, 1: ATTACKER_DID}})
        self.assert_schema_violation({5: {}})
        self.assert_schema_violation({5: {0: DID}})  # own DID forbidden
        self.assert_schema_violation({5: {2: ATTACKER_DID}})
        self.assert_schema_violation({5: {0: "did:flw:not-a-did"}})

    def test_extension_keys_must_be_absolute_uris(self):
        self.assert_schema_violation({6: {"not-a-uri": 1}})
        self.accept({6: {"https://ext.example/a": {"k": [1, -1, b"", "", None, True]}}})


class RecordBodyRuleTests(unittest.TestCase):
    def test_unknown_body_label(self):
        envelope = sign_body(root_body(extra_labels={9: 1}))
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(DID, envelope, NOW_MS)
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)

    def test_wrong_protocol_version(self):
        body = root_body()
        body[0] = 2
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(DID, sign_body(body), NOW_MS)
        self.assertEqual(ctx.exception.code, ErrorCode.SCHEMA_VIOLATION)

    def test_binding_checked_before_signature(self):
        # A record whose id and descriptor mismatch the target AND whose
        # signature is broken must classify as identityBindingMismatch,
        # following the Section 8.1 step order.
        envelope = bytearray(sign_body(root_body()))
        envelope[-1] ^= 0x01
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(ATTACKER_DID, bytes(envelope), NOW_MS)
        self.assertEqual(
            ctx.exception.code, ErrorCode.IDENTITY_BINDING_MISMATCH
        )

    def test_revoked_record_verifies_with_revealed_key(self):
        from .helpers import REVOCATION_SEED

        envelope = sign_body(revoked_body(), REVOCATION_SEED)
        record = verify.verify_full_record(DID, envelope, NOW_MS)
        self.assertEqual(record.authority, 1)
        self.assertIsNotNone(record.revocation_public_key)

    def test_revoked_record_signed_by_root_key_fails(self):
        envelope = sign_body(revoked_body())  # root seed signs
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(DID, envelope, NOW_MS)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_SIGNATURE)

    def test_root_record_signed_by_revocation_key_fails(self):
        from .helpers import REVOCATION_SEED

        envelope = sign_body(root_body(), REVOCATION_SEED)
        with self.assertRaises(FolloweeError) as ctx:
            verify.verify_full_record(DID, envelope, NOW_MS)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_SIGNATURE)


if __name__ == "__main__":
    unittest.main()
