"""Deterministic candidate selection and sticky root revocation
(Sections 8.2-8.4)."""

import itertools
import unittest

from followee_model import selection
from followee_model.errors import ErrorCode

from .helpers import (
    DID,
    NOW_MS,
    REVOCATION_SEED,
    TIMESTAMP_MS,
    revoked_body,
    root_body,
    sign_body,
)


def root_envelope(**overrides) -> bytes:
    return sign_body(root_body(**overrides))


def revoked_envelope(**overrides) -> bytes:
    return sign_body(revoked_body(**overrides), REVOCATION_SEED)


class OrderingTests(unittest.TestCase):
    def test_greater_timestamp_wins(self):
        older = root_envelope(timestamp_ms=TIMESTAMP_MS)
        newer = root_envelope(timestamp_ms=TIMESTAMP_MS + 5)
        result = selection.select_current(DID, [older, newer], NOW_MS)
        self.assertEqual(result.winner.timestamp_ms, TIMESTAMP_MS + 5)
        statuses = [outcome.error for outcome in result.outcomes]
        self.assertEqual(statuses, [ErrorCode.LOSING_RECORD, None])

    def test_equal_time_lower_digest_wins(self):
        # Same timestamp, different displayName: the lexicographically
        # lower 32-byte body digest must win regardless of input order.
        variant_a = root_envelope(contact={0: "Alice A"})
        variant_b = root_envelope(contact={0: "Alice B"})
        forward = selection.select_current(DID, [variant_a, variant_b], NOW_MS)
        reverse = selection.select_current(DID, [variant_b, variant_a], NOW_MS)
        losing_digests = [
            outcome.record.body_digest
            for outcome in forward.outcomes
            if outcome.error == ErrorCode.LOSING_RECORD
        ]
        self.assertEqual(len(losing_digests), 1)
        self.assertLess(forward.winner.body_digest, losing_digests[0])
        self.assertEqual(
            forward.winner.body_digest, reverse.winner.body_digest
        )

    def test_order_independence(self):
        envelopes = [
            root_envelope(timestamp_ms=TIMESTAMP_MS),
            root_envelope(timestamp_ms=TIMESTAMP_MS + 5),
            root_envelope(timestamp_ms=TIMESTAMP_MS + 5, contact={0: "Zed"}),
            revoked_envelope(timestamp_ms=TIMESTAMP_MS + 1),
        ]
        digests = set()
        for permutation in itertools.permutations(envelopes):
            result = selection.select_current(DID, list(permutation), NOW_MS)
            digests.add(result.winner.body_digest)
            self.assertTrue(result.root_revoked)
        self.assertEqual(len(digests), 1)

    def test_duplicate_detection(self):
        envelope = root_envelope()
        result = selection.select_current(DID, [envelope, envelope], NOW_MS)
        self.assertIsNotNone(result.winner)
        errors = [outcome.error for outcome in result.outcomes]
        self.assertEqual(errors, [None, ErrorCode.DUPLICATE])


class RootRevocationTests(unittest.TestCase):
    def test_revoked_beats_any_root_timestamp(self):
        # Root record far in the future of the revocation still loses.
        late_root = root_envelope(timestamp_ms=TIMESTAMP_MS + 50_000)
        early_revoked = revoked_envelope(timestamp_ms=TIMESTAMP_MS + 1)
        result = selection.select_current(
            DID, [late_root, early_revoked], NOW_MS
        )
        self.assertTrue(result.root_revoked)
        self.assertEqual(result.winner.authority, 1)
        self.assertEqual(
            result.outcomes[0].error, ErrorCode.ROOT_REVOKED
        )

    def test_stale_revoked_record_still_activates(self):
        stale_revoked = revoked_envelope(
            timestamp_ms=TIMESTAMP_MS + 1,
            valid_until_ms=TIMESTAMP_MS + 2,
        )
        root = root_envelope(timestamp_ms=TIMESTAMP_MS + 10)
        result = selection.select_current(DID, [root, stale_revoked], NOW_MS)
        self.assertTrue(result.root_revoked)
        self.assertEqual(result.winner.authority, 1)
        self.assertTrue(result.winner.stale)

    def test_premature_revoked_record_does_not_activate(self):
        premature_revoked = revoked_envelope(timestamp_ms=NOW_MS + 300_001)
        root = root_envelope()
        result = selection.select_current(
            DID, [root, premature_revoked], NOW_MS
        )
        self.assertFalse(result.root_revoked)
        self.assertEqual(result.winner.authority, 0)
        self.assertEqual(result.outcomes[1].error, ErrorCode.PREMATURE)

    def test_sticky_state_carries_in(self):
        root = root_envelope()
        result = selection.select_current(
            DID, [root], NOW_MS, sticky_root_revoked=True
        )
        self.assertTrue(result.root_revoked)
        self.assertIsNone(result.winner)
        self.assertEqual(result.outcomes[0].error, ErrorCode.ROOT_REVOKED)

    def test_revoked_ordering_within_state(self):
        first = revoked_envelope(timestamp_ms=TIMESTAMP_MS + 1)
        second = revoked_envelope(timestamp_ms=TIMESTAMP_MS + 2)
        result = selection.select_current(DID, [first, second], NOW_MS)
        self.assertEqual(result.winner.timestamp_ms, TIMESTAMP_MS + 2)
        self.assertEqual(result.outcomes[0].error, ErrorCode.LOSING_RECORD)


class MixedCandidateTests(unittest.TestCase):
    def test_invalid_candidates_reported_and_skipped(self):
        good = root_envelope()
        broken = bytearray(good)
        broken[-1] ^= 0x01
        result = selection.select_current(
            DID, [bytes(broken), good], NOW_MS
        )
        self.assertIsNotNone(result.winner)
        self.assertEqual(
            result.outcomes[0].error, ErrorCode.INVALID_SIGNATURE
        )
        self.assertIsNone(result.outcomes[1].error)

    def test_premature_root_not_selected(self):
        premature = root_envelope(timestamp_ms=NOW_MS + 300_001)
        current = root_envelope()
        result = selection.select_current(DID, [premature, current], NOW_MS)
        self.assertEqual(result.winner.timestamp_ms, TIMESTAMP_MS)
        self.assertEqual(result.outcomes[0].error, ErrorCode.PREMATURE)

    def test_boundary_future_timestamp_admissible(self):
        boundary = root_envelope(timestamp_ms=NOW_MS + 300_000)
        result = selection.select_current(DID, [boundary], NOW_MS)
        self.assertIsNotNone(result.winner)

    def test_no_candidates(self):
        result = selection.select_current(DID, [], NOW_MS)
        self.assertIsNone(result.winner)
        self.assertFalse(result.root_revoked)

    def test_stale_winner_flagged(self):
        envelope = root_envelope(valid_until_ms=TIMESTAMP_MS + 1)
        result = selection.select_current(DID, [envelope], NOW_MS)
        self.assertIsNotNone(result.winner)
        self.assertTrue(result.winner.stale)


if __name__ == "__main__":
    unittest.main()
