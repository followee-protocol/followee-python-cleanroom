import unittest

from followee_model import signing
from followee_model.record import UINT64_MAX


class NextTimestampTests(unittest.TestCase):
    def test_first_record_uses_now(self):
        self.assertEqual(signing.next_timestamp(1000), 1000)

    def test_monotonic_advance(self):
        self.assertEqual(signing.next_timestamp(1000, previous_ms=999), 1000)
        self.assertEqual(signing.next_timestamp(1000, previous_ms=1000), 1001)
        self.assertEqual(signing.next_timestamp(1000, previous_ms=5000), 5001)

    def test_checked_arithmetic(self):
        with self.assertRaises(OverflowError):
            signing.next_timestamp(1000, previous_ms=UINT64_MAX)
        with self.assertRaises(ValueError):
            signing.next_timestamp(-1)
        with self.assertRaises(ValueError):
            signing.next_timestamp(UINT64_MAX + 1)


if __name__ == "__main__":
    unittest.main()
