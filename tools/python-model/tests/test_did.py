import unittest

from followee_model import base58, did
from followee_model.errors import ErrorCode, FolloweeError


def make_did(multihash: bytes) -> str:
    return "did:flw:z" + base58.encode(multihash)


class Base58Tests(unittest.TestCase):
    def test_roundtrip(self):
        for data in (b"", b"\x00", b"\x00\x00\x01", b"hello world", bytes(range(64))):
            self.assertEqual(base58.decode(base58.encode(data)), data)

    def test_leading_zero_bytes(self):
        self.assertEqual(base58.encode(b"\x00\x00"), "11")
        self.assertEqual(base58.decode("11"), b"\x00\x00")

    def test_invalid_characters(self):
        for text in ("0", "O", "I", "l", "a+b", "%41"):
            with self.assertRaises(ValueError):
                base58.decode(text)


class DidParseTests(unittest.TestCase):
    def setUp(self):
        self.digest = bytes(range(32))
        self.good = make_did(b"\x12\x20" + self.digest)

    def assert_code(self, value, code):
        with self.assertRaises(FolloweeError) as ctx:
            did.parse_did(value)
        self.assertEqual(ctx.exception.code, code, value)

    def test_parse_valid(self):
        self.assertEqual(did.parse_did(self.good), self.digest)

    def test_derive_and_parse_roundtrip(self):
        derived = did.did_from_digest(self.digest)
        self.assertEqual(did.parse_did(derived), self.digest)
        self.assertTrue(derived.startswith("did:flw:z"))

    def test_prefix_must_be_exact_lowercase(self):
        body = self.good[len("did:flw:") :]
        for bad in (
            "DID:flw:" + body,
            "did:FLW:" + body,
            "did:flw" + body,
            "flw:" + body,
            "",
        ):
            self.assert_code(bad, ErrorCode.INVALID_DID)

    def test_multibase_prefix_required(self):
        encoded = base58.encode(b"\x12\x20" + self.digest)
        self.assert_code("did:flw:" + encoded, ErrorCode.INVALID_DID)
        self.assert_code("did:flw:f" + encoded, ErrorCode.INVALID_DID)
        self.assert_code("did:flw:z", ErrorCode.INVALID_DID)

    def test_invalid_base58(self):
        self.assert_code("did:flw:z0OIl", ErrorCode.INVALID_DID)
        self.assert_code("did:flw:z%31%32", ErrorCode.INVALID_DID)

    def test_unsupported_hash_code(self):
        # Structurally well-formed multihash, code 0x13 instead of 0x12.
        self.assert_code(
            make_did(b"\x13\x20" + self.digest), ErrorCode.UNSUPPORTED_HASH
        )
        # Code 0x11 (sha1) with matching 20-byte digest.
        self.assert_code(
            make_did(b"\x11\x14" + bytes(20)), ErrorCode.UNSUPPORTED_HASH
        )
        # Multi-byte minimally encoded varint code.
        self.assert_code(
            make_did(b"\xb2\x20\x20" + self.digest), ErrorCode.UNSUPPORTED_HASH
        )

    def test_unsupported_digest_length(self):
        # Code 0x12 with declared length 0x1f matching the bytes present.
        self.assert_code(
            make_did(b"\x12\x1f" + self.digest[:31]), ErrorCode.UNSUPPORTED_HASH
        )
        self.assert_code(
            make_did(b"\x12\x21" + self.digest + b"\x00"),
            ErrorCode.UNSUPPORTED_HASH,
        )

    def test_length_disagreement_is_invalid(self):
        self.assert_code(
            make_did(b"\x12\x20" + self.digest[:31]), ErrorCode.INVALID_DID
        )
        self.assert_code(
            make_did(b"\x12\x20" + self.digest + b"\x00"), ErrorCode.INVALID_DID
        )

    def test_non_minimal_varint_is_invalid(self):
        # 0x92 0x00 is a two-byte encoding of 0x12.
        self.assert_code(
            make_did(b"\x92\x00\x20" + self.digest), ErrorCode.INVALID_DID
        )
        # Non-minimal length varint.
        self.assert_code(
            make_did(b"\x12\xa0\x00" + self.digest), ErrorCode.INVALID_DID
        )

    def test_truncated_varint_is_invalid(self):
        self.assert_code(make_did(b"\x92"), ErrorCode.INVALID_DID)
        self.assert_code(make_did(b"\x12"), ErrorCode.INVALID_DID)
        self.assert_code(make_did(b""), ErrorCode.INVALID_DID)


if __name__ == "__main__":
    unittest.main()
