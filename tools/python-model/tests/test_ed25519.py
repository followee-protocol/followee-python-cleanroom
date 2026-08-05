import unittest

from followee_model import ed25519

# RFC 8032 Section 7.1 test vectors (Ed25519, pure).
RFC8032_VECTORS = [
    {
        "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message": "",
        "signature": (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    },
    {
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    },
    {
        "seed": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message": "af82",
        "signature": (
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ),
    },
]


def small_order_encodings():
    """Canonical encodings of small-order points for negative tests."""
    identity = (1).to_bytes(32, "little")  # y = 1, x = 0: the identity
    order_two = (ed25519.P - 1).to_bytes(32, "little")  # y = -1, x = 0
    # y = 0 gives x^2 = -1; both sign choices have order 4.
    x = ed25519._SQRT_M1
    order_four = ((x & 1) << 255).to_bytes(32, "little")
    return identity, order_two, order_four


class Rfc8032VectorTests(unittest.TestCase):
    def test_vectors(self):
        for vector in RFC8032_VECTORS:
            seed = bytes.fromhex(vector["seed"])
            public = bytes.fromhex(vector["public"])
            message = bytes.fromhex(vector["message"])
            signature = bytes.fromhex(vector["signature"])
            self.assertEqual(ed25519.public_key_from_seed(seed), public)
            self.assertEqual(ed25519.sign(seed, message), signature)
            self.assertTrue(ed25519.verify_strict(public, message, signature))


class StrictVerifyTests(unittest.TestCase):
    def setUp(self):
        self.seed = bytes(range(32))
        self.public = ed25519.public_key_from_seed(self.seed)
        self.message = b"strictness test message"
        self.signature = ed25519.sign(self.seed, self.message)

    def test_roundtrip(self):
        self.assertTrue(
            ed25519.verify_strict(self.public, self.message, self.signature)
        )

    def test_wrong_message(self):
        self.assertFalse(
            ed25519.verify_strict(self.public, b"other", self.signature)
        )

    def test_bit_flipped_signature(self):
        for index in (0, 31, 32, 63):
            mutated = bytearray(self.signature)
            mutated[index] ^= 0x01
            self.assertFalse(
                ed25519.verify_strict(self.public, self.message, bytes(mutated))
            )

    def test_length_checks(self):
        self.assertFalse(
            ed25519.verify_strict(self.public[:-1], self.message, self.signature)
        )
        self.assertFalse(
            ed25519.verify_strict(self.public, self.message, self.signature[:-1])
        )
        self.assertFalse(
            ed25519.verify_strict(
                self.public, self.message, self.signature + b"\x00"
            )
        )

    def test_s_at_least_l_rejected(self):
        r_part = self.signature[:32]
        s = int.from_bytes(self.signature[32:], "little")
        # S + L still fits in 32 bytes but violates the S < L requirement.
        mutated = r_part + (s + ed25519.L).to_bytes(32, "little")
        self.assertFalse(
            ed25519.verify_strict(self.public, self.message, mutated)
        )

    def test_non_canonical_r_rejected(self):
        # y = p is a non-canonical encoding of y = 0.
        bad_r = ed25519.P.to_bytes(32, "little")
        mutated = bad_r + self.signature[32:]
        self.assertFalse(
            ed25519.verify_strict(self.public, self.message, mutated)
        )

    def test_non_canonical_public_key_rejected(self):
        bad_public = (ed25519.P + 1).to_bytes(32, "little")  # y = 1 + p
        self.assertFalse(
            ed25519.verify_strict(bad_public, self.message, self.signature)
        )
        # x = 0 with sign bit set is the non-canonical minus-zero.
        bad_sign = (1 | (1 << 255)).to_bytes(32, "little")
        self.assertFalse(
            ed25519.verify_strict(bad_sign, self.message, self.signature)
        )

    def test_small_order_public_keys_rejected(self):
        for encoded in small_order_encodings():
            self.assertIsNotNone(ed25519._decompress(encoded))
            self.assertFalse(
                ed25519.verify_strict(encoded, self.message, self.signature)
            )

    def test_small_order_r_rejected(self):
        _, order_two, order_four = small_order_encodings()
        for bad_r in (order_two, order_four):
            mutated = bad_r + self.signature[32:]
            self.assertFalse(
                ed25519.verify_strict(self.public, self.message, mutated)
            )

    def test_base_point_properties(self):
        base = ed25519._BASE
        self.assertFalse(ed25519._is_identity(base))
        self.assertTrue(ed25519._is_identity(ed25519._pt_mul(ed25519.L, base)))


if __name__ == "__main__":
    unittest.main()
