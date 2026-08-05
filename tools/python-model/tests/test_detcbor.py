import unittest

from followee_model import detcbor
from followee_model.errors import ErrorCode, FolloweeError


def dec(data_hex, max_depth=8, max_members=256):
    return detcbor.decode(
        bytes.fromhex(data_hex), max_depth=max_depth, max_members=max_members
    )


class EncodeTests(unittest.TestCase):
    def test_integer_boundaries(self):
        cases = {
            0: "00",
            23: "17",
            24: "1818",
            255: "18ff",
            256: "190100",
            65535: "19ffff",
            65536: "1a00010000",
            2**32 - 1: "1affffffff",
            2**32: "1b0000000100000000",
            2**64 - 1: "1bffffffffffffffff",
            -1: "20",
            -24: "37",
            -25: "1818".replace("1", "3", 1),  # 0x3818
            -19: "32",
            -256: "38ff",
            -257: "390100",
            -(2**64): "3bffffffffffffffff",
        }
        for value, expected in cases.items():
            self.assertEqual(detcbor.encode(value).hex(), expected, value)

    def test_integer_out_of_range(self):
        with self.assertRaises(ValueError):
            detcbor.encode(2**64)
        with self.assertRaises(ValueError):
            detcbor.encode(-(2**64) - 1)

    def test_strings_and_bytes(self):
        self.assertEqual(detcbor.encode("").hex(), "60")
        self.assertEqual(detcbor.encode("a").hex(), "6161")
        self.assertEqual(detcbor.encode(b"").hex(), "40")
        self.assertEqual(detcbor.encode(b"\x01\x02").hex(), "420102")

    def test_simple_values(self):
        self.assertEqual(detcbor.encode(False).hex(), "f4")
        self.assertEqual(detcbor.encode(True).hex(), "f5")
        self.assertEqual(detcbor.encode(None).hex(), "f6")

    def test_map_key_ordering_bytewise(self):
        # 10 encodes as 0a, 100 as 1864: bytewise 0a < 1864; -1 encodes as
        # 20, so unsigned keys sort before it despite numeric order.
        encoded = detcbor.encode({100: 1, 10: 2, -1: 3})
        self.assertEqual(encoded.hex(), "a30a02186401200 3".replace(" ", ""))

    def test_unsupported_type_rejected(self):
        with self.assertRaises(ValueError):
            detcbor.encode(object())
        with self.assertRaises(ValueError):
            detcbor.encode(1.5)

    def test_roundtrip(self):
        value = {
            0: 1,
            1: "did:flw:zabc",
            2: [b"\x00" * 3, "x", True, False, None, -5],
            3: {"a": {"b": [1, 2]}},
        }
        encoded = detcbor.encode(value)
        self.assertEqual(
            detcbor.decode(encoded, max_depth=8, max_members=256), value
        )


class DecodeStrictnessTests(unittest.TestCase):
    def assert_code(self, data_hex, code, **kwargs):
        with self.assertRaises(FolloweeError) as ctx:
            dec(data_hex, **kwargs)
        self.assertEqual(ctx.exception.code, code, data_hex)

    def test_valid_scalars(self):
        self.assertEqual(dec("00"), 0)
        self.assertEqual(dec("1818"), 24)
        self.assertEqual(dec("20"), -1)
        self.assertEqual(dec("f4"), False)
        self.assertEqual(dec("f5"), True)
        self.assertEqual(dec("f6"), None)
        self.assertEqual(dec("6161"), "a")
        self.assertEqual(dec("4100"), b"\x00")

    def test_non_minimal_integers(self):
        for data_hex in ("1800", "1817", "190018", "1a0000ffff", "1b00000000ffffffff"):
            self.assert_code(data_hex, ErrorCode.NON_DETERMINISTIC_CBOR)

    def test_non_minimal_lengths(self):
        self.assert_code("5801ff", ErrorCode.NON_DETERMINISTIC_CBOR)  # bstr len 1
        self.assert_code("780161", ErrorCode.NON_DETERMINISTIC_CBOR)  # tstr len 1
        self.assert_code("980100", ErrorCode.NON_DETERMINISTIC_CBOR)  # array len 1
        self.assert_code("b8010001", ErrorCode.NON_DETERMINISTIC_CBOR)  # map len 1

    def test_indefinite_lengths(self):
        for data_hex in ("5f41004100ff", "7f6161ff", "9f00ff", "bf0001ff"):
            self.assert_code(data_hex, ErrorCode.NON_DETERMINISTIC_CBOR)

    def test_floats_and_undefined(self):
        for data_hex in ("f90000", "fa00000000", "fb0000000000000000", "f7"):
            self.assert_code(data_hex, ErrorCode.NON_DETERMINISTIC_CBOR)

    def test_unassigned_simple_values(self):
        self.assert_code("f0", ErrorCode.NON_DETERMINISTIC_CBOR)  # simple(16)
        self.assert_code("f820", ErrorCode.NON_DETERMINISTIC_CBOR)  # simple(32)
        self.assert_code("f800", ErrorCode.INVALID_CBOR)  # ill-formed two-byte

    def test_tags_rejected(self):
        self.assert_code("c000", ErrorCode.NON_DETERMINISTIC_CBOR)
        self.assert_code("d20000".replace("0000", "8100"), ErrorCode.NON_DETERMINISTIC_CBOR)
        self.assert_code("c249010000000000000000", ErrorCode.NON_DETERMINISTIC_CBOR)  # bignum

    def test_unordered_map_keys(self):
        self.assert_code("a201000001", ErrorCode.NON_DETERMINISTIC_CBOR)

    def test_duplicate_map_keys(self):
        self.assert_code("a200000001", ErrorCode.NON_DETERMINISTIC_CBOR)

    def test_python_key_collision(self):
        # Distinct CBOR keys 1 and true collide as Python keys.
        self.assert_code("a20100f501", ErrorCode.SCHEMA_VIOLATION)

    def test_container_map_key(self):
        self.assert_code("a1800101", ErrorCode.SCHEMA_VIOLATION)

    def test_invalid_utf8(self):
        self.assert_code("61ff", ErrorCode.NON_DETERMINISTIC_CBOR)
        self.assert_code("62c328", ErrorCode.NON_DETERMINISTIC_CBOR)
        # UTF-16 surrogate half encoded as UTF-8 is invalid.
        self.assert_code("63eda080", ErrorCode.NON_DETERMINISTIC_CBOR)

    def test_truncation(self):
        for data_hex in ("18", "19ff", "41", "62c3", "8100".replace("00", ""), "a1"):
            self.assert_code(data_hex, ErrorCode.INVALID_CBOR)

    def test_trailing_bytes(self):
        self.assert_code("0000", ErrorCode.INVALID_CBOR)

    def test_reserved_additional_info(self):
        for data_hex in ("1c", "1d", "1e"):
            self.assert_code(data_hex, ErrorCode.INVALID_CBOR)

    def test_unexpected_break(self):
        self.assert_code("ff", ErrorCode.INVALID_CBOR)

    def test_depth_limit(self):
        self.assertEqual(dec("8181818100", max_depth=5), [[[[0]]]])
        self.assert_code("8181818100", ErrorCode.SCHEMA_VIOLATION, max_depth=3)

    def test_member_limit(self):
        self.assertEqual(dec("83000102", max_members=3), [0, 1, 2])
        self.assert_code("83000102", ErrorCode.SCHEMA_VIOLATION, max_members=2)
        # Map entries count one member per entry.
        self.assertEqual(dec("a2000001 01".replace(" ", ""), max_members=2), {0: 0, 1: 1})
        self.assert_code("a200000101", ErrorCode.SCHEMA_VIOLATION, max_members=1)

    def test_decode_reencode_identity(self):
        samples = [
            "a3000101a20032015820" + "11" * 32 + "025820" + "22" * 32,
            "84006161410002",
        ]
        for data_hex in samples:
            data = bytes.fromhex(data_hex)
            value = detcbor.decode(data, max_depth=8, max_members=256)
            self.assertEqual(detcbor.encode(value), data)


if __name__ == "__main__":
    unittest.main()
