"""Base58btc (Bitcoin alphabet) encoding without padding.

Alphabet per the multibase base58btc encoding: the 58 characters below,
excluding 0, O, I, and l.  Leading zero bytes encode as leading '1'
characters, one per byte.
"""

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {char: value for value, char in enumerate(ALPHABET)}


def encode(data: bytes) -> str:
    zeros = 0
    for byte in data:
        if byte != 0:
            break
        zeros += 1
    number = int.from_bytes(data, "big")
    digits = []
    while number > 0:
        number, remainder = divmod(number, 58)
        digits.append(ALPHABET[remainder])
    return "1" * zeros + "".join(reversed(digits))


def decode(text: str) -> bytes:
    """Decode base58btc text.  Raises ValueError on any invalid character."""
    zeros = 0
    for char in text:
        if char != "1":
            break
        zeros += 1
    number = 0
    for char in text:
        try:
            number = number * 58 + _INDEX[char]
        except KeyError:
            raise ValueError(f"invalid base58 character {char!r}") from None
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * zeros + body
