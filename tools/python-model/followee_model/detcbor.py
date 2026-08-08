"""Deterministic CBOR encoder and strict decoder.

Implements RFC 8949 CBOR under the three successive validation layers of
Followee-Specification.md Section 6.1:

1. *Well-formedness and basic validity* (Section 6.1.1): exactly one
   well-formed CBOR data item; every map has unique keys under generic
   data-model value equivalence; every text string is valid RFC 3629
   UTF-8, checked recursively through arrays and maps.  Recursion stops
   at byte-string boundaries: byte-string contents are opaque and are
   never reinterpreted as CBOR by this decoder.
2. *Followee deterministic profile* (Section 6.1.2): definite lengths
   only; shortest permitted encodings for integers, lengths, and tags;
   map entries in bytewise lexicographic order of their encoded keys;
   floating-point values, ``undefined``, and tags (including bignum tags)
   forbidden.  (The required outer COSE tag 18 is handled by the envelope
   parser, not here.)
3. *Schema* (Section 6.1.3): the depth and member limits passed by the
   caller, plus key forms no Followee schema admits.

The decoder verifies exactly the received bytes: a successfully decoded value
re-encodes to the identical byte string via :func:`encode`.

Error classification (Sections 6.1 and 15.3):

* not well-formed (truncation, reserved values, trailing bytes, unexpected
  break), or well-formed but basically invalid (duplicate map keys, invalid
  UTF-8 text) -> ``invalidCbor``;
* basically valid but non-deterministic or profile-forbidden encodings
  (non-minimal encodings, indefinite lengths, floats, undefined, tags,
  unordered map keys) -> ``nonDeterministicCbor``;
* depth or member limits exceeded, simple values no v1 schema admits
  (Section 6.1.2 explicitly classifies simple values other than
  ``false``, ``true``, ``null``, and ``undefined`` as schema failures,
  never ``nonDeterministicCbor``), or a map key form the Followee
  schemas can never admit (container keys, or distinct CBOR keys that
  would collide in the decoded representation such as ``true`` versus
  ``1``) -> ``schemaViolation``.

The decoder enforces the deterministic profile while parsing, so a
value-equal duplicate key with a non-minimal second serialization (for
example ``00`` then ``1800``) is a multi-fault input; Section 6.1.3 leaves
its exact error unspecified, and this decoder reports the encoding fault it
meets first.  The fault-isolated adjacent-duplicate case of Appendix B.10
has byte-identical keys and is always classified ``invalidCbor``.

Decoded values use plain Python types: int, bytes, str, bool, None, list,
dict.  Booleans are distinct from integers in both directions.
"""

from .errors import ErrorCode, FolloweeError


def _invalid(message: str) -> "FolloweeError":
    return FolloweeError(ErrorCode.INVALID_CBOR, message)


def _nondet(message: str) -> "FolloweeError":
    return FolloweeError(ErrorCode.NON_DETERMINISTIC_CBOR, message)


def _schema(message: str) -> "FolloweeError":
    return FolloweeError(ErrorCode.SCHEMA_VIOLATION, message)


_UINT64_MAX = 2**64 - 1

# Minimum argument value for each multi-byte argument encoding; anything
# smaller must have used a shorter form.
_MIN_FOR_AI = {24: 24, 25: 256, 26: 65536, 27: 2**32}
_AI_SIZE = {24: 1, 25: 2, 26: 4, 27: 8}


class _Decoder:
    def __init__(self, data: bytes, max_depth: int, max_members: int):
        self.data = data
        self.pos = 0
        self.members = 0
        self.max_depth = max_depth
        self.max_members = max_members

    def _need(self, n: int) -> None:
        if self.pos + n > len(self.data):
            raise _invalid("truncated CBOR input")

    def _count_member(self) -> None:
        self.members += 1
        if self.members > self.max_members:
            raise _schema(
                "aggregate map/array member limit exceeded "
                f"({self.max_members})"
            )

    def _read_arg(self, ai: int) -> int:
        """Read the argument for additional info ``ai`` (0..27), enforcing
        the shortest-form rule."""
        if ai < 24:
            return ai
        size = _AI_SIZE[ai]
        self._need(size)
        arg = int.from_bytes(self.data[self.pos : self.pos + size], "big")
        self.pos += size
        if arg < _MIN_FOR_AI[ai]:
            raise _nondet("non-minimal argument encoding")
        return arg

    def decode_item(self, depth: int):
        self._need(1)
        initial = self.data[self.pos]
        self.pos += 1
        major = initial >> 5
        ai = initial & 0x1F

        if major == 7:
            return self._decode_major7(ai)

        if ai in (28, 29, 30):
            raise _invalid("reserved additional-information value")
        if ai == 31:
            if major in (2, 3, 4, 5):
                raise _nondet("indefinite-length item")
            raise _invalid("ill-formed additional-information 31")

        arg = self._read_arg(ai)

        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            self._need(arg)
            value = self.data[self.pos : self.pos + arg]
            self.pos += arg
            return bytes(value)
        if major == 3:
            self._need(arg)
            raw = self.data[self.pos : self.pos + arg]
            self.pos += arg
            try:
                # Python's strict UTF-8 decoder implements RFC 3629: it
                # rejects overlong encodings, surrogate code points, values
                # above U+10FFFF, and incomplete code-point sequences.
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                # Basic-validity failure (Section 6.1.1).
                raise _invalid("text string is not valid UTF-8") from None
        if major == 4:
            if depth > self.max_depth:
                raise _schema(f"nesting depth limit exceeded ({self.max_depth})")
            items = []
            for _ in range(arg):
                self._count_member()
                items.append(self.decode_item(depth + 1))
            return items
        if major == 5:
            if depth > self.max_depth:
                raise _schema(f"nesting depth limit exceeded ({self.max_depth})")
            result = {}
            previous_key_bytes = None
            for _ in range(arg):
                self._count_member()
                key_start = self.pos
                key = self.decode_item(depth + 1)
                key_bytes = self.data[key_start : self.pos]
                if previous_key_bytes is not None:
                    if key_bytes == previous_key_bytes:
                        # Basic-validity failure (Section 6.1.1): after the
                        # deterministic checks, byte equality is exactly
                        # generic data-model key equivalence.
                        raise _invalid("duplicate map key")
                    if key_bytes < previous_key_bytes:
                        raise _nondet("map keys not in bytewise lexicographic order")
                previous_key_bytes = key_bytes
                if isinstance(key, (list, dict)):
                    raise _schema("container map key is not admitted by any v1 schema")
                if key in result:
                    # Distinct CBOR keys that collide as Python dict keys
                    # (e.g. true vs 1).  Section 6.1.1: values of different
                    # generic data-model types are *not* equivalent keys, so
                    # this is not a basic-validity duplicate; no v1 schema
                    # admits such key pairs.
                    raise _schema("map keys collide in decoded representation")
                result[key] = self.decode_item(depth + 1)
            return result
        # major == 6
        raise _nondet("CBOR tag inside protocol data")

    def _decode_major7(self, ai: int):
        if ai == 20:
            return False
        if ai == 21:
            return True
        if ai == 22:
            return None
        if ai == 23:
            raise _nondet("CBOR 'undefined' is forbidden")
        if ai < 20:
            # Well-formed and basically valid; not forbidden by the
            # Section 6.1.2 profile list; no v1 schema admits it
            # (explicit in Section 6.1.2: schemaViolation, never
            # nonDeterministicCbor).
            raise _schema("unassigned CBOR simple value")
        if ai == 24:
            self._need(1)
            value = self.data[self.pos]
            self.pos += 1
            if value < 32:
                raise _invalid("ill-formed two-byte simple value")
            raise _schema("unassigned CBOR simple value")
        if ai in (25, 26, 27):
            raise _nondet("floating-point values are forbidden")
        if ai == 31:
            raise _invalid("unexpected break code")
        raise _invalid("reserved additional-information value")


def decode(data: bytes, *, max_depth: int, max_members: int):
    """Decode exactly one deterministic CBOR item; reject trailing bytes."""
    decoder = _Decoder(bytes(data), max_depth, max_members)
    value = decoder.decode_item(1)
    if decoder.pos != len(decoder.data):
        raise _invalid("trailing bytes after CBOR item")
    return value


def _encode_head(major: int, arg: int, out: bytearray) -> None:
    if arg < 24:
        out.append((major << 5) | arg)
    elif arg < 256:
        out.append((major << 5) | 24)
        out.append(arg)
    elif arg < 65536:
        out.append((major << 5) | 25)
        out += arg.to_bytes(2, "big")
    elif arg < 2**32:
        out.append((major << 5) | 26)
        out += arg.to_bytes(4, "big")
    elif arg <= _UINT64_MAX:
        out.append((major << 5) | 27)
        out += arg.to_bytes(8, "big")
    else:
        raise ValueError("integer argument exceeds 64 bits")


def _encode_item(value, out: bytearray) -> None:
    if value is False:
        out.append(0xF4)
    elif value is True:
        out.append(0xF5)
    elif value is None:
        out.append(0xF6)
    elif isinstance(value, int):
        if value >= 0:
            _encode_head(0, value, out)
        else:
            _encode_head(1, -1 - value, out)
    elif isinstance(value, (bytes, bytearray)):
        _encode_head(2, len(value), out)
        out += value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
        _encode_head(3, len(raw), out)
        out += raw
    elif isinstance(value, (list, tuple)):
        _encode_head(4, len(value), out)
        for item in value:
            _encode_item(item, out)
    elif isinstance(value, dict):
        entries = []
        for key, item in value.items():
            key_out = bytearray()
            _encode_item(key, key_out)
            item_out = bytearray()
            _encode_item(item, item_out)
            entries.append((bytes(key_out), bytes(item_out)))
        entries.sort(key=lambda entry: entry[0])
        for index in range(1, len(entries)):
            if entries[index][0] == entries[index - 1][0]:
                raise ValueError("duplicate map key")
        _encode_head(5, len(entries), out)
        for key_bytes, item_bytes in entries:
            out += key_bytes
            out += item_bytes
    else:
        raise ValueError(f"type {type(value).__name__} is not encodable")


def encode(value) -> bytes:
    """Deterministically encode a Python value to CBOR bytes."""
    out = bytearray()
    _encode_item(value, out)
    return bytes(out)
