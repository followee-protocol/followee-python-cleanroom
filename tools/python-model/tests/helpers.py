"""Shared builders for verification and mutation tests.

Uses the public Appendix B seeds (declared public test material in B.1)
to construct records from structured input, plus low-level raw-CBOR
builders for deliberately non-deterministic encodings.
"""

from followee_model import cose, descriptor, detcbor, ed25519, signing

ROOT_SEED = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
REVOCATION_SEED = bytes.fromhex(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
)
ATTACKER_ROOT_SEED = bytes.fromhex(
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
)
ATTACKER_REVOCATION_SEED = bytes.fromhex(
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
)

ROOT_PUBLIC = ed25519.public_key_from_seed(ROOT_SEED)
REVOCATION_PUBLIC = ed25519.public_key_from_seed(REVOCATION_SEED)

DESCRIPTOR = descriptor.make_descriptor(ROOT_PUBLIC, REVOCATION_PUBLIC)
DID = descriptor.did_for_descriptor(DESCRIPTOR)

ATTACKER_DESCRIPTOR = descriptor.make_descriptor(
    ed25519.public_key_from_seed(ATTACKER_ROOT_SEED),
    ed25519.public_key_from_seed(ATTACKER_REVOCATION_SEED),
)
ATTACKER_DID = descriptor.did_for_descriptor(ATTACKER_DESCRIPTOR)

TIMESTAMP_MS = 1785589200123
NOW_MS = TIMESTAMP_MS + 60_000

BASIC_CONTACT = {0: "Alice Example"}


def root_body(**overrides) -> dict:
    body = signing.build_record_body(
        did=overrides.pop("did", DID),
        timestamp_ms=overrides.pop("timestamp_ms", TIMESTAMP_MS),
        authority=0,
        descriptor_obj=overrides.pop("descriptor_obj", DESCRIPTOR),
        contact=overrides.pop("contact", dict(BASIC_CONTACT)),
        valid_until_ms=overrides.pop("valid_until_ms", None),
        extensions=overrides.pop("extensions", None),
    )
    body.update(overrides.pop("extra_labels", {}))
    assert not overrides, overrides
    return body


def revoked_body(**overrides) -> dict:
    body = signing.build_record_body(
        did=overrides.pop("did", DID),
        timestamp_ms=overrides.pop("timestamp_ms", TIMESTAMP_MS + 1000),
        authority=1,
        descriptor_obj=overrides.pop("descriptor_obj", DESCRIPTOR),
        contact=overrides.pop("contact", dict(BASIC_CONTACT)),
        revocation_key_obj=overrides.pop(
            "revocation_key_obj", descriptor.make_public_key(REVOCATION_PUBLIC)
        ),
        valid_until_ms=overrides.pop("valid_until_ms", None),
    )
    body.update(overrides.pop("extra_labels", {}))
    assert not overrides, overrides
    return body


def sign_body(body: dict, seed: bytes = ROOT_SEED) -> bytes:
    return signing.sign_record_body(detcbor.encode(body), seed)


def sign_body_bytes(body_bytes: bytes, seed: bytes = ROOT_SEED) -> bytes:
    return signing.sign_record_body(body_bytes, seed)


# --- Raw CBOR builders for deliberately non-deterministic bodies -----------


def raw_head(major: int, arg: int) -> bytes:
    out = bytearray()
    if arg < 24:
        out.append((major << 5) | arg)
    elif arg < 256:
        out.append((major << 5) | 24)
        out.append(arg)
    elif arg < 65536:
        out.append((major << 5) | 25)
        out += arg.to_bytes(2, "big")
    else:
        raise ValueError("unsupported test argument")
    return bytes(out)


def raw_map(entries) -> bytes:
    """A map from raw (key_bytes, value_bytes) pairs, exactly as given."""
    out = bytearray(raw_head(5, len(entries)))
    for key_bytes, value_bytes in entries:
        out += key_bytes
        out += value_bytes
    return bytes(out)


def root_body_raw_entries() -> list:
    """The canonical root-record body as raw (key, value) encoded pairs."""
    body = root_body()
    return [(detcbor.encode(k), detcbor.encode(body[k])) for k in sorted(body)]


def raw_envelope(
    payload_bytes: bytes,
    seed: bytes = ROOT_SEED,
    protected: bytes = None,
    unprotected: bytes = b"\xa0",
    signature: bytes = None,
    tag: bytes = b"\xd2",
) -> bytes:
    """Assemble an envelope with full control over each component.

    The signature, unless supplied, is computed correctly over the given
    payload bytes so that only the mutation under test differs.
    """
    if protected is None:
        protected = cose.PROTECTED_HEADER
    if signature is None:
        signature = ed25519.sign(seed, cose.sig_structure(payload_bytes))
    return (
        tag
        + b"\x84"
        + detcbor.encode(protected)
        + unprotected
        + detcbor.encode(payload_bytes)
        + detcbor.encode(signature)
    )
