# Authoring Record: Followee Python Clean-Room Model

Author: clean-room authoring session (Claude Code), 2026-08-05.
Inputs: exactly the two approved files listed in `AUTHORING-CONSTRAINTS.md`,
verified by SHA-256 before authoring began.  No other Followee material was
inspected, searched for, or received.  No GitHub or web search was performed.

## Environment and dependencies

- Python 3.10.12 (system interpreter, Linux/WSL2).
- **No third-party dependencies.**  Only Python standard-library modules are
  used (`hashlib`, `re`, `enum`, `dataclasses`, `json`, `pathlib`,
  `itertools`, `typing`, `unittest`).  There is consequently no dependency
  lock file; the standard-library-only constraint is the lock.
- Tests run with the standard-library `unittest` runner:
  `python3 -m unittest discover -s tests -t .` from `tools/python-model/`.

## External standards relied upon

The specification cites its normative externals in Appendix C.  This model
was written from the author's working knowledge of those documents; no
document was fetched over the network during the session.  The standards
whose content materially shaped code are:

| Standard | Used for | URL |
| --- | --- | --- |
| RFC 8949 | CBOR encoding, deterministic-encoding rules (Section 4.2.1), well-formedness (ill-formed vs invalid items, reserved additional-info values, two-byte simple-value floor of 32) | https://www.rfc-editor.org/rfc/rfc8949 |
| RFC 9052 | COSE Sign1 structure and `Sig_structure` layout (`"Signature1"`, protected bytes, external AAD, payload) | https://www.rfc-editor.org/rfc/rfc9052 |
| RFC 8032 | Ed25519: key generation, signing, point decompression (Section 5.1.3), verification equation, Section 7.1 test vectors (reproduced from memory in `tests/test_ed25519.py` and independently confirmed by matching all Appendix B signatures) | https://www.rfc-editor.org/rfc/rfc8032 |
| RFC 3986 | `absolute-URI` grammar (scheme, hier-part, authority, IPv6/IPvFuture literals, pchar, query) | https://www.rfc-editor.org/rfc/rfc3986 |
| RFC 6838 | `restricted-name` grammar for `mediaType` (Section 4.2: leading alphanumeric, chars `!#$&-^_.+`, 127-char name cap) | https://www.rfc-editor.org/rfc/rfc6838 |
| RFC 5646 | `Language-Tag` ABNF including the fixed irregular and regular grandfathered lists; case-insensitive well-formedness | https://www.rfc-editor.org/rfc/rfc5646 |
| RFC 8288 | `reg-rel-type` grammar for `rel` tokens | https://www.rfc-editor.org/rfc/rfc8288 |
| RFC 9864 | Only the fact that COSE `alg` `-19` is fully-specified Ed25519; the numeric value itself is given by the Followee specification | https://www.rfc-editor.org/rfc/rfc9864 |
| multiformats multibase/multicodec | Base58btc alphabet and `z` prefix; unsigned-varint convention including its 9-byte practical maximum | https://github.com/multiformats/multibase, https://github.com/multiformats/unsigned-varint |

The Ed25519 group constants (p, L, d, base point y = 4/5) are the RFC 8032
domain parameters.  The strictness checks beyond RFC 8032 (S < L, subgroup
membership via [L]P = identity, non-identity public key, uncofactored
equation) implement Followee Section 3.3 items 1-7 directly.

## Interpretation decisions and ambiguities

Recorded rather than resolved against any other implementation, per the
clean-room procedure.  Numbers refer to the specification.

1. **"Absolute URI" and fragments (7.2).**  The spec requires URI fields to
   be "an absolute URI under RFC 3986" and says "relative references are
   malformed."  RFC 3986's `absolute-URI` production excludes fragments,
   while the contrast drawn ("relative references") could suggest only the
   scheme requirement was intended.  **Chosen:** the literal `absolute-URI`
   production — a fragment (`...#x`) makes the field malformed.  Flagged as
   a likely differential-test divergence point.
2. **Error classification under multiple failures (8.1).**  The permitted
   reordering of "cheap independent checks" with an "equivalent" final
   result leaves the reported *code* ambiguous when several checks would
   fail.  **Chosen:** perform the numbered steps of Section 8.1 exactly in
   the listed order and report the first failure.  Consequences include:
   binding mismatches (steps 7/9) are reported even when the signature is
   also invalid, and Contact Document violations (step 15) are reported
   only after signature verification (step 14) succeeds.
3. **Protected-header mismatch classification (6.2, 15.3).**  A protected
   map of exactly `{1: <int != -19>}` reports `unsupportedSuite`
   (Section 3.2: `-8` "MUST NOT be accepted", unsupported suites produce
   `unsupportedSuite`).  Any other deviation from the exact bytes `a10132`
   (extra entries, wrong types, undecodable content) is `schemaViolation`.
4. **Descriptor version other than 1 (4.1).**  No dedicated error code
   exists; classified `schemaViolation` (CDDL pins `0: 1`).
5. **Revealed revocation key with wrong suite or key length (5.1, 15.3).**
   Classified `invalidRevocationKey`, following the code-8 description
   "does not match the commitment or key profile".  Structural failures of
   the label-5 map (wrong label set, non-map) are `schemaViolation`.
6. **Invalid UTF-8 in a text string (6.1 item 8).**  Classified
   `nonDeterministicCbor` (a Section 6.1 profile violation), not
   `invalidCbor`.
7. **Unassigned CBOR simple values.**  Not mentioned by Section 6.1; no
   Followee schema admits them.  Well-formed unassigned simple values are
   rejected as `nonDeterministicCbor`; the ill-formed two-byte form with
   value < 32 is `invalidCbor` per RFC 8949.
8. **Multihash varint bound (3.1).**  Unsigned varints are capped at
   9 bytes per the multiformats convention; longer varints produce
   `invalidDid` as structurally malformed.
9. **Detached payload (6.2, B.7 item 6).**  A `nil` payload violates the
   required profile: `schemaViolation`.
10. **Malformed DID inside `migration` (7.4).**  `invalidDid` is reserved
    for the requested/target DID; a non-canonical DID string inside the
    Contact Document is a schema failure of that document:
    `schemaViolation`.  Migration DID values are required to parse under
    the full v1 profile (an `unsupportedHash`-shaped value is likewise a
    `schemaViolation` there).
11. **Depth counting (15.1).**  "Record-body CBOR nesting depth 8" is read
    as container nesting depth with the record-body map at depth 1; only
    arrays and maps add depth.
12. **Member counting (15.1).**  "Total record-body map and array members"
    counts every map entry (one per key/value pair) and every array element,
    recursively, over the record body only (the COSE envelope array and
    headers are outside it).  This reading exactly reproduces the
    specification's own arithmetic of "at most 61 minimal services in a
    Root record and 60 in a RootRevoked record"
    (12 + 4n <= 256 and 15 + 4n <= 256).
13. **Trailing bytes.**  Trailing bytes after the tagged envelope or after
    the record-body item make the input not "exactly one" CBOR item:
    `invalidCbor`.
14. **Signature length (6.2 item 6).**  A signature field that is not
    exactly 64 bytes is `schemaViolation` (CDDL `.size 64`); a 64-byte
    signature that fails cryptographic checks is `invalidSignature`.
15. **Non-minimal outer tag encoding.**  `0xd8 0x12` (tag 18 in two bytes)
    is `nonDeterministicCbor`; a different tag value is `schemaViolation`;
    a non-tag first item is `schemaViolation` ("missing tag").
16. **`rel` byte cap (7.3, 15.1).**  The 256-byte maximum applies to both
    the token form and the absolute-URI form of `rel`.
17. **Contact 12 KiB cap (15.1).**  Measured over the deterministic CBOR
    encoding of the contact map value, which equals the received bytes
    (guaranteed by strict decoding).
18. **Decoded-representation collisions.**  CBOR admits map keys the
    Python model cannot faithfully hold (`1` vs `true`, container keys).
    No v1 schema admits any of them; they are rejected at decode time as
    `schemaViolation` so no information is silently lost.
19. **Step 13 (8.1).**  With only suite `-19` in v1, the "selected key
    suite equals protected algorithm" check is vacuously true once steps
    3, 8, and 12 have pinned both sides; retained as an internal invariant.
20. **Selection outcome vocabulary.**  Per-candidate outcomes in the
    selection model reuse the wire codes symbolically: `premature`,
    `rootRevoked` (sticky exclusion), `losingRecord`, `duplicate`
    (body-digest match with the winner, Section 8.4).
21. **Identity elements (3.3).**  The identity point is rejected as a
    public key (item 5 requires non-identity) but accepted as a decoded
    `R` (item 6 requires only prime-order subgroup membership, which the
    identity satisfies).  The uncofactored equation then decides.
22. **Appendix B structured inputs.**  Treated as vector *inputs*: seeds,
    the two timestamps 1785589200123 (given in B.4) and 1785589201123
    (taken from the B.5 body bytes of the approved fixture), and the
    Contact Document field values shown in Section 9.6/B.4.  All derived
    values (keys, commitment, descriptor bytes, digest, DID, body bytes,
    Sig_structure, body digests, signatures, envelopes) are computed by
    the model and compared against the fixture in
    `tools/python-model/tests/test_appendix_b.py`.
23. **`validUntil_ms` boundaries (5.4, 5.5).**  Premature strictly greater
    (`timestamp > now + 300000`); stale strictly greater
    (`now > validUntil`); `validUntil == timestamp` is valid;
    `timestamp == now + 300000` is admissible.  All comparisons use
    Python's unbounded integers, so they are inherently overflow-safe.
24. **Empty containers.**  An empty Contact Document is valid (7.1); empty
    `alsoKnownAs`/`services` arrays and empty extension maps are accepted
    (CDDL `*`); an empty `migration` map is rejected (7.4 requires at
    least one field).
25. **Service `type` URI length.**  The generic 2,048-byte "any URI" cap
    applies to URI-form service types; no tighter bound is stated.

## Reproduction confidence

All 155 unit tests pass, including byte-exact independent reproduction of
every Appendix B value from seeds and structured inputs, the three
identity-binding permutations of B.7 item 1, the B.7 mutation list with
its normative error assignments, and the B.8 descriptor-substitution
attack (signature valid, rejected `identityBindingMismatch` at step 9).
