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
   *Resolved by specification v0.7*, which pins the RFC 3986 `URI`
   production (fragments and queries permitted); see the v0.7 maintenance
   section below.
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

## Post-freeze clean-room review corrections (2026-08-05)

An independent review of the freeze revision (`7ca1f62`), derived solely
from the approved specification and the frozen Python source, reported two
defects.  No Rust source, fixtures, outputs, or other excluded or
provisional Followee material was revealed to or inspected by this session
in receiving or fixing them.

1. **Boolean CBOR labels versus fixed integer labels.**  Python evaluates
   `False == 0` and `True == 1`, so the set-equality label checks in
   `descriptor.validate_public_key()` and `descriptor.validate_descriptor()`
   accepted deterministic CBOR maps keyed by `false`/`true` in place of the
   required uint labels — including a complete, descriptor-bound, correctly
   signed envelope.  Fixed by requiring `type(label) is int` for every
   label before the set comparison.  Audit of the other fixed-label map
   checks: `record.py` (body, contact, service, migration, extension-object
   labels) already enforced exact label types; `cose._classify_protected`
   had the same aliasing flaw in its *classification* branch only (a
   boolean-keyed protected header was rejected either way but as
   `unsupportedSuite` rather than `schemaViolation`) and was corrected;
   `parse_envelope`'s empty-unprotected comparison and all value-position
   checks were already exact-type safe.  Regression tests cover `false` and
   `true` substitutions in both maps at unit level and a fully signed,
   descriptor-bound envelope with a boolean descriptor label, asserted to
   fail with `schemaViolation` while its Ed25519 signature verifies.
2. **IPvFuture case-insensitivity (RFC 3986).**  RFC ABNF string literals
   are case-insensitive, so IPvFuture's `"v"` must match `v` and `V`; the
   URI grammar previously accepted only lowercase.  Fixed to `[vV]` with
   positive tests for both forms.  The recorded `absolute-URI`/fragment
   interpretation (ambiguity 1 above) is deliberately unchanged.

## v0.7 maintenance pass (2026-08-05)

Bounded maintenance pass under the updated `AUTHORING-CONSTRAINTS.md`.

**Revisions.**
- v0.6 base model: commit `70e4a6caa8720f1dfbb3b183a5d305fca0cf3e57`
  (`cleanroom-v0.6-review1`), itself descending from the v0.6 freeze
  `7ca1f623453065deefd1e6cfdf15e135d523dd7e`.
- v0.6 specification input: `followee-protocol/followee` commit
  `44c68660f0c0a1e3504c0f9794b8c51058da6f18` (recorded in this
  repository's history at commit `70b393f`).
- v0.7 specification input: `followee-protocol/followee` commit
  `abc9a55d90f1026e6509207abda73e5dc6d14241`, SHA-256
  `2b264823ba68d9a7d69ce68de5c1408ac8a3d54ff6d726ab89ee2baa2707c81f`,
  pinned by repository commit `6b944b952d1daec6840deae7e07f304f5349637d`.
- Appendix B fixture unchanged (SHA-256
  `f188316ffd7ad07fe94a842027f1ea7596e42a2f00b0691c1096fa2bfaddb717`).

The semantic delta was determined exclusively from this repository's own
Git history (`git diff 70e4a6c..6b944b9 -- Followee-Specification.md`)
plus a full read of the v0.6 text earlier in the clean room; no other
implementation was consulted.

**Semantic differences identified (v0.6 → v0.7).**

1. *Section 7.2 URI grammar (normative behavior change).*  URI fields now
   match the RFC 3986 Section 3 `URI` production: a scheme is required and
   the optional query and fragment components are permitted; every
   `relative-ref` form (network-path, absolute-path, relative-path,
   query-only, fragment-only) is malformed.  This resolves recorded
   ambiguity 1 — in the opposite direction from the v0.6 model's chosen
   `absolute-URI` reading, so fragments change from rejected to accepted.
   Sections 5.6, 7.1, and 7.3 now phrase avatar, `alsoKnownAs` entries,
   service `type` (URI form), `endpoint`, `rel` (URI form), and extension
   keys as "URI satisfying Section 7.2".  **Code change:**
   `syntax.py` — `is_absolute_uri()` replaced by `is_uri()` with an
   optional `#fragment` component (fragment grammar `*( pchar / "/" /
   "?" )`); `record.py` call sites and messages updated.  Migration
   values are unaffected (still canonical Followee DIDs, not Section 7.2
   URIs).
2. *Section 7.2 IPvFuture case (codifies existing behavior).*  New
   paragraph: RFC ABNF string literals are case-insensitive (RFC 5234),
   so both `v` and `V` introduce IPvFuture.  The model already conformed
   via the v0.6 post-freeze review fix.  **Tests only.**
3. *Section 6.1 exact label typing plus Appendix B.7 item 17 and the
   Section 20.1 additions (codifies existing behavior).*  Integer map
   labels are CBOR major-type-0 keys; `false`/`true` MUST NOT be accepted
   as labels `0`/`1` even where the host language compares them equal,
   and key type must be enforced before host-language lookup or
   set-equality.  B.7 item 17 requires an otherwise consistent,
   descriptor-bound, correctly signed boolean-label record to fail with
   `schemaViolation`.  The model already conformed via the v0.6
   post-freeze review fix.  **Tests only.**
4. *Non-normative for this model:* version header v0.7, expanded
   Section 20.1 conformance list, new Appendix C reference to RFC 5234.
   Appendix B vectors are unchanged (fixture hash identical).

**Changes made.**

- Code: `followee_model/syntax.py` (URI production with optional
  fragment; function renamed `is_uri`), `followee_model/record.py`
  (call sites, error messages, docstring), `followee_model/__init__.py`
  (docstring version).
- Tests: `tests/test_syntax.py` (fragment/query positives including the
  Section 7.2 examples, all five relative-reference negatives, fragment
  edge cases); new `tests/test_v07_conformance.py` (one focused class per
  normative change: URI production exercised on every URI-bearing record
  field including extension keys, with the 2,048-byte cap re-checked
  across a fragment; IPvFuture `v`/`V` at unit and full-record level;
  B.7 item 17 signed-vector, nested public-key, revealed revocation-key,
  and wire-level `f4` byte cases); comment fix in
  `tests/test_verify_behavior.py`.
- Documentation: this section; ambiguity 1 annotated as resolved;
  `tools/python-model/README.md` updated to describe the v0.6 authorship
  plus v0.7 maintenance and the renamed grammar.

**Ambiguities found in the v0.7 delta.**  None new.  The delta's changed
paragraphs are prescriptive and match the model's existing
classifications (`schemaViolation` for boolean labels, including the
signed B.7 item 17 vector, as the v0.6 review corrections already chose).

**External material consulted for the v0.7 pass.**  None fetched.  The
fragment ABNF (`fragment = *( pchar / "/" / "?" )`) comes from working
knowledge of RFC 3986 (already listed above); RFC 5234's
case-insensitivity rule is restated inside the v0.7 specification text
itself.  No new dependencies were added; the model remains Python
3.10 standard-library only.

**Exclusion statement.**  No excluded or provisional Followee material
was inspected, searched for, received, or supplied during this pass: no
`followee-rs` source, tests, documentation, issues, CI output, or
history; no whitepaper; no `IMPLEMENTATION.md`, `SPEC-QUESTIONS.md`, or
`tools/spec_vector_check.py`; no implementation-status or provisional
fixtures; no Rust-derived expected outputs; no reports from another
implementation; and no GitHub or web searches for Followee material.
The only inputs were this repository at commit `6b944b9` (including its
own Git history) and the two approved files verified by SHA-256 above.

## Reproduction confidence

All 173 unit tests pass (155 at the v0.6 freeze, plus 5 post-freeze
regression tests, plus 13 v0.7 conformance and regression tests), including byte-exact independent reproduction of
every Appendix B value from seeds and structured inputs, the three
identity-binding permutations of B.7 item 1, the B.7 mutation list with
its normative error assignments, and the B.8 descriptor-substitution
attack (signature valid, rejected `identityBindingMismatch` at step 9).
